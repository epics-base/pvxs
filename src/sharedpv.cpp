/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <set>
#include <map>

#include <epicsTime.h>
#include <epicsMutex.h>
#include <epicsGuard.h>

#include <pvxs/log.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/server.h>

#include "utilpvt.h"
#include "dataimpl.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

DEFINE_LOGGER(logshared, "pvxs.server.sharedpv");

namespace pvxs {
namespace server {

template<typename T>
using ptr_set = std::set<T, std::owner_less<T>>;

struct SharedPV::Impl : public std::enable_shared_from_this<Impl>
{
    mutable epicsMutex lock;

    std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)> onPut;
    std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)> onRPC;
    std::function<void()> onFirstConnect;
    std::function<void()> onLastDisconnect;

    ptr_set<std::weak_ptr<ChannelControl>> channels;

    std::set<std::shared_ptr<ConnectOp>> pending;
    std::set<std::shared_ptr<MonitorSetupOp>> mpending;
    std::set<std::shared_ptr<MonitorControlOp>> subscribers;

    Value current;

    INST_COUNTER(SharedPVImpl);
};

SharedPV SharedPV::buildMailbox()
{
    SharedPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](SharedPV& pv, std::unique_ptr<ExecOp>&& op, Value&& val) {

        log_debug_printf(logshared, "%s on %s mailbox put\n", op->peerName().c_str(), op->name().c_str());

        auto ts(val["timeStamp"]);
        if(ts && !ts.isMarked(true, true)) {
            // use current time
            epicsTimeStamp now;
            if(!epicsTimeGetCurrent(&now)) {
                ts["secondsPastEpoch"] = now.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH;
                ts["nanoseconds"] = now.nsec;
            }
        }

        pv.post(val);

        op->reply();
    });

    return ret;
}

SharedPV SharedPV::buildReadonly()
{
    SharedPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](SharedPV& pv, std::unique_ptr<ExecOp>&& op, Value&& val) {
        op->error("Read-only PV");
    });

    return ret;
}

SharedPV::~SharedPV() {}

void SharedPV::attach(std::unique_ptr<ChannelControl>&& ctrlop)
{
    // in, or after, some Source::onCreate()

    if(!impl)
        throw std::logic_error("Empty SharedPV");

    auto self(impl); // to be captured

    std::shared_ptr<ChannelControl> ctrl(std::move(ctrlop));

    log_debug_printf(logshared, "%s on %s Chan setup\n", ctrl->peerName().c_str(), ctrl->name().c_str());

    ctrl->onRPC([self](std::unique_ptr<ExecOp>&& op, Value&& arg) {
        // on server worker

        log_debug_printf(logshared, "%s on %s RPC\n", op->peerName().c_str(), op->name().c_str());

        Guard G(self->lock);
        auto cb(self->onRPC);
        if(cb) {
            SharedPV pv;
            pv.impl = self;
            try {
                UnGuard U(G);
                cb(pv, std::move(op), std::move(arg));
            }catch(std::exception& e){
                log_err_printf(logshared, "error in RPC cb: %s\n", e.what());
            }
        } else {
            op->error("RPC not implemented by this PV");
        }
    });

    ctrl->onOp([self](std::unique_ptr<ConnectOp>&& op) {
        // on server worker

        std::shared_ptr<ConnectOp> conn(std::move(op));

        log_debug_printf(logshared, "%s on %s Op connecting\n", conn->peerName().c_str(), conn->name().c_str());

        conn->onGet([self](std::unique_ptr<ExecOp>&& op) {
            // on server worker

            log_debug_printf(logshared, "%s on %s Get\n", op->peerName().c_str(), op->name().c_str());

            Value got;
            {
                Guard G(self->lock);
                if(self->current)
                    got = self->current.clone();
            }
            if(got) {
                op->reply(got);
            } else {
                op->error("Get races with type change");
            }

        });

        conn->onPut([self](std::unique_ptr<ExecOp>&& op, Value&& val) {
            // on server worker

            log_debug_printf(logshared, "%s on %s RPC\n", op->peerName().c_str(), op->name().c_str());

            Guard G(self->lock);
            auto cb(self->onPut);
            if(cb) {
                try {
                    SharedPV pv;
                    pv.impl = self;
                    UnGuard U(G);
                    cb(pv, std::move(op), std::move(val));
                }catch(std::exception& e){
                    log_err_printf(logshared, "error in Put cb: %s\n", e.what());
                }
            } else {
                op->error("RPC not implemented by this PV");
            }

        });

        conn->onClose([self, conn](const std::string&) {
            // on server worker

            log_debug_printf(logshared, "%s on %s OP onClose\n", conn->peerName().c_str(), conn->name().c_str());

            self->pending.erase(conn);
        });

        Guard G(self->lock);

        if(!self->current) {
            // no type
            self->pending.insert(std::move(conn));

        } else {
            UnGuard U(G);
            conn->connect(self->current);
        }
    });

    ctrl->onSubscribe([self](std::unique_ptr<MonitorSetupOp>&& op) {
        // on server worker

        log_debug_printf(logshared, "%s on %s Monitor setup\n", op->peerName().c_str(), op->name().c_str());

        std::shared_ptr<MonitorSetupOp> conn(std::move(op));

        Guard G(self->lock);

        if(!self->current) {
            // no type

            // this onClose will be later replaced if/when the monitor is open()'d
            conn->onClose([self, conn](const std::string& msg) {
                log_debug_printf(logshared, "%s on %s Monitor onClose\n", conn->peerName().c_str(), conn->name().c_str());
                Guard G(self->lock);
                self->mpending.erase(conn);
            });

            self->mpending.insert(std::move(conn));

        } else {
            auto ctrl = conn->connect(self->current);
            std::shared_ptr<MonitorControlOp> sub(std::move(ctrl));

            conn->onClose([self, sub](const std::string& msg) {
                log_debug_printf(logshared, "%s on %s Monitor onClose\n", sub->peerName().c_str(), sub->name().c_str());
                Guard G(self->lock);
                self->subscribers.erase(sub);
            });

            sub->post(self->current.clone());
            self->subscribers.emplace(std::move(sub));
        }
    });

    ctrl->onClose([self, ctrl](const std::string& msg) {
        // on server worker

        log_debug_printf(logshared, "%s on %s Chan close\n", ctrl->peerName().c_str(), ctrl->name().c_str());

        Guard G(self->lock);

        self->channels.erase(ctrl);

        if(self->channels.empty())
            log_debug_printf(logshared, "%s on %s onLastDisconnect()\n", ctrl->peerName().c_str(), ctrl->name().c_str());

        if(self->channels.empty() && self->onLastDisconnect) {
            auto cb(self->onLastDisconnect);
            UnGuard U(G);
            cb();
        }
    });

    Guard G(self->lock);

    bool first = impl->channels.empty();
    impl->channels.insert(ctrl);

    if(first)
        log_debug_printf(logshared, "%s on %s onFirstConnect()\n", ctrl->peerName().c_str(), ctrl->name().c_str());

    if(first && self->onFirstConnect) {
        auto cb(self->onFirstConnect);
        UnGuard U(G);
        cb();
    }
}

void SharedPV::onFirstConnect(std::function<void()>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    Guard G(impl->lock);
    impl->onFirstConnect = std::move(fn);
}

void SharedPV::onLastDisconnect(std::function<void()>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    Guard G(impl->lock);
    impl->onLastDisconnect = std::move(fn);
}

void SharedPV::onPut(std::function<void(SharedPV&, std::unique_ptr<ExecOp> &&, Value &&)> &&fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    Guard G(impl->lock);
    impl->onPut = std::move(fn);
}

void SharedPV::onRPC(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    Guard G(impl->lock);
    impl->onRPC = std::move(fn);
}

void SharedPV::open(const Value& initial)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    else if(!initial || initial.type()!=TypeCode::Struct)
        throw std::logic_error("Must specify non-empty initial Struct");

    decltype (impl->pending) pending;
    decltype (impl->mpending) mpending;
    decltype (impl->subscribers) subscribers;

    {
        Guard G(impl->lock);

        if(impl->current)
            throw std::logic_error("close() first");

        pending = std::move(impl->pending);
        mpending = std::move(impl->mpending);

        impl->current = initial.clone();
    }

    // TODO the following is really inefficient if we aren't on a worker.
    //      API to batch?

    for(auto& op : pending) {
        op->connect(initial);
    }
    for(auto& op : mpending) {
        auto ctrl = op->connect(initial);
        auto self(impl);
        std::shared_ptr<MonitorControlOp> sub(std::move(ctrl));

        op->onClose([self, sub](const std::string& msg) {
            Guard G(self->lock);
            self->subscribers.erase(sub);
        });

        subscribers.emplace(sub);
    }

    {
        Guard G(impl->lock);

        //c++17 adds std::set::merge()
        for(auto& sub : subscribers) {
            sub->post(impl->current.clone());
            impl->subscribers.insert(sub);
        }
    }
}

bool SharedPV::isOpen() const
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    Guard G(impl->lock);
    return !!impl->current;
}

void SharedPV::close()
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");

    decltype (impl->channels) channels;

    {
        Guard G(impl->lock);

        if(!impl->current)
            return; // ignore double close()

        impl->current = Value();

        impl->subscribers.clear();
        channels = std::move(impl->channels);
    }

    for(auto& ch : channels) {
        if(auto chan = ch.lock())
            chan->close();
    }
}

void SharedPV::post(const Value& val)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    else if(!val)
        throw std::logic_error("Can't post() empty Value");

    Guard G(impl->lock);

    if(!impl->current)
        throw std::logic_error("Must open() before post()ing");
    else if(Value::Helper::desc(impl->current)!=Value::Helper::desc(val))
        throw std::logic_error("post() requires the exact type of open().  Recommend pvxs::Value::cloneEmpty()");

    impl->current.assign(val);

    if(impl->subscribers.empty())
        return;

    auto copy(val.clone());

    for(auto& sub : impl->subscribers) {
        sub->post(copy);
    }
}

void SharedPV::fetch(Value& val)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");

    Guard G(impl->lock);

    if(impl->current) {
        val.assign(impl->current);
    } else {
        throw std::logic_error("open() first");
    }
}

struct StaticSource::Impl : public Source
{
    RWLock lock;

    std::map<std::string, SharedPV> pvs;
    decltype (List::names) list;

    virtual void onSearch(Search &op) override
    {
        auto G(lock.lockReader());
        for(auto& name : op) {
            auto it(pvs.find(name.name()));
            if(it!=pvs.end())
                name.claim();
        }
    }

    virtual void onCreate(std::unique_ptr<ChannelControl> &&op) override
    {
        SharedPV pv;
        {
            auto G(lock.lockReader());
            auto it(pvs.find(op->name()));
            if(it==pvs.end())
                return; // not mine
            pv = it->second;
        }

        pv.attach(std::move(op));
    }

    virtual List onList() override
    {
        List ret;
        auto G(lock.lockReader());

        if(!list || list.use_count()!=1u) {
            auto temp = std::make_shared<std::set<std::string>>();
            for(auto& pair : pvs) {
                temp->emplace(pair.first);
            }
            list = std::move(temp);
        }

        ret.names = list;
        ret.dynamic = false;

        return ret;
    }
};

StaticSource StaticSource::build()
{
    StaticSource ret;
    ret.impl = std::make_shared<Impl>();
    return ret;
}

StaticSource::~StaticSource() {}

std::shared_ptr<Source> StaticSource::source() const
{
    if(!impl)
        throw std::logic_error("Empty StaticSource");
    return impl;
}

StaticSource& StaticSource::add(const std::string& name, const SharedPV &pv)
{
    if(!impl)
        throw std::logic_error("Empty StaticSource");

    auto G(impl->lock.lockWriter());

    if(impl->pvs.find(name)!=impl->pvs.end())
        throw std::logic_error("add() will not create duplicate PV");

    impl->pvs[name] = pv;
    impl->list.reset();

    return *this;
}

StaticSource& StaticSource::remove(const std::string& name)
{
    if(!impl)
        throw std::logic_error("Empty StaticSource");

    SharedPV pv;
    {
        auto G(impl->lock.lockWriter());

        auto it(impl->pvs.find(name));
        if(it==impl->pvs.end())
            return *this;
        pv = it->second;
        impl->pvs.erase(it);
        impl->list.reset();
    }

    pv.close();

    return *this;
}

} // namespace server
} // namespace pvxs
