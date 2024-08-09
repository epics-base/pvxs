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
#include <pvxs/sharedwildcardpv.h>
#include <pvxs/source.h>
#include <pvxs/server.h>

#include "utilpvt.h"
#include "dataimpl.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

DEFINE_LOGGER(logshared, "pvxs.server.sharedpv.wildcard");
DEFINE_LOGGER(logmailbox, "pvxs.mailbox");

namespace pvxs {
namespace server {

template<typename T>
using ptr_set = std::set<T, std::owner_less<T>>;

struct SharedWildcardPV::Impl : public std::enable_shared_from_this<Impl>
{
    mutable epicsMutex lock;

    std::function<void(SharedWildcardPV&, std::unique_ptr<ExecOp>&&, const std::string &pv_name, const std::list<std::string> &parameters, Value&&)> onPut;
    std::function<void(SharedWildcardPV&, std::unique_ptr<ExecOp>&&, const std::string &pv_name, const std::list<std::string> &parameters, Value&&)> onRPC;
    std::function<void(SharedWildcardPV&, const std::string &pv_name, const std::list<std::string> &parameters)> onFirstConnect;
    std::function<void(SharedWildcardPV&, const std::string &pv_name, const std::list<std::string> &parameters)> onLastDisconnect;

    std::map<std::string, ptr_set<std::weak_ptr<ChannelControl>>> channels;

    std::map<std::string, std::set<std::shared_ptr<ConnectOp>>> pending;
    std::map<std::string, std::set<std::shared_ptr<MonitorSetupOp>>> mpending;
    std::map<std::string, std::set<std::shared_ptr<MonitorControlOp>>> subscribers;

    std::map<std::string, Value> current_vals;

    static
    void connectOp(const std::shared_ptr<Impl>& self, const std::shared_ptr<ConnectOp>& conn, const Value& current)
    {
        try{
            // unlocked as connect() will sync. with the client worker
            conn->connect(current);
        }catch(std::exception& e){
            log_warn_printf(logshared, "%s Client %s: Can't attach() get: %s\n",
                            conn->name().c_str(), conn->peerName().c_str(), e.what());
            // not re-throwing for consistency
            // we couldn't deliver an error after pending
            conn->error(e.what());
        }
    }

    static
    void connectSub(Guard& G,
                    const std::shared_ptr<Impl>& self,
                    const std::shared_ptr<MonitorSetupOp>& conn,
                    const Value& current)
    {
        G.assertIdenticalMutex(self->lock);
        try {
            std::shared_ptr<MonitorControlOp> sub;
            {
                UnGuard U(G);

                // unlock as connect() and onClose() sync. with the client worker
                sub = conn->connect(current);

                conn->onClose([self, sub](const std::string& msg) {
                    log_debug_printf(logshared, "%s on %s Monitor onClose\n", sub->peerName().c_str(), sub->name().c_str());
                    Guard G(self->lock);
                    self->subscribers[sub->name()].erase(sub);
                });

                sub->post(current);
            }
            self->subscribers[sub->name()].emplace(std::move(sub));

        }catch(std::exception& e){
            UnGuard U(G);
            log_warn_printf(logshared, "%s Client %s: Can't attach() monitor: %s\n",
                            conn->name().c_str(), conn->peerName().c_str(), e.what());
            // not re-throwing for consistency
            // we couldn't deliver an error after pending
            conn->error(e.what());
        }
    }
};

SharedWildcardPV SharedWildcardPV::buildMailbox()
{
    SharedWildcardPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](SharedWildcardPV& pv, std::unique_ptr<ExecOp>&& op, const std::string &pv_name, const std::list<std::string> &parameters, Value&& val) {
        auto ts(val["timeStamp"]);
        if(ts && !ts.isMarked(true, true)) {
            // use current time
            epicsTimeStamp now;
            if(!epicsTimeGetCurrent(&now)) {
                ts["secondsPastEpoch"] = now.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH;
                ts["nanoseconds"] = now.nsec;
            }
        }

        log_debug_printf(logmailbox, "%s on %s mailbox put: %s\n",
                         op->peerName().c_str(), op->name().c_str(),
                         std::string(SB()<<val).c_str());

        pv.post(pv_name, val);

        op->reply();
    });

    return ret;
}

SharedWildcardPV SharedWildcardPV::buildReadonly()
{
    SharedWildcardPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](SharedWildcardPV& pv, std::unique_ptr<ExecOp>&& op, const std::string &pv_name, const std::list<std::string> &parameters, Value&& val) {
        op->error(SB() << "Read-only PV: " << pv_name);
    });

    return ret;
}

SharedWildcardPV::~SharedWildcardPV() {}

void SharedWildcardPV::attach(std::unique_ptr<ChannelControl>&& ctrlop, const std::list<std::string> parameters)
{
    // in, or after, some Source::onCreate()

    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");

    auto self(impl); // to be captured

    std::shared_ptr<ChannelControl> ctrl(std::move(ctrlop));

    log_debug_printf(logshared, "%s on %s Chan setup\n", ctrl->peerName().c_str(), ctrl->name().c_str());

    ctrl->onRPC([self, parameters](std::unique_ptr<ExecOp>&& op, Value&& arg) {
        // on server worker

        log_debug_printf(logshared, "%s on %s RPC\n", op->peerName().c_str(), op->name().c_str());

        Guard G(self->lock);
        auto cb(self->onRPC);
        if(cb) {
            SharedWildcardPV pv;
            pv.impl = self;
            try {
                UnGuard U(G);
                cb(pv, std::move(op), op->name(), parameters, std::move(arg));
            }catch(std::exception& e){
                log_err_printf(logshared, "error in RPC cb(%s): %s\n", op->name().c_str(), e.what());
            }
        } else {
            op->error("RPC not implemented by this PV");
        }
    });

    ctrl->onOp([self,parameters](std::unique_ptr<ConnectOp>&& op) {
        // on server worker

        std::shared_ptr<ConnectOp> conn(std::move(op));

        log_debug_printf(logshared, "%s on %s Op connecting\n", conn->peerName().c_str(), conn->name().c_str());

        conn->onGet([self](std::unique_ptr<ExecOp>&& op) {
            // on server worker

            log_debug_printf(logshared, "%s on %s Get\n", op->peerName().c_str(), op->name().c_str());

            Value got;
            {
                Guard G(self->lock);
                if(self->current_vals[op->name()])
                    got = self->current_vals[op->name()].clone();
            }
            if(got) {
                op->reply(got);
            } else {
                op->error("Get races with type change");
            }

        });

        conn->onPut([self,parameters](std::unique_ptr<ExecOp>&& op, Value&& val) {
            // on server worker

            log_debug_printf(logshared, "%s on %s RPC\n", op->peerName().c_str(), op->name().c_str());

            Guard G(self->lock);
            auto cb(self->onPut);
            if(cb) {
                try {
                    SharedWildcardPV pv;
                    pv.impl = self;
                    UnGuard U(G);
                    cb(pv, std::move(op), op->name(), parameters, std::move(val));
                }catch(std::exception& e){
                    log_err_printf(logshared, "error in Put cb: %s\n", e.what());
                }
            } else {
                op->error("Put not implemented by this PV");
            }

        });

        conn->onClose([self, conn](const std::string&) {
            // on server worker

            log_debug_printf(logshared, "%s on %s OP onClose\n", conn->peerName().c_str(), conn->name().c_str());

            self->pending[conn->name()].erase(conn);
        });

        Guard G(self->lock);

        if(!self->current_vals[conn->name()]) {
            // no type
            self->pending[conn->name()].insert(std::move(conn));

        } else {
            Value temp(self->current_vals[conn->name()]);
            UnGuard U(G);
            Impl::connectOp(self, conn, temp);
        }
    });

    ctrl->onSubscribe([self](std::unique_ptr<MonitorSetupOp>&& op) {
        // on server worker

        log_debug_printf(logshared, "%s on %s Monitor setup\n", op->peerName().c_str(), op->name().c_str());

        std::shared_ptr<MonitorSetupOp> conn(std::move(op));

        Guard G(self->lock);

        if(!self->current_vals[conn->name()]) {
            // no type

            // this onClose will be later replaced if/when the monitor is open()'d
            conn->onClose([self, conn](const std::string& msg) {
                log_debug_printf(logshared, "%s on %s Monitor onClose\n", conn->peerName().c_str(), conn->name().c_str());
                Guard G(self->lock);
                self->mpending[conn->name()].erase(conn);
            });

            self->mpending[conn->name()].insert(std::move(conn));

        } else {
            Impl::connectSub(G, self, conn, self->current_vals[conn->name()].clone());
        }
    });

    ctrl->onClose([self, ctrl, parameters](const std::string& msg) {
        // on server worker

        log_debug_printf(logshared, "%s on %s Chan close\n", ctrl->peerName().c_str(), ctrl->name().c_str());

        Guard G(self->lock);

        self->channels[ctrl->name()].erase(ctrl);

        if(self->channels[ctrl->name()].empty())
            log_debug_printf(logshared, "%s on %s onLastDisconnect()\n", ctrl->peerName().c_str(), ctrl->name().c_str());

        if(self->channels[ctrl->name()].empty() && self->onLastDisconnect) {
            auto cb(self->onLastDisconnect);
            UnGuard U(G);
            SharedWildcardPV pv;
            pv.impl = self;
            cb(pv, ctrl->name(), parameters);
        }
    });

    Guard G(self->lock);

    bool first = impl->channels[ctrl->name()].empty();
    impl->channels[ctrl->name()].insert(ctrl);

    if(first)
        log_debug_printf(logshared, "%s on %s onFirstConnect()\n", ctrl->peerName().c_str(), ctrl->name().c_str());

    if(first && self->onFirstConnect) {
        auto cb(self->onFirstConnect);
        UnGuard U(G);
        SharedWildcardPV pv;
        pv.impl=self;
        pv.wildcard_pv = wildcard_pv;
        cb(pv, ctrl->name(), parameters);
    }
}

void SharedWildcardPV::onFirstConnect(std::function<void(SharedWildcardPV&, const std::string &, const std::list<std::string> &)>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    Guard G(impl->lock);
    impl->onFirstConnect = std::move(fn);
}

void SharedWildcardPV::onLastDisconnect(std::function<void(SharedWildcardPV&, const std::string &, const std::list<std::string> &)>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    Guard G(impl->lock);
    impl->onLastDisconnect = std::move(fn);
}

void SharedWildcardPV::onPut(std::function<void(SharedWildcardPV&, std::unique_ptr<ExecOp> &&, const std::string &, const std::list<std::string> &, Value &&)> &&fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    Guard G(impl->lock);
    impl->onPut = std::move(fn);
}

void SharedWildcardPV::onRPC(std::function<void(SharedWildcardPV&, std::unique_ptr<ExecOp>&&, const std::string &, const std::list<std::string> &, Value&&)>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    Guard G(impl->lock);
    impl->onRPC = std::move(fn);
}

// Checks existence without creating entry in map
template <typename T>
bool SharedWildcardPV::exists(const std::map<std::string, T>& m, const std::string& ref) const {
    auto it = m.find(ref);
    return (it != m.end() && !!(it->second));
}

void SharedWildcardPV::open(const std::string &pv_name, const Value& initial)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    else if(!initial || initial.type()!=TypeCode::Struct)
        throw std::logic_error("Must specify non-empty initial Struct");

    auto &pending = impl->pending[pv_name];
    auto &mpending = impl->mpending[pv_name];

    Value temp;
    {
        Guard G(impl->lock);

        if(exists(impl->current_vals, pv_name))
            throw std::logic_error("close() first");

        pending = std::move(impl->pending[pv_name]);
        mpending = std::move(impl->mpending[pv_name]);

        impl->current_vals[pv_name] = initial.clone();
        // make a second copy as 'temp' will be queued
        temp = initial.clone();

        // TODO these loops will be really inefficient if we aren't on a worker.
        //      API to batch?

        for(auto& op : mpending) {
            Impl::connectSub(G, impl, op, temp);
            // initial open post()'d
        }
    }

    for(auto& op : pending) {
        Impl::connectOp(impl, op, temp);
    }
}

bool SharedWildcardPV::isOpen(const std::string &pv_name) const
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    Guard G(impl->lock);
    return exists(impl->current_vals, pv_name);
}

void SharedWildcardPV::close(const std::string &pv_name)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");

    auto &channels = impl->channels[pv_name];

    {
        Guard G(impl->lock);

        if(exists(impl->current_vals, pv_name))
            impl->current_vals[pv_name] = Value();

        impl->subscribers[pv_name].clear();
        channels = std::move(impl->channels[pv_name]);
    }

    for(auto& ch : channels) {
        if(auto chan = ch.lock())
            chan->close();
    }
}

void SharedWildcardPV::post(const std::string &pv_name, const Value& val)
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");
    else if(!val)
        throw std::logic_error("Can't post() empty Value");

    Guard G(impl->lock);

    if(!exists(impl->current_vals, pv_name))
        throw std::logic_error("Must open() before post()ing");
    else if(Value::Helper::desc(impl->current_vals[pv_name])!=Value::Helper::desc(val))
        throw std::logic_error("post() requires the exact type of open().  Recommend pvxs::Value::cloneEmpty()");

    impl->current_vals[pv_name].assign(val);

    if(impl->subscribers[pv_name].empty())
        return;

    auto copy(val.clone());

    for(auto& sub : impl->subscribers[pv_name]) {
        sub->post(copy);
    }
}

void SharedWildcardPV::fetch(const std::string &pv_name, Value& val) const
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");

    Guard G(impl->lock);

    if(exists(impl->current_vals, pv_name)) {
        val.assign(impl->current_vals[pv_name]);
    } else {
        throw std::logic_error("open() first");
    }
}

Value SharedWildcardPV::fetch(const std::string &pv_name) const
{
    if(!impl)
        throw std::logic_error("Empty SharedWildcardPV");

    Guard G(impl->lock);

    if(exists(impl->current_vals, pv_name)) {
        return impl->current_vals[pv_name].clone();
    } else {
        throw std::logic_error("open() first");
    }
}

} // namespace server
} // namespace pvxs
