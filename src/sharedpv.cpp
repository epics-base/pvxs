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
DEFINE_LOGGER(logsource, "pvxs.server.staticsource");
DEFINE_LOGGER(logmailbox, "pvxs.mailbox");

namespace pvxs {
namespace server {

template<typename T>
using ptr_set = std::set<T, std::owner_less<T>>;

struct SharedPV::Impl : public std::enable_shared_from_this<Impl>
{
    mutable epicsMutex lock;

    std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)> onPut;
    std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)> onRPC;
    std::function<void(SharedPV&)> onFirstConnect;
    std::function<void(SharedPV&)> onLastDisconnect;

    ptr_set<std::weak_ptr<ChannelControl>> channels;

    std::set<std::shared_ptr<ConnectOp>> pending;
    std::set<std::shared_ptr<MonitorSetupOp>> mpending;
    std::set<std::shared_ptr<MonitorControlOp>> subscribers;

    Value current;

    INST_COUNTER(SharedPVImpl);

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
                    self->subscribers.erase(sub);
                });

                sub->post(current);
            }
            self->subscribers.emplace(std::move(sub));

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
DEFINE_INST_COUNTER2(SharedPV::Impl, SharedPVImpl);

SharedPV SharedPV::buildMailbox()
{
    SharedPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](SharedPV& pv, std::unique_ptr<ExecOp>&& op, Value&& val) {

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
            Value temp(self->current);
            UnGuard U(G);
            Impl::connectOp(self, conn, temp);
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
            Impl::connectSub(G, self, conn, self->current.clone());
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
            SharedPV pv;
            pv.impl = self;
            cb(pv);
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
        SharedPV pv;
        pv.impl = self;
        cb(pv);
    }
}

void SharedPV::onFirstConnect(std::function<void(SharedPV&)>&& fn)
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");
    Guard G(impl->lock);
    impl->onFirstConnect = std::move(fn);
}

void SharedPV::onLastDisconnect(std::function<void(SharedPV&)>&& fn)
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

    Value temp;
    {
        Guard G(impl->lock);

        if(impl->current)
            throw std::logic_error("close() first");

        pending = std::move(impl->pending);
        mpending = std::move(impl->mpending);

        impl->current = initial.clone();
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

        if(impl->current)
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

void SharedPV::fetch(Value& val) const
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

Value SharedPV::fetch() const
{
    if(!impl)
        throw std::logic_error("Empty SharedPV");

    Guard G(impl->lock);

    if(impl->current) {
        return impl->current.clone();
    } else {
        throw std::logic_error("open() first");
    }
}

struct StaticSource::Impl final : public Source
{
    mutable RWLock lock;

    list_t pvs;
    decltype (List::names) list;

    /**
     * @brief Claims all the searched names specified in a search operation for
     * this static source.
     *
     * This method will iterate over the list of searched names contained in the
     * search operation.
     *
     * In each iteration it will first ignore all names that contain wild card
     * characters '*' and '?'
     *
     * Then it will try to directly match the searched name with one of the
     * names associated with this static source.
     *
     * If it finds a match it will claim the searched name so that processing,
     * and optionally a response, can take place.
     *
     * If no direct match is found then it will try an enhanced match
     * implementing the wildcard matches in epics-base. e.g. `pattern`
     * "pv:name:*" will match with `searched_name` "pv:name:123Abc" and
     * `pattern` "pv:name:????" will match with `searched_name` "pv:name:12Ab".
     *
     * Again, if a match is found the searched
     * name will be claimed .
     *
     * @param op The 'Search' object that contains the searched names to
     * be matched.
     *
     * @return void, but claims all searched names that match either directly or
     * against patterns
     */
    virtual void onSearch(Search &op) override
    {
        auto G(lock.lockReader());

        for(auto& name : op) {
            const auto searched_name = std::string(name.name());

            // Don't allow `searched_name`s containing EPICS wildcard characters
            if (std::find_first_of(
                        searched_name.begin(), searched_name.end(),
                        kEpicsWildcardChars.begin(), kEpicsWildcardChars.end()
                    ) != searched_name.end()) {
                continue;
            }

            // Try a direct match of the `searched_name` in `pvs` map
            if(pvs.find(searched_name)!=pvs.end()) {
                name.claim();
                log_debug_printf(logsource, "%p claim '%s'\n", this, searched_name.c_str());
            } else {
                // If that failed then try a wildcard match
                wildcardMatch(name, searched_name);
            }
        }
    }

    virtual void onCreate(std::unique_ptr<ChannelControl> &&op) override
    {
        SharedPV pv;
        {
            auto G(lock.lockReader());
            auto it(pvs.find(op->name()));
            bool found = it!=pvs.end();
            log_debug_printf(logsource, "%p %screate '%s'\n",
                             this, found ? "":"can't ", op->name().c_str());
            if(!found)
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

    virtual void show(std::ostream& strm) override final
    {
        strm<<"StaticProvider";

        auto G(lock.lockReader());
        for(auto& pair : pvs) {
            strm<<"\n"<<indent{}<<pair.first;
            // TODO: details for SharedPV
        }
    }

  private:
    static const std::string kEpicsWildcardChars;

    /**
     * @brief Enhanced wildcard search
     *
     * Enhanced search will try to match `searched_name` based on
     * EPICS wildcard matches (as in epics-base)
     * `pattern` "pv:name:*" => `searched_name` "pv:name:123Abc"
     * `pattern` "pv:name:????" => `searched_name` "pv:name:12Ab"
     *
     * @param pv_name the PV name definition to check
     * @param searched_name the name presented to the server in the search message
     */
    void wildcardMatch(Search::Name &pv_name, const std::basic_string<char> &searched_name) {
        static const std::regex kRegexSpecialChars{R"([-[\]{}()+.,\^$|#\s])"};
        static const std::regex kWildcardStarPattern("\\*");
        static const char kWildcardQueryCharacter = '?';

        // Consider only PVs containing EPICS wildcard characters (others already checked)
        std::vector<std::pair<std::string, SharedPV>> wildcard_pv_names;
        std::copy_if(pvs.begin(), pvs.end(), std::back_inserter(wildcard_pv_names), containsEpicsWildcard);

        for (const auto &pattern_shared_pv_pair: wildcard_pv_names) {
            // 1. Prepare PV regex pattern converting from the EPICS wildcard-style patterns to regex syntax
            std::string pv_pattern = pattern_shared_pv_pair.first;

            // 1.1 Escape all regex special characters in original PV pattern
            pv_pattern =
              std::__1::regex_replace(pv_pattern, kRegexSpecialChars, R"(\\$&)");

            // 1.2 Replace Query and Star EPICS wildcard characters with their regex equivalents
            std::replace(pv_pattern.begin(), pv_pattern.end(), kWildcardQueryCharacter, '.');
            pv_pattern = std::__1::regex_replace(pv_pattern, kWildcardStarPattern, ".*");

            // 2. Compare the PV regex pattern with the `searched_name`
            std::regex pv_regex_pattern(pv_pattern);
            if (std::regex_match(searched_name, pv_regex_pattern)) {
                pv_name.claim();
                log_debug_printf(logsource, "%p claim '%s'\n", this,
                                 searched_name.c_str());
            }
        }
    }

    /**
     * Given a pattern / source pair return true if the pattern contains any EPICS wildcard characters
     * Suitable for use as `std::copy_if()` predicate
     */
    static bool containsEpicsWildcard(const std::pair<std::string, SharedPV>& pv_pattern_source) {
        const std::string &pv_pattern = pv_pattern_source.first;
        return std::find_first_of(
          pv_pattern.begin(), pv_pattern.end(),
          kEpicsWildcardChars.begin(), kEpicsWildcardChars.end()
        ) != pv_pattern.end();
    }
};

const std::string StaticSource::Impl::kEpicsWildcardChars = "*?";

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

void StaticSource::close()
{
    if(!impl)
        throw std::logic_error("Empty StaticSource");

    {
        auto G(impl->lock.lockReader());

        for(auto& pair : impl->pvs) {
            pair.second.close();
        }
    }
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

StaticSource::list_t StaticSource::list() const
{
    list_t ret;

    if(!impl)
        throw std::logic_error("Empty StaticSource");

    {
        auto G(impl->lock.lockReader());

        return impl->pvs; // copies map
    }
}

} // namespace server
} // namespace pvxs
