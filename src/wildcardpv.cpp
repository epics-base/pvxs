/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "wildcardpv.h"

#include <map>
#include <set>

#include <epicsGuard.h>
#include <epicsMutex.h>
#include <epicsTime.h>

#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/source.h>
#include <pvxs/sharedpv.h>

#include "dataimpl.h"
#include "utilpvt.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

DEFINE_LOGGER(logshared, "pvxs.svr.pvwild");
DEFINE_LOGGER(logmailbox, "pvxs.mailbox");
DEFINE_LOGGER(logsource, "pvxs.svr.src");

namespace pvxs {
namespace server {

template <typename T>
using ptr_set = std::set<T, std::owner_less<T>>;

struct WildcardPV::Impl : std::enable_shared_from_this<Impl> {
    mutable epicsMutex lock;

    std::function<void(WildcardPV&, std::unique_ptr<ExecOp>&&, const std::string& pv_name, const std::list<std::string>& parameters, Value&&)> onPut;
    std::function<void(WildcardPV&, std::unique_ptr<ExecOp>&&, const std::string& pv_name, const std::list<std::string>& parameters, Value&&)> onRPC;
    std::function<void(WildcardPV&, const std::string& pv_name, const std::list<std::string>& parameters)> onFirstConnect;
    std::function<void(WildcardPV&, const std::string& pv_name, const std::list<std::string>& parameters)> onLastDisconnect;

    std::map<std::string, ptr_set<std::weak_ptr<ChannelControl>>> channels;

    std::map<std::string, std::set<std::shared_ptr<ConnectOp>>> pending;
    std::map<std::string, std::set<std::shared_ptr<MonitorSetupOp>>> mpending;
    std::map<std::string, std::set<std::shared_ptr<MonitorControlOp>>> subscribers;

    std::map<std::string, Value> current_vals;

    static void connectOp(const std::shared_ptr<Impl>& self, const std::shared_ptr<ConnectOp>& conn, const Value& current) {
        try {
            // unlocked as connect() will sync. with the client worker
            conn->connect(current);
        } catch (std::exception& e) {
            log_warn_printf(logshared, "%s Client %s: Can't attach() get: %s\n", conn->name().c_str(), conn->peerName().c_str(), e.what());
            // not re-throwing for consistency,
            // we couldn't deliver an error after pending
            conn->error(e.what());
        }
    }

    static void connectSub(Guard& G, const std::shared_ptr<Impl>& self, const std::shared_ptr<MonitorSetupOp>& conn, const Value& current) {
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

        } catch (std::exception& e) {
            UnGuard U(G);
            log_warn_printf(logshared, "%s Client %s: Can't attach() monitor: %s\n", conn->name().c_str(), conn->peerName().c_str(), e.what());
            // not re-throwing for consistency
            // we couldn't deliver an error after pending
            conn->error(e.what());
        }
    }
};

WildcardPV WildcardPV::buildMailbox() {
    WildcardPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](WildcardPV& pv, std::unique_ptr<ExecOp>&& op, const std::string& pv_name, const std::list<std::string>&, Value&& val) {
        auto ts(val["timeStamp"]);
        if (ts && !ts.isMarked(true, true)) {
            // use current time
            epicsTimeStamp now;
            if (!epicsTimeGetCurrent(&now)) {
                ts["secondsPastEpoch"] = now.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH;
                ts["nanoseconds"] = now.nsec;
            }
        }

        log_debug_printf(logmailbox, "%s on %s mailbox put: %s\n", op->peerName().c_str(), op->name().c_str(), std::string(SB() << val).c_str());

        pv.post(pv_name, val);

        op->reply();
    });

    return ret;
}

WildcardPV WildcardPV::buildReadonly() {
    WildcardPV ret;
    ret.impl = std::make_shared<Impl>();

    ret.onPut([](WildcardPV& pv, std::unique_ptr<ExecOp>&& op, const std::string& pv_name, const std::list<std::string>&, Value&&) {
        op->error(SB() << "Read-only PV: " << pv_name);
    });

    return ret;
}

void WildcardPV::attach(std::unique_ptr<ChannelControl>&& ctrlop, const std::list<std::string> parameters) {
    // in, or after, some Source::onCreate()

    if (!impl) throw std::logic_error("Empty WildcardPV");

    auto self(impl);  // to be captured

    std::shared_ptr<ChannelControl> ctrl(std::move(ctrlop));

    log_debug_printf(logshared, "%s on %s Chan setup\n", ctrl->peerName().c_str(), ctrl->name().c_str());

    ctrl->onRPC([self, parameters](std::unique_ptr<ExecOp>&& op, Value&& arg) {
        // on server worker

        log_debug_printf(logshared, "%s on %s RPC\n", op->peerName().c_str(), op->name().c_str());

        Guard G(self->lock);
        auto cb(self->onRPC);
        if (cb) {
            WildcardPV pv;
            pv.impl = self;
            try {
                UnGuard U(G);
                cb(pv, std::move(op), op->name(), parameters, std::move(arg));
            } catch (std::exception& e) {
                log_err_printf(logshared, "error in RPC cb(%s): %s\n", op->name().c_str(), e.what());
            }
        } else {
            op->error("RPC not implemented by this PV");
        }
    });

    ctrl->onOp([this, self, parameters](std::unique_ptr<ConnectOp>&& op) {
        // on server worker

        std::shared_ptr<ConnectOp> conn(std::move(op));

        log_debug_printf(logshared, "%s on %s Op connecting\n", conn->peerName().c_str(), conn->name().c_str());

        conn->onGet([self](std::unique_ptr<ExecOp>&& op) {
            // on server worker

            log_debug_printf(logshared, "%s on %s Get\n", op->peerName().c_str(), op->name().c_str());

            Value got;
            {
                Guard G(self->lock);
                if (self->current_vals[op->name()]) got = self->current_vals[op->name()].clone();
            }
            if (got) {
                op->reply(got);
            } else {
                op->error("Get races with type change");
            }
        });

        conn->onPut([self, parameters](std::unique_ptr<ExecOp>&& op, Value&& val) {
            // on server worker

            log_debug_printf(logshared, "%s on %s RPC\n", op->peerName().c_str(), op->name().c_str());

            Guard G(self->lock);
            auto cb(self->onPut);
            if (cb) {
                try {
                    WildcardPV pv;
                    pv.impl = self;
                    UnGuard U(G);
                    cb(pv, std::move(op), op->name(), parameters, std::move(val));
                } catch (std::exception& e) {
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
        if (!exists(self->current_vals, conn->name())) {
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

        if (!self->current_vals[conn->name()]) {
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

        if (self->channels[ctrl->name()].empty()) log_debug_printf(logshared, "%s on %s onLastDisconnect()\n", ctrl->peerName().c_str(), ctrl->name().c_str());

        if (self->channels[ctrl->name()].empty() && self->onLastDisconnect) {
            auto cb(self->onLastDisconnect);
            UnGuard U(G);
            WildcardPV pv;
            pv.impl = self;
            cb(pv, ctrl->name(), parameters);
        }
    });

    Guard G(self->lock);

    bool first = impl->channels[ctrl->name()].empty();
    impl->channels[ctrl->name()].insert(ctrl);

    if (first) log_debug_printf(logshared, "%s on %s onFirstConnect()\n", ctrl->peerName().c_str(), ctrl->name().c_str());

    if (first && self->onFirstConnect) {
        auto cb(self->onFirstConnect);
        UnGuard U(G);
        WildcardPV pv;
        pv.impl = self;
        pv.wildcard_pv = wildcard_pv;
        cb(pv, ctrl->name(), parameters);
    }
}

void WildcardPV::onFirstConnect(std::function<void(WildcardPV&, const std::string&, const std::list<std::string>&)>&& fn) {
    if (!impl) throw std::logic_error("Empty WildcardPV");
    Guard G(impl->lock);
    impl->onFirstConnect = std::move(fn);
}

void WildcardPV::onLastDisconnect(std::function<void(WildcardPV&, const std::string&, const std::list<std::string>&)>&& fn) {
    if (!impl) throw std::logic_error("Empty WildcardPV");
    Guard G(impl->lock);
    impl->onLastDisconnect = std::move(fn);
}

void WildcardPV::onPut(
    std::function<void(WildcardPV&, std::unique_ptr<ExecOp>&&, const std::string&, const std::list<std::string>&, Value&&)>&& fn) {
    if (!impl) throw std::logic_error("Empty WildcardPV");
    Guard G(impl->lock);
    impl->onPut = std::move(fn);
}

void WildcardPV::onRPC(
    std::function<void(WildcardPV&, std::unique_ptr<ExecOp>&&, const std::string&, const std::list<std::string>&, Value&&)>&& fn) {
    if (!impl) throw std::logic_error("Empty WildcardPV");
    Guard G(impl->lock);
    impl->onRPC = std::move(fn);
}

void WildcardPV::open(const std::string& pv_name, const Value& initial) {
    if (!impl)
        throw std::logic_error("Empty WildcardPV");
    else if (!initial || initial.type() != TypeCode::Struct)
        throw std::logic_error("Must specify non-empty initial Struct");

    auto& pending = impl->pending[pv_name];
    auto& mpending = impl->mpending[pv_name];

    Value temp;
    {
        Guard G(impl->lock);

        if (exists(impl->current_vals, pv_name)) throw std::logic_error("close() first");

        pending = std::move(impl->pending[pv_name]);
        mpending = std::move(impl->mpending[pv_name]);

        impl->current_vals[pv_name] = initial.clone();
        // make a second copy as 'temp' will be queued
        temp = initial.clone();

        for (auto& op : mpending) {
            Impl::connectSub(G, impl, op, temp);
        }
    }

    for (auto& op : pending) {
        Impl::connectOp(impl, op, temp);
    }
}

bool WildcardPV::isOpen(const std::string& pv_name) const {
    if (!impl) throw std::logic_error("Empty WildcardPV");
    Guard G(impl->lock);
    return exists(impl->current_vals, pv_name);
}

void WildcardPV::close(const std::string& pv_name) {
    if (!impl) throw std::logic_error("Empty WildcardPV");

    auto& channels = impl->channels[pv_name];

    {
        Guard G(impl->lock);

        if (exists(impl->current_vals, pv_name)) impl->current_vals[pv_name] = Value();

        impl->subscribers[pv_name].clear();
        channels = std::move(impl->channels[pv_name]);
    }

    for (auto& ch : channels) {
        if (auto chan = ch.lock()) chan->close();
    }
}

void WildcardPV::close() {
    if (!impl) throw std::logic_error("Empty WildcardPV");

    for ( auto& channel : impl->channels ) {
        auto pv_name = channel.first;
        close(pv_name);
    }
}

void WildcardPV::post(const std::string& pv_name, const Value& val) {
    if (!impl)
        throw std::logic_error("Empty WildcardPV");
    else if (!val)
        throw std::logic_error("Can't post() empty Value");

    Guard G(impl->lock);

    if (!exists(impl->current_vals, pv_name))
        throw std::logic_error("Must open() before post()ing");
    else if (Value::Helper::desc(impl->current_vals[pv_name]) != Value::Helper::desc(val))
        throw std::logic_error("post() requires the exact type of open().  Recommend pvxs::Value::cloneEmpty()");

    impl->current_vals[pv_name].assign(val);

    if (impl->subscribers[pv_name].empty()) return;

    auto copy(val.clone());

    for (auto& sub : impl->subscribers[pv_name]) {
        sub->post(copy);
    }
}

void WildcardPV::fetch(const std::string& pv_name, Value& val) const {
    if (!impl) throw std::logic_error("Empty WildcardPV");

    Guard G(impl->lock);

    if (exists(impl->current_vals, pv_name)) {
        val.assign(impl->current_vals[pv_name]);
    } else {
        throw std::logic_error("open() first");
    }
}

Value WildcardPV::fetch(const std::string& pv_name) const {
    if (!impl) throw std::logic_error("Empty WildcardPV");

    Guard G(impl->lock);

    if (exists(impl->current_vals, pv_name)) {
        return impl->current_vals[pv_name].clone();
    } else {
        throw std::logic_error("open() first");
    }
}

/**
 * @brief Get the parameters from the given wildcard PV name.
 * Will provide strings for each of the parts of the PV name matched by
 * patterns in the wildcard PV name.  e.g. strings of `???` or `*` will
 * resolve to strings in the returned vector.
 *
 * @param pv_name For wildcard PVs this indicates the actual PV requested
 * @return a list of strings that correspond to the parts of the PV name matched by pattern in the Wildcard PV.
 */
std::list<std::string> WildcardPV::getParameters(const std::string &pv_name) noexcept {
    std::list<std::string> parameters;
    size_t pv_name_pos = 0;
    size_t wildcard_pv_pos = 0;

    while (wildcard_pv_pos < wildcard_pv.length() && pv_name_pos < pv_name.length()) {
        if (wildcard_pv[wildcard_pv_pos] == '?') {
            // Extract the sequence of '?' matched characters
            size_t start = pv_name_pos;
            while (wildcard_pv_pos < wildcard_pv.length() && wildcard_pv[wildcard_pv_pos] == '?') {
                wildcard_pv_pos++;
                pv_name_pos++;
            }
            parameters.push_back(pv_name.substr(start, pv_name_pos - start));
        } else if (wildcard_pv[wildcard_pv_pos] == '*') {
            // Extract the sequence of '*' matched characters
            size_t start = pv_name_pos;
            wildcard_pv_pos++;
            if (wildcard_pv_pos < wildcard_pv.length()) {
                // There are more characters in format after '*', find the next part
                char next_char = wildcard_pv[wildcard_pv_pos];
                pv_name_pos = pv_name.find(next_char, pv_name_pos);
                if (pv_name_pos != std::string::npos) {
                    parameters.push_back(pv_name.substr(start, pv_name_pos - start));
                } else {
                    // This condition should not happen in a valid input where the non '*' and '?' match correctly
                    parameters.push_back(pv_name.substr(start));
                    return parameters;
                }
            } else {
                // '*' is the last character in format, extract till the end of pv_name
                parameters.push_back(pv_name.substr(start));
                return parameters;
            }
        } else {
            // Skip the non '?' and '*' characters in the format
            wildcard_pv_pos++;
            pv_name_pos++;
        }
    }
    return parameters;
}

// Checks existence without creating an entry in the map
template <typename T>
bool WildcardPV::exists(const std::map<std::string, T>& m, const std::string& ref) const {
    auto it = m.find(ref);
    return (it != m.end() && !!(it->second));
}

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
void WildcardSource::onSearch(Search& op) {
    auto G(lock.lockReader());

    for(auto& name : op) {
        const auto searched_name = std::string(name.name());

        // Try a wildcard match
        WildcardPV pv;
        if(wildcardMatch(searched_name, pv)) {
            name.claim();
            log_debug_printf(logsource, "%p claim '%s'\n", this, searched_name.c_str());
        }
    }
}

void WildcardSource::onCreate(std::unique_ptr<ChannelControl>&& op)
{
    WildcardPV pv;
    {
        auto G(lock.lockReader());
        const auto searched_name = op->name();

        if(wildcardMatch(searched_name, pv)) {
            log_debug_printf(logsource, "%p create '%s'\n", this, searched_name.c_str());
            pv.attach(std::move(op), pv.getParameters(searched_name));
        } else {
            // not mine
            log_debug_printf(logsource, "%p can't create '%s'\n", this, searched_name.c_str());
        }
    }
}

Source::List WildcardSource::onList()
{
    auto G(lock.lockReader());
    const auto names = std::make_shared<std::set<std::string>>();
    for(auto& pair : pvs) names->insert(pair.first);
    return List{names, true};
}

void WildcardSource::show(std::ostream& strm)
{
    strm<<"StaticProvider";
    auto G(lock.lockReader());
    for(auto& pair : pvs) {
        strm<<"\n"<<indent{}<<pair.first;
    }
}

/**
 * @brief Enhanced wildcard search
 *
 * Enhanced search will try to match `searched_name` based on
 * EPICS wildcard matches (as in epics-base)
 * `pattern` "pv:name:*" => `searched_name` "pv:name:123Abc"
 * `pattern` "pv:name:????" => `searched_name" "pv:name:12Ab"
 *
 * @param searched_name the name presented to the server in the search message
 * @param pv that wildcard pv that matched the wildcard_pv_name
 * @return true if a match is found
 */
bool WildcardSource::wildcardMatch(const std::string& searched_name, WildcardPV& pv) {
    for (const auto &wildcard_shared_pv_pair : pvs) {
        // 1. Prepare PV regex pattern converting from the EPICS wildcard-style patterns to regex syntax
        std::string wildcard_pv = wildcard_shared_pv_pair.first;

        // 1.1 Escape all regex special characters in the original PV pattern
        wildcard_pv = std::regex_replace(wildcard_pv, kRegexSpecialChars, R"(\\$&)");

        // 1.2 Replace Query and Star EPICS wildcard characters with their regex equivalents
        std::replace(wildcard_pv.begin(), wildcard_pv.end(), kWildcardQueryCharacter, '.');
        wildcard_pv = std::regex_replace(wildcard_pv, kWildcardStarPattern, ".*");

        // 2. Compare the PV regex pattern with the `searched_name`
        std::regex pv_regex_pattern(wildcard_pv);
        if (std::regex_match(searched_name, pv_regex_pattern)) {
            try {
                std::shared_ptr<WildcardPV> base_pv = wildcard_shared_pv_pair.second;
                if (!base_pv) {
                    throw std::bad_cast();
                }
                pv = *base_pv; // Assign or use as needed
                pv.wildcard_pv = wildcard_shared_pv_pair.first;
            } catch (const std::bad_cast& e) {
                throw std::runtime_error(std::string("Programming error: use WildcardPVs for wildcard PVs: ") + wildcard_shared_pv_pair.first);
            }
            return true;
        }
    }
    return false;
}

std::shared_ptr<WildcardSource> WildcardSource::build() {
    return std::make_shared<WildcardSource>();
}

WildcardPV::~WildcardPV() {}

void WildcardSource::close() {
    auto G(lock.lockReader());

    for (const auto& pair : pvs) {
        pair.second->close();
    }
}

WildcardSource& WildcardSource::add(const std::string& name, const WildcardPV& pv) {
    auto G(lock.lockWriter());
    if (pvs.find(name)!=pvs.end())
        throw std::logic_error("add() will not create duplicate PV");
    pvs[name] = std::make_shared<WildcardPV>(pv);
    return *this;
}

WildcardSource& WildcardSource::remove(const std::string& name) {
    auto G(lock.lockWriter());
    WildcardPV pv;
    {
        const auto it = pvs.find(name);
        if (it==pvs.end()) return *this;
        pvs.erase(it);
        pv = *it->second;
    }
    pv.close(name);
    return *this;
}

WildcardSource::list_t WildcardSource::list() const {
    list_t ret;
    auto G(lock.lockReader());
    for (const auto& pair : pvs) {
        ret[pair.first] = *(pair.second);
    }
    return ret;
}

}  // namespace server
}  // namespace pvxs
