/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <iterator>

#include <dbDefs.h>
#include <osiSock.h>
#include <epicsString.h>

#include <pvxs/log.h>
#include "serverconn.h"
#include "clientimpl.h"
#include "evhelper.h"

DEFINE_LOGGER(serversetup, "pvxs.server.setup");
DEFINE_LOGGER(config, "pvxs.config");

namespace pvxs {

namespace {
void split_addr_into(const char* name, std::vector<std::string>& out, const std::string& inp,
                     uint16_t defaultPort, bool required=false)
{
    size_t pos=0u;

    while(pos<inp.size()) {
        auto start = inp.find_first_not_of(" \t\r\n", pos);
        auto end = inp.find_first_of(" \t\r\n", start);
        pos = end;

        if(start<end) {
            auto temp = inp.substr(start, end==std::string::npos ? end : end-start);

            sockaddr_in addr = {};
            if(aToIPAddr(temp.c_str(), defaultPort, &addr)) {
                if(required)
                    throw std::runtime_error(SB()<<"invalid IP or non-existent hostname \""<<temp<<"\"");
                log_err_printf(config, "%s ignoring invalid '%s'\n", name, temp.c_str());
                continue;
            }
            char buf[24];
            ipAddrToDottedIP(&addr, buf, sizeof(buf));
            out.emplace_back(buf);
        }
    }
}

std::string join_addr(const std::vector<std::string>& in)
{
    std::ostringstream strm;
    std::copy(in.begin(), in.end(), std::ostream_iterator<std::string>(strm, " "));
    return strm.str();
}

struct PickOne {
    const std::map<std::string, std::string>& defs;
    bool useenv;

    std::string name, val;

    bool operator()(std::initializer_list<const char*> names) {
        for(auto candidate : names) {
            if(useenv) {
                if(auto eval = getenv(candidate)) {
                    name = candidate;
                    val = eval;
                    return true;
                }

            } else {
                auto it = defs.find(candidate);
                if(it!=defs.end()) {
                    name = candidate;
                    val = it->second;
                    return true;
                }
            }
        }
        return false;
    }
};

template<typename Fn>
struct cleaner {
    Fn fn;
    ~cleaner() { fn(); }
};

template<typename Fn>
cleaner<Fn> make_cleaner(Fn&& fn) {
    return cleaner<Fn>{std::move(fn)};
}

// Fill out address list by appending broadcast addresses
// of any and all local interface addresses already included
void expandAddrList(const std::vector<std::string>& ifaces,
                    std::vector<std::string>& addrs)
{
    evsocket dummy(AF_INET, SOCK_DGRAM, 0);

    std::vector<std::string> bcasts;

    for(auto& addr : ifaces) {

        ELLLIST blist = ELLLIST_INIT;
        auto bclean = make_cleaner([&blist] {
            ellFree(&blist);
        });

        SockAddr saddr(AF_INET);
        try {
            saddr.setAddress(addr.c_str());
        }catch(std::runtime_error& e){
            log_warn_printf(config, "%s  Ignoring...\n", e.what());
            continue;
        }

        osiSockAddr match = {};
        match.ia = saddr->in;
        osiSockDiscoverBroadcastAddresses(&blist, dummy.sock, &match);

        while(ELLNODE *cur = ellGet(&blist)) {
            osiSockAddrNode *node = CONTAINER(cur, osiSockAddrNode, node);

            SockAddr temp(&node->addr.sa, sizeof(node->addr.ia));
            free(node);
            temp.setPort(0u);

            bcasts.push_back(temp.tostring());
        }
    }

    addrs.reserve(addrs.size()+bcasts.size());
    for(auto& bcast : bcasts) {
        addrs.push_back(std::move(bcast));
    }
}

void removeDups(std::vector<std::string>& addrs)
{
    addrs.erase(std::unique(addrs.begin(), addrs.end()),
                addrs.end());
}

} // namespace

namespace server {

static
void _fromDefs(Config& self, const std::map<std::string, std::string>& defs, bool useenv)
{
    PickOne pickone{defs, useenv};

    if(pickone({"EPICS_PVAS_SERVER_PORT", "EPICS_PVA_SERVER_PORT"})) {
        try {
            self.tcp_port = parseTo<uint64_t>(pickone.val);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }

    if(pickone({"EPICS_PVAS_BROADCAST_PORT", "EPICS_PVA_BROADCAST_PORT"})) {
        try {
            self.udp_port = parseTo<uint64_t>(pickone.val);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }

    if(pickone({"EPICS_PVAS_INTF_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.interfaces, pickone.val, self.tcp_port, true);
    }

    if(pickone({"EPICS_PVAS_BEACON_ADDR_LIST", "EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.beaconDestinations, pickone.val, self.udp_port);
    }

    if(pickone({"EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "EPICS_PVA_AUTO_ADDR_LIST"})) {
        if(epicsStrCaseCmp(pickone.val.c_str(), "YES")==0) {
            self.auto_beacon = true;
        } else if(epicsStrCaseCmp(pickone.val.c_str(), "NO")==0) {
            self.auto_beacon = false;
        } else {
            log_err_printf(serversetup, "%s invalid bool value (YES/NO)", pickone.name.c_str());
        }
    }
}

Config& Config::applyEnv()
{
    _fromDefs(*this, std::map<std::string, std::string>(), true);
    return *this;
}

Config Config::isolated()
{
    Config ret;

    ret.udp_port = 0u;
    ret.tcp_port = 0u;
    ret.interfaces.emplace_back("127.0.0.1");
    ret.auto_beacon = false;
    ret.beaconDestinations.emplace_back("127.0.0.1");

    return ret;
}

Config& Config::applyDefs(const std::map<std::string, std::string>& defs)
{
    _fromDefs(*this, defs, false);
    return *this;
}

void Config::updateDefs(defs_t& defs) const
{
    defs["EPICS_PVAS_BROADCAST_PORT"] = SB()<<udp_port;
    defs["EPICS_PVAS_SERVER_PORT"] = SB()<<tcp_port;
    defs["EPICS_PVAS_AUTO_BEACON_ADDR_LIST"] = auto_beacon ? "YES" : "NO";
    defs["EPICS_PVAS_BEACON_ADDR_LIST"] = join_addr(beaconDestinations);
    defs["EPICS_PVAS_INTF_ADDR_LIST"] = join_addr(interfaces);
}

void Config::expand()
{
    // empty interface address list implies the wildcard
    // (because no addresses isn't interesting...)
    if(interfaces.empty()) {
        interfaces.emplace_back("0.0.0.0");
    }

    if(auto_beacon) {
        expandAddrList(interfaces, beaconDestinations);
        auto_beacon = false;
    }

    removeDups(interfaces);
    removeDups(beaconDestinations);
}

std::ostream& operator<<(std::ostream& strm, const Config& conf)
{
    bool first;

    strm<<"EPICS_PVAS_INTF_ADDR_LIST=\"";
    first = true;
    for(auto& iface : conf.interfaces) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<iface;
    }
    strm<<"\"\n";

    strm<<"EPICS_PVAS_BEACON_ADDR_LIST=\"";
    first = true;
    for(auto& iface : conf.beaconDestinations) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<iface;
    }
    strm<<"\"\n";

    strm<<"EPICS_PVAS_AUTO_BEACON_ADDR_LIST="<<(conf.auto_beacon?"YES":"NO")<<'\n';

    strm<<"EPICS_PVAS_SERVER_PORT="<<conf.tcp_port<<'\n';

    strm<<"EPICS_PVAS_BROADCAST_PORT="<<conf.udp_port<<'\n';

    return strm;
}

} // namespace server

namespace client {

static
void _fromDefs(Config& self, const std::map<std::string, std::string>& defs, bool useenv)
{
    PickOne pickone{defs, useenv};

    if(pickone({"EPICS_PVA_BROADCAST_PORT"})) {
        try {
            self.udp_port = parseTo<uint64_t>(pickone.val);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }
    if(self.udp_port==0u) {
        log_err_printf(serversetup, "ignoring EPICS_PVA_BROADCAST_PORT=%d", 0);
        self.udp_port = 5076;
    }

    if(pickone({"EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.addressList, pickone.val, self.udp_port);
    }

    if(pickone({"EPICS_PVA_AUTO_ADDR_LIST"})) {
        if(epicsStrCaseCmp(pickone.val.c_str(), "YES")==0) {
            self.autoAddrList = true;
        } else if(epicsStrCaseCmp(pickone.val.c_str(), "NO")==0) {
            self.autoAddrList = false;
        } else {
            log_err_printf(serversetup, "%s invalid bool value (YES/NO)", pickone.name.c_str());
        }
    }
}

Config& Config::applyEnv()
{
    _fromDefs(*this, std::map<std::string, std::string>(), true);
    return *this;
}

Config& Config::applyDefs(const std::map<std::string, std::string>& defs)
{
    _fromDefs(*this, defs, false);
    return *this;
}

void Config::updateDefs(defs_t& defs) const
{
    defs["EPICS_PVA_BROADCAST_PORT"] = SB()<<udp_port;
    defs["EPICS_PVA_AUTO_ADDR_LIST"] = autoAddrList ? "YES" : "NO";
    defs["EPICS_PVA_ADDR_LIST"] = join_addr(interfaces);
}

void Config::expand()
{
    if(udp_port==0)
        throw std::runtime_error("Client can't use UDP random port");

    if(interfaces.empty())
        interfaces.emplace_back("0.0.0.0");

    if(autoAddrList) {
        expandAddrList(interfaces, addressList);
        autoAddrList = false;
    }

    removeDups(addressList);
}

std::ostream& operator<<(std::ostream& strm, const Config& conf)
{
    bool first;

    strm<<"EPICS_PVA_ADDR_LIST=\"";
    first = true;
    for(auto& iface : conf.addressList) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<iface;
    }
    strm<<"\"\n";

    strm<<"EPICS_PVA_AUTO_ADDR_LIST="<<(conf.autoAddrList?"YES":"NO")<<'\n';

    strm<<"EPICS_PVA_BROADCAST_PORT="<<conf.udp_port<<'\n';

    return strm;
}

} // namespace client

} // namespace pvxs
