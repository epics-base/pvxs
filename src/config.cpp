/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <vector>
#include <string>
#include <sstream>

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
            std::ostringstream strm;
            uint32_t ip = ntohl(addr.sin_addr.s_addr);
            strm<<((ip>>24)&0xff)<<'.'<<((ip>>16)&0xff)<<'.'<<((ip>>8)&0xff)<<'.'<<((ip>>0)&0xff);
            if(addr.sin_port)
                strm<<':'<<ntohs(addr.sin_port);
            out.emplace_back(strm.str());
        }
    }
}

std::string join_addr(const std::vector<std::string>& in)
{
    std::ostringstream strm;
    bool first=true;
    for(auto& addr : in) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<addr;
    }
    return strm.str();
}

void parse_bool(bool& dest, const std::string& name, const std::string& val)
{
    if(epicsStrCaseCmp(val.c_str(), "YES")==0 || val=="1") {
        dest = true;
    } else if(epicsStrCaseCmp(val.c_str(), "NO")==0 || val=="0") {
        dest = false;
    } else {
        log_err_printf(serversetup, "%s invalid bool value (YES/NO) : '%s'\n",
                       name.c_str(), val.c_str());
    }
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
    SockAttach attach;
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
        parse_bool(self.auto_beacon, pickone.name, pickone.val);
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
    defs["EPICS_PVA_BROADCAST_PORT"] = defs["EPICS_PVAS_BROADCAST_PORT"] = SB()<<udp_port;
    defs["EPICS_PVA_SERVER_PORT"]    = defs["EPICS_PVAS_SERVER_PORT"]    = SB()<<tcp_port;
    defs["EPICS_PVA_AUTO_ADDR_LIST"] = defs["EPICS_PVAS_AUTO_BEACON_ADDR_LIST"] = auto_beacon ? "YES" : "NO";
    defs["EPICS_PVA_ADDR_LIST"]      = defs["EPICS_PVAS_BEACON_ADDR_LIST"] = join_addr(beaconDestinations);
    defs["EPICS_PVA_INTF_ADDR_LIST"] = defs["EPICS_PVAS_INTF_ADDR_LIST"]   = join_addr(interfaces);
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

    strm<<indent{}<<"EPICS_PVAS_INTF_ADDR_LIST=\"";
    first = true;
    for(auto& iface : conf.interfaces) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<iface;
    }
    strm<<"\"\n";

    strm<<indent{}<<"EPICS_PVAS_BEACON_ADDR_LIST=\"";
    first = true;
    for(auto& iface : conf.beaconDestinations) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<iface;
    }
    strm<<"\"\n";

    strm<<indent{}<<"EPICS_PVAS_AUTO_BEACON_ADDR_LIST="<<(conf.auto_beacon?"YES":"NO")<<'\n';

    strm<<indent{}<<"EPICS_PVAS_SERVER_PORT="<<conf.tcp_port<<'\n';

    strm<<indent{}<<"EPICS_PVAS_BROADCAST_PORT="<<conf.udp_port<<'\n';

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
        parse_bool(self.autoAddrList, pickone.name, pickone.val);
    }

    if(pickone({"EPICS_PVA_INTF_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.interfaces, pickone.val, 0);
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
    defs["EPICS_PVA_ADDR_LIST"] = join_addr(addressList);
    defs["EPICS_PVA_INTF_ADDR_LIST"] = join_addr(interfaces);
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

    strm<<indent{}<<"EPICS_PVA_ADDR_LIST=\"";
    first = true;
    for(auto& iface : conf.addressList) {
        if(first)
            first = false;
        else
            strm<<' ';
        strm<<iface;
    }
    strm<<"\"\n";

    strm<<indent{}<<"EPICS_PVA_AUTO_ADDR_LIST="<<(conf.autoAddrList?"YES":"NO")<<'\n';

    strm<<indent{}<<"EPICS_PVA_BROADCAST_PORT="<<conf.udp_port<<'\n';

    return strm;
}

} // namespace client

} // namespace pvxs
