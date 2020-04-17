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
void split_addr_into(const char* name, std::vector<std::string>& out, const std::string& inp, uint16_t defaultPort)
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
                log_err_printf(config, "%s ignoring invalid '%s'\n", name, temp.c_str());
                continue;
            }
            char buf[24];
            ipAddrToDottedIP(&addr, buf, sizeof(buf));
            out.emplace_back(buf);
        }
    }
}

const char* pickenv(const char** picked, std::initializer_list<const char*> names)
{
    for(auto name : names) {
        if(auto val = getenv(name)) {
            if(picked)
                *picked = name;
            return val;
        }
    }
    return nullptr;
}

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

Config Config::from_env()
{
    Config ret;

    const char* name;

    if(const char *env = pickenv(&name, {"EPICS_PVAS_SERVER_PORT", "EPICS_PVA_SERVER_PORT"})) {
        try {
            ret.tcp_port = parseTo<uint64_t>(env);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", name, e.what());
        }
    }

    if(const char *env = pickenv(&name, {"EPICS_PVAS_BROADCAST_PORT", "EPICS_PVA_BROADCAST_PORT"})) {
        try {
            ret.udp_port = parseTo<uint64_t>(env);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", name, e.what());
        }
    }

    if(const char *env = pickenv(&name, {"EPICS_PVAS_INTF_ADDR_LIST"})) {
        split_addr_into(name, ret.interfaces, env, ret.tcp_port);
    }

    if(auto env = pickenv(&name, {"EPICS_PVAS_BEACON_ADDR_LIST", "EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(name, ret.beaconDestinations, env, ret.udp_port);
    }

    if(const char *env = pickenv(&name, {"EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "EPICS_PVA_AUTO_ADDR_LIST"})) {
        if(epicsStrCaseCmp(env, "YES")==0) {
            ret.auto_beacon = true;
        } else if(epicsStrCaseCmp(env, "NO")==0) {
            ret.auto_beacon = false;
        } else {
            log_err_printf(serversetup, "%s invalid bool value (YES/NO)", name);
        }
    }

    return ret;
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

Config Config::from_env()
{
    Config ret;

    const char* name;

    if(const char *env = pickenv(&name, {"EPICS_PVA_BROADCAST_PORT"})) {
        try {
            ret.udp_port = parseTo<uint64_t>(env);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", name, e.what());
        }
    }
    if(ret.udp_port==0u) {
        log_err_printf(serversetup, "ignoring EPICS_PVA_BROADCAST_PORT=%d", 0);
        ret.udp_port = 5076;
    }

    if(const char *env = pickenv(&name, {"EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(name, ret.addressList, env, ret.udp_port);
    }

    if(const char *env = pickenv(&name, {"EPICS_PVA_AUTO_ADDR_LIST"})) {
        if(epicsStrCaseCmp(env, "YES")==0) {
            ret.autoAddrList = true;
        } else if(epicsStrCaseCmp(env, "NO")==0) {
            ret.autoAddrList = false;
        } else {
            log_err_printf(serversetup, "%s invalid bool value (YES/NO)", name);
        }
    }

    return ret;
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
