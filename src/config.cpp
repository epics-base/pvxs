/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <vector>
#include <string>
#include <regex>

#include <osiSock.h>
#include <epicsString.h>

#include <pvxs/log.h>
#include "serverconn.h"

DEFINE_LOGGER(serversetup, "pvxs.server.setup");

namespace {
void split_addr_into(const char* name, std::vector<std::string>& out, const char *inp)
{
    std::regex word("\\s*(\\S+)(.*)");
    std::cmatch M;

    while(*inp && std::regex_match(inp, M, word)) {
        sockaddr_in addr = {};
        if(aToIPAddr(M[1].str().c_str(), 0, &addr)) {
            log_err_printf(serversetup, "%s ignoring invalid '%s'\n", name, M[1].str().c_str());
            continue;
        }
        char buf[24];
        ipAddrToDottedIP(&addr, buf, sizeof(buf));
        out.emplace_back(buf);
        inp = M[2].first;
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

} // namespace

namespace pvxs {
namespace server {

Config Config::from_env()
{
    Config ret;
    ret.udp_port = 5076;

    const char* name;

    if(const char *env = pickenv(&name, {"EPICS_PVAS_INTF_ADDR_LIST"})) {
        split_addr_into(name, ret.interfaces, env);
    }

    if(auto env = pickenv(&name, {"EPICS_PVAS_BEACON_ADDR_LIST", "EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(name, ret.beaconDestinations, env);
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

    if(const char *env = pickenv(&name, {"EPICS_PVAS_SERVER_PORT", "EPICS_PVA_SERVER_PORT"})) {
        try {
            ret.tcp_port = lexical_cast<unsigned short>(env);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", name, e.what());
        }
    }

    if(const char *env = pickenv(&name, {"EPICS_PVAS_BROADCAST_PORT", "EPICS_PVA_BROADCAST_PORT"})) {
        try {
            ret.udp_port = lexical_cast<unsigned short>(env);
        }catch(std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", name, e.what());
        }
    }

    return ret;
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

}
}
