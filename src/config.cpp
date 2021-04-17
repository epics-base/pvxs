/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <limits>
#include <cmath>

#include <dbDefs.h>
#include <osiSock.h>
#include <epicsMath.h>
#include <epicsStdlib.h>
#include <epicsString.h>

#include <pvxs/log.h>
#include "serverconn.h"
#include "clientimpl.h"
#include "evhelper.h"

DEFINE_LOGGER(serversetup, "pvxs.server.setup");
DEFINE_LOGGER(clientsetup, "pvxs.client.setup");
DEFINE_LOGGER(config, "pvxs.config");

namespace pvxs {

namespace {

/* Historically pvAccessCPP used $EPICS_PVA_CONN_TMO as the period
 * between sending CMD_ECHO.  *::Config::tcpTimeout is the actual
 * inactivity timeout period.  Apply a scaling factor to add a
 * go from one to the other.
 */
constexpr double tmoScale = 4.0/3.0; // 40 second idle timeout / 30 configured

void split_addr_into(const char* name, std::vector<std::string>& out, const std::string& inp,
                     uint16_t defaultPort, bool required=false)
{
    size_t pos=0u;

    // parse, resolve host names, then re-print.
    // Catch syntax errors early, and normalize prior to removing duplicates
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

    // remove any duplicates
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()),
              out.end());
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
        log_err_printf(config, "%s invalid bool value (YES/NO) : '%s'\n",
                       name.c_str(), val.c_str());
    }
}

void parse_timeout(double& dest, const std::string& name, const std::string& val)
{
    double temp;
    try {
        temp = parseTo<double>(val);

        if(!std::isfinite(temp)
                || temp<0.0
                || temp>double(std::numeric_limits<time_t>::max()))
            throw std::out_of_range("Out of range");

        dest = temp*tmoScale;
    } catch(std::exception& e) {
        log_err_printf(serversetup, "%s invalid double value : '%s'\n",
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

// Fill out address list by appending broadcast addresses
// of any and all local interface addresses already included
void expandAddrList(const std::vector<std::string>& ifaces,
                    std::vector<std::string>& addrs)
{
    SockAttach attach;
    evsocket dummy(AF_INET, SOCK_DGRAM, 0);

    std::vector<std::string> bcasts;

    for(auto& addr : ifaces) {
        SockAddr saddr(AF_INET);
        try {
            saddr.setAddress(addr.c_str());
        }catch(std::runtime_error& e){
            log_warn_printf(config, "%s  Ignoring...\n", e.what());
            continue;
        }

        for(auto& addr : dummy.interfaces(&saddr)) {
            addr.setPort(0u);
            bcasts.push_back(addr.tostring());
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

void enforceTimeout(double& tmo)
{
    /* Inactivity timeouts with PVA have a long (and growing) history.
     *
     * - Originally pvAccessCPP clients didn't send CMD_ECHO, and servers would never timeout.
     * - Since module version 7.0.0 (in Base 7.0.3) clients send echo every 15 seconds, and
     *   either peer will timeout after 30 seconds of inactivity.
     * - pvAccessJava clients send CMD_ECHO every 30 seconds, and timeout after 60 seconds.
     *
     * So this was a bug, with c++ server timeout racing with Java client echo.
     *
     * - As a compromise, continue to send echo at least every 15 seconds,
     *   and increase default timeout to 40.
     */
    if(!std::isfinite(tmo) || tmo <= 0.0 || tmo >= double(std::numeric_limits<time_t>::max()))
        tmo = 40.0;
    else if(tmo < 2.0)
        tmo = 2.0;
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

    if(pickone({"EPICS_PVAS_IGNORE_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.ignoreAddrs, pickone.val, 0, true);
    }

    if(pickone({"EPICS_PVAS_BEACON_ADDR_LIST", "EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.beaconDestinations, pickone.val, self.udp_port);
    }

    if(pickone({"EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "EPICS_PVA_AUTO_ADDR_LIST"})) {
        parse_bool(self.auto_beacon, pickone.name, pickone.val);
    }

    if(pickone({"EPICS_PVA_CONN_TMO"})) {
        parse_timeout(self.tcpTimeout, pickone.name, pickone.val);
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
    defs["EPICS_PVAS_IGNORE_ADDR_LIST"]   = join_addr(ignoreAddrs);
    defs["EPICS_PVA_CONN_TMO"] = SB()<<tcpTimeout/tmoScale;
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
    removeDups(ignoreAddrs);

    enforceTimeout(tcpTimeout);
}

std::ostream& operator<<(std::ostream& strm, const Config& conf)
{
    auto showAddrs = [&strm](const char* var, const std::vector<std::string>& addrs) {
        strm<<indent{}<<var<<"=\"";
        bool first = true;
        for(auto& iface : addrs) {
            if(first)
                first = false;
            else
                strm<<' ';
            strm<<iface;
        }
        strm<<"\"\n";
    };

    showAddrs("EPICS_PVAS_INTF_ADDR_LIST", conf.interfaces);
    showAddrs("EPICS_PVAS_BEACON_ADDR_LIST", conf.beaconDestinations);
    showAddrs("EPICS_PVAS_IGNORE_ADDR_LIST", conf.ignoreAddrs);

    strm<<indent{}<<"EPICS_PVAS_AUTO_BEACON_ADDR_LIST="<<(conf.auto_beacon?"YES":"NO")<<'\n';

    strm<<indent{}<<"EPICS_PVAS_SERVER_PORT="<<conf.tcp_port<<'\n';

    strm<<indent{}<<"EPICS_PVAS_BROADCAST_PORT="<<conf.udp_port<<'\n';

    strm<<indent{}<<"EPICS_PVA_CONN_TMO="<<conf.tcpTimeout/tmoScale<<'\n';

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
            log_warn_printf(clientsetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }
    if(self.udp_port==0u) {
        log_warn_printf(clientsetup, "ignoring EPICS_PVA_BROADCAST_PORT=%d\n", 0);
        self.udp_port = 5076;
    }

    if(pickone({"EPICS_PVA_SERVER_PORT", "EPICS_PVAS_SERVER_PORT"})) {
        try {
            self.tcp_port = parseTo<uint64_t>(pickone.val);
        }catch(std::exception& e) {
            log_warn_printf(clientsetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }
    if(self.tcp_port==0u && !self.nameServers.empty()) {
        log_warn_printf(clientsetup, "ignoring EPICS_PVA_SERVER_PORT=%d\n", 0);
        self.tcp_port = 5075;
    }

    if(pickone({"EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.addressList, pickone.val, self.udp_port);
    }

    if(pickone({"EPICS_PVA_NAME_SERVERS"})) {
        split_addr_into(pickone.name.c_str(), self.nameServers, pickone.val, self.tcp_port);
    }

    if(pickone({"EPICS_PVA_AUTO_ADDR_LIST"})) {
        parse_bool(self.autoAddrList, pickone.name, pickone.val);
    }

    if(pickone({"EPICS_PVA_INTF_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.interfaces, pickone.val, 0);
    }

    if(pickone({"EPICS_PVA_CONN_TMO"})) {
        parse_timeout(self.tcpTimeout, pickone.name, pickone.val);
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
    defs["EPICS_PVA_SERVER_PORT"] = SB()<<tcp_port;
    defs["EPICS_PVA_AUTO_ADDR_LIST"] = autoAddrList ? "YES" : "NO";
    defs["EPICS_PVA_ADDR_LIST"] = join_addr(addressList);
    defs["EPICS_PVA_INTF_ADDR_LIST"] = join_addr(interfaces);
    defs["EPICS_PVA_CONN_TMO"] = SB()<<tcpTimeout/tmoScale;
}

void Config::expand()
{
    if(udp_port==0)
        throw std::runtime_error("Client can't use UDP random port");

    if(tcp_port==0)
        tcp_port = 5075;

    if(interfaces.empty())
        interfaces.emplace_back("0.0.0.0");

    if(autoAddrList) {
        expandAddrList(interfaces, addressList);
        autoAddrList = false;
    }

    removeDups(addressList);

    enforceTimeout(tcpTimeout);
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

    strm<<indent{}<<"EPICS_PVA_SERVER_PORT="<<conf.tcp_port<<'\n';

    strm<<indent{}<<"EPICS_PVA_CONN_TMO="<<conf.tcpTimeout/tmoScale<<'\n';

    return strm;
}

} // namespace client

} // namespace pvxs
