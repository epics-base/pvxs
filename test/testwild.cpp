/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <atomic>

#include <testMain.h>

#include <epicsUnitTest.h>

#include <epicsEvent.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/nt.h>
#include "evhelper.h"

namespace {
using namespace pvxs;

// Ensure we can setup a server and client on the wildcard interface(s).
// bind()ing sockets and similar.
// No operations are attempted as the default interface on some test systems
// may have firewall rules blocking PVA traffic in and/or out.
void testwildcard(const std::string& addr1, const std::string& addr2)
{
    testDiag("%s(%s, %s)", __func__,addr1.c_str(), addr2.c_str());

    server::Config sconf;
    sconf.tcp_port = sconf.udp_port = 0u; // choose randomly

    if(!addr1.empty())
        sconf.interfaces.push_back(addr1);
    if(!addr2.empty())
        sconf.interfaces.push_back(addr2);

    auto serv(sconf.build());
    sconf = serv.config();
    testShow()<<"Server Config\n"<<sconf;

    testNotEq(0u, sconf.udp_port);
    testNotEq(0u, sconf.tcp_port);

    auto cli(serv.clientConfig().build());
    auto cconf(cli.config());
    testShow()<<"Client Config\n"<<cconf;

    testEq(sconf.udp_port, cconf.udp_port);
    testEq(sconf.tcp_port, cconf.tcp_port);
}

// check logic for detection and fallback when requested TCP port
// is already in use.
void testconflict(const char* addr)
{
    testDiag("%s(\"%s\")", __func__, addr);

    evsocket otherserver(AF_INET, SOCK_STREAM, 0);
    otherserver.bind(SockAddr::any(AF_INET));
    otherserver.listen(4);

    server::Config iconf;
    iconf.tcp_port = otherserver.sockname().port();
    iconf.udp_port = 0u; // choose randomly
    if(addr)
        iconf.interfaces.push_back(addr);

    auto serv(iconf.build());
    auto fconf(serv.config());
    testShow()<<"Server Config\n"<<iconf;

    testNotEq(0u, fconf.udp_port)<<"w/ "<<addr;
    testNotEq(iconf.tcp_port, fconf.tcp_port)<<"w/ "<<addr;
}

} // namespace

MAIN(testwild)
{
    testPlan(18);
    testSetup();
    logger_config_env();
    SockAttach attach;
    const bool canIPv6 = pvxs::impl::evsocket::canIPv6;
    testwildcard("", ""); // implies 0.0.0.0
    testwildcard("0.0.0.0", "");
    if(canIPv6) {
        testwildcard("::", "");
    } else {
        testSkip(4, "No IPv6 Support");
    }
    if(evsocket::ipstack==evsocket::Linsock) {
        testconflict("127.0.0.1");
    } else {
        testSkip(2, "Can bind both 0.0.0.0 and 127.0.0.1 to the same port");
    }
    testconflict("0.0.0.0");
    if(canIPv6) {
        testconflict("::");
    } else {
        testSkip(2, "No IPv6 Support");
    }
    return testDone();
}
