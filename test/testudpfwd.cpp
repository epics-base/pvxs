/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define PVXS_ENABLE_EXPERT_API

#include <testMain.h>
#include <epicsUnitTest.h>
#include <pvxs/unittest.h>

#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/client.h>
#include "evhelper.h"


using namespace pvxs;

namespace {

bool testFwdVia(const server::Config& base, const SockAddr& ifaddr)
{
    bool ok = true;
    testDiag("In %s(%s)", __func__, ifaddr.tostring().c_str());

    auto pv(server::SharedPV::buildMailbox());
    pv.open(nt::NTScalar{TypeCode::UInt32}.create().update("value", 42u));

    server::Server srv1, srv2, srv3;
    {
        auto sconf = base;
        sconf.overrideShareUDP(false);
        // unicast through one interface
        sconf.tcp_port = sconf.udp_port = 0;
        if(ifaddr.family()!=AF_UNSPEC)
            sconf.interfaces.push_back(ifaddr.tostring());
        sconf.auto_beacon = false;

        srv1 = sconf.build();

        sconf = srv1.config();
        sconf.overrideShareUDP(false);

        srv2 = sconf.build();

        // bind to wildcard
        sconf.interfaces.clear();
        /* BSD and MS IP stacks allow two TCP sockets bound to the same port
         * one to wildcard and one to an interface address.  This leaves one
         * of the two sometimes unreachable.
         * Explicitly select random port as workaround.
         */
        sconf.tcp_port = 0;
        srv3 = sconf.build();
    }

    auto tcp1 = srv1.config().tcp_port;
    auto tcp2 = srv2.config().tcp_port;
    auto tcp3 = srv3.config().tcp_port;
    if(tcp1==tcp2 || tcp1==tcp3 || tcp2==tcp3) {
        testFail("Server bind() conflict %d, %d, %d", tcp1, tcp2, tcp3);
    }

    srv1.addPV("testpv1", pv);
    srv2.addPV("testpv2", pv);
    srv3.addPV("testpv3", pv);

    srv1.start();
    srv2.start();
    srv3.start();

    auto cli(srv1.clientConfig().build());
    /* There are now 4x UDP sockets listening.  Only one will receive unicast search.
     * Which one is OS dependent.  With Linux the last (cli), with Windows the first (srv1).
     */

    const auto doGet = [&cli](const char* pvname) -> bool {
        try {
            auto result = cli.get(pvname).exec()->wait(5.0);
            testDiag("Success %s %u", pvname, (unsigned)result["value"].as<uint32_t>());
            return true;
        } catch (client::Timeout&) {
            testDiag("Timeout %s", pvname);
            return false;
        }
    };

    ok &= doGet("testpv1");
    ok &= doGet("testpv2");
    ok &= doGet("testpv3");
    return ok;
}

void testFwdIface()
{
    testDiag("In %s", __func__);

    std::vector<SockAddr> ifaddrs;
    {
        auto& ifs(IfaceMap::instance());

        epicsGuard<epicsMutex> G(ifs.lock);

        for(auto it : ifs.byIndex) {
            auto& iface = it.second;
            if(iface.isLO)
                continue;

            for(auto it2 : iface.addrs) {
                if(it2.first.family()!=AF_INET)
                    continue; // TODO: ipv6 link local addresses don't have scope set
                ifaddrs.emplace_back(it2.first);
            }
        }
    }

    bool ok = false;
    for(auto& ifaddr : ifaddrs) {
        ok |= testFwdVia(server::Config{}, ifaddr);
    }

#if defined(__rtems__) || defined(vxWorks)
    testSkip(1, "local mcast unnecessary with a single OS process");
#else
    testOk(!!ok, "Succeeded via at least one interface");
#endif
}


} // namespace

MAIN(testudpfwd)
{
    SockAttach attach;
    testPlan(1);
    testSetup();
    pvxs::logger_config_env();
    testFwdIface();
    cleanup_for_valgrind();
    return testDone();
}
