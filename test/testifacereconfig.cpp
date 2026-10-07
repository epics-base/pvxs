/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <set>
#include <tuple>

#include <epicsUnitTest.h>

#define PVXS_ENABLE_EXPERT_API

#include <pvxs/unittest.h>

#include "clientimpl.h"
#include "serverconn.h"

using namespace pvxs;

namespace {

void addIface(IfaceMap::Current& cur, uint64_t index, const std::string& name, bool isLO)
{
    auto pair(cur.byIndex.emplace(std::piecewise_construct,
                                  std::forward_as_tuple(index),
                                  std::forward_as_tuple(name, index, isLO)));
    pair.first->second.addrs.emplace(SockAddr("127.0.0.1"), SockAddr("127.255.255.255"));
}

void testIfaceMapCurrentSame()
{
    testShow()<<__func__;

    IfaceMap::Current one, two;

    testTrue(one.same(two));

    addIface(one, 1u, "lo0", true);
    addIface(two, 1u, "lo0", true);
    testTrue(one.same(two));

    two.byIndex.begin()->second.name = "lo1";
    testFalse(one.same(two));

    two.byIndex.begin()->second.name = "lo0";
    two.byIndex.begin()->second.addrs.clear();
    testFalse(one.same(two));
}

void testClientSearchDest()
{
    testShow()<<__func__;

    client::Config conf;
    conf.udp_port = 1234u;
    conf.autoAddrList = false;
    conf.addressList = {"1.2.3.4", "5.6.7.8:9876"};

    std::set<SockAddr, SockAddrOnlyLess> bcasts;
    bcasts.emplace("1.2.3.4");

    auto dest(client::ContextImpl::buildSearchDest(conf, bcasts, false));

    testEq(dest.size(), 2u);
    testFalse(dest[0].isucast);
    testTrue(dest[1].isucast);
    testEq(dest[0].dest.addr.port(), 1234u);
    testEq(dest[1].dest.addr.port(), 9876u);

    auto same(client::ContextImpl::buildSearchDest(conf, bcasts, false));
    testTrue(client::ContextImpl::searchDestEqual(dest, same));

    conf.addressList.pop_back();
    auto changed(client::ContextImpl::buildSearchDest(conf, bcasts, false));
    testFalse(client::ContextImpl::searchDestEqual(dest, changed));
}

void testServerBeaconDest()
{
    testShow()<<__func__;

    server::Config conf;
    conf.udp_port = 1234u;
    conf.auto_beacon = false;
    conf.beaconDestinations = {"1.2.3.4", "5.6.7.8:9876"};

    auto dest(server::Server::Pvt::buildBeaconDest(conf, conf.udp_port));

    testEq(dest.size(), 2u);
    testEq(dest[0].first.addr.port(), 1234u);
    testEq(dest[1].first.addr.port(), 9876u);
    testTrue(dest[0].second);

    auto same(server::Server::Pvt::buildBeaconDest(conf, conf.udp_port));
    testTrue(server::Server::Pvt::beaconDestEqual(dest, same));

    conf.beaconDestinations.pop_back();
    auto changed(server::Server::Pvt::buildBeaconDest(conf, conf.udp_port));
    testFalse(server::Server::Pvt::beaconDestEqual(dest, changed));
}

} // namespace

MAIN(testifacereconfig)
{
    testPlan(17);
    testSetup();
    testIfaceMapCurrentSame();
    testClientSearchDest();
    testServerBeaconDest();
    cleanup_for_valgrind();
    return testDone();
}
