/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <epicsUnitTest.h>

#include <envDefs.h>

#include <pvxs/unittest.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/log.h>

#if EPICS_VERSION_INT>=VERSION_INT(3,15,6,0) && EPICS_VERSION_INT<VERSION_INT(7,0,0,0)
#  define HAVE_ENV_UNSET
#elif EPICS_VERSION_INT>=VERSION_INT(7,0,2,0)
#  define HAVE_ENV_UNSET
#endif
using namespace pvxs;

namespace std {
ostream& operator<<(ostream& strm, const vector<string>& v)
{
    strm<<"[";
    bool first=true;
    for(auto& e : v) {
        if(first)
            first = false;
        else
            strm<<", ";
        strm<<'"'<<e<<'"';
    }
    strm<<"]";
    return strm;
}
}

namespace {

void testParse()
{
    testShow()<<__func__;

    epicsEnvSet("EPICS_PVA_ADDR_LIST", "  1.2.3.4  5.6.7.8:9876  ");
    epicsEnvSet("EPICS_PVA_AUTO_ADDR_LIST", "NO");
    epicsEnvSet("EPICS_PVA_BROADCAST_PORT", "1234");


    client::Config conf;
    try {
        conf = client::Config::fromEnv();
        testPass("client::Config::fromEnv()");
    }catch(std::exception& e){
        testFail("client::Config::fromEnv() %s : %s", typeid (e).name(), e.what());
    }

    if(testEq(conf.addressList.size(), 2u)) {
        testEq(conf.addressList[0], "1.2.3.4:1234");
        testEq(conf.addressList[1], "5.6.7.8:9876");
    }

#ifdef HAVE_ENV_UNSET
    epicsEnvUnset("EPICS_PVA_ADDR_LIST");
    epicsEnvUnset("EPICS_PVA_AUTO_ADDR_LIST");
    epicsEnvUnset("EPICS_PVA_BROADCAST_PORT");
#endif
}

void testDefs()
{
    testShow()<<__func__;

    {
        client::Config::defs_t defs;
        client::Config conf;

        conf.udp_port = 1234;
        conf.interfaces = {"1.2.3.4", "1.1.1.1"};
        conf.addressList = {"1.2.1.2", "4.3.2.1:1234"};
        conf.autoAddrList = false;
        conf.updateDefs(defs);
        testEq(defs["EPICS_PVA_BROADCAST_PORT"], "1234");
        testEq(defs["EPICS_PVA_AUTO_ADDR_LIST"], "NO");
        testEq(defs["EPICS_PVA_ADDR_LIST"], "1.2.1.2 4.3.2.1:1234");
        testEq(defs["EPICS_PVA_INTF_ADDR_LIST"], "1.2.3.4 1.1.1.1");
    }

    {
        client::Config::defs_t defs;
        client::Config conf;

        defs["EPICS_PVA_BROADCAST_PORT"] = "1234";
        defs["EPICS_PVA_AUTO_ADDR_LIST"] = "NO";
        defs["EPICS_PVA_ADDR_LIST"] = "1.2.1.2 4.3.2.1:1234";
        defs["EPICS_PVA_INTF_ADDR_LIST"] = "1.2.3.4 1.1.1.1";
        conf.applyDefs(defs);
        testEq(conf.udp_port, 1234);
        testFalse(conf.autoAddrList);
        testEq(conf.addressList, std::vector<std::string>({"1.2.1.2:1234", "4.3.2.1:1234"}));
        testEq(conf.interfaces, std::vector<std::string>({"1.1.1.1", "1.2.3.4"}));
    }

    {
        server::Config::defs_t defs;
        server::Config conf;

        conf.udp_port = 1234;
        conf.tcp_port = 5678;
        conf.interfaces = {"1.2.3.4", "1.1.1.1"};
        conf.beaconDestinations = {"1.2.1.2", "4.3.2.1:1234"};
        conf.auto_beacon = false;

        conf.updateDefs(defs);
        testEq(defs["EPICS_PVA_BROADCAST_PORT"], "1234");
        testEq(defs["EPICS_PVAS_BROADCAST_PORT"], "1234");
        testEq(defs["EPICS_PVA_SERVER_PORT"], "5678");
        testEq(defs["EPICS_PVAS_SERVER_PORT"], "5678");
        testEq(defs["EPICS_PVA_AUTO_ADDR_LIST"], "NO");
        testEq(defs["EPICS_PVAS_AUTO_BEACON_ADDR_LIST"], "NO");
        testEq(defs["EPICS_PVA_ADDR_LIST"], "1.2.1.2 4.3.2.1:1234");
        testEq(defs["EPICS_PVAS_BEACON_ADDR_LIST"], "1.2.1.2 4.3.2.1:1234");
        testEq(defs["EPICS_PVA_INTF_ADDR_LIST"], "1.2.3.4 1.1.1.1");
        testEq(defs["EPICS_PVAS_INTF_ADDR_LIST"], "1.2.3.4 1.1.1.1");
    }

    {
        server::Config::defs_t defs;
        server::Config conf;

        defs["EPICS_PVAS_BROADCAST_PORT"] = "1234";
        defs["EPICS_PVAS_SERVER_PORT"] = "5678";
        defs["EPICS_PVAS_AUTO_BEACON_ADDR_LIST"] = "NO";
        defs["EPICS_PVAS_BEACON_ADDR_LIST"] = "1.2.1.2 4.3.2.1:1234";
        defs["EPICS_PVAS_INTF_ADDR_LIST"] = "1.2.3.4 1.1.1.1";
        conf.applyDefs(defs);
        testEq(conf.udp_port, 1234);
        testEq(conf.tcp_port, 5678);
        testFalse(conf.auto_beacon);
        testEq(conf.beaconDestinations, std::vector<std::string>({"1.2.1.2:1234", "4.3.2.1:1234"}));
        testEq(conf.interfaces, std::vector<std::string>({"1.1.1.1:5678", "1.2.3.4:5678"}));
    }
}

void testServerAuto()
{
    testShow()<<__func__;

    /* We assume that the test host has at least
     * one interface other than localhost configured.
     * It need not be usable (eg. due to firewall).
     */
    server::Config conf;
    conf.expand();

    testFalse(conf.interfaces.empty())<<conf.interfaces;
    testFalse(conf.beaconDestinations.empty())<<conf.beaconDestinations;
}

void testClientAuto()
{
    testShow()<<__func__;

    /* We assume that the test host has at least
     * one interface other than localhost configured.
     * It need not be usable (eg. due to firewall).
     */
    client::Config conf;
    conf.expand();

    testFalse(conf.interfaces.empty())<<conf.interfaces;
    testFalse(conf.addressList.empty())<<conf.addressList;
}

} // namespace

MAIN(testconfig)
{
    testPlan(31);
    testSetup();
    testDefs();
    logger_config_env();
    testParse();
    testServerAuto();
    testClientAuto();
    cleanup_for_valgrind();
    return testDone();
}
