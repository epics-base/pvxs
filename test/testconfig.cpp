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

using namespace pvxs;

namespace {

void testParse()
{
    epicsEnvSet("EPICS_PVA_ADDR_LIST", "1.2.3.4");
    epicsEnvSet("EPICS_PVA_AUTO_ADDR_LIST", "NO");
    epicsEnvSet("EPICS_PVA_BROADCAST_PORT", "1234");


    client::Config conf;
    try {
        conf = client::Config::from_env();
        testPass("client::Config::from_env()");
    }catch(std::exception& e){
        testFail("client::Config::from_env() %s : %s", typeid (e).name(), e.what());
    }

    testOk(!conf.addressList.empty() && conf.addressList[0]=="1.2.3.4:1234",
            "addressList[0] = \"%s\" == \"1.2.3.4:1234\"", conf.addressList[0].c_str());

    epicsEnvUnset("EPICS_PVA_ADDR_LIST");
    epicsEnvUnset("EPICS_PVA_AUTO_ADDR_LIST");
    epicsEnvUnset("EPICS_PVA_BROADCAST_PORT");
}

}

MAIN(testconfig)
{
    testPlan(2);
    logger_config_env();
    testParse();
    cleanup_for_valgrind();
    return testDone();
}
