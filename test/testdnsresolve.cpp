/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>
#include <epicsUnitTest.h>
#include <envDefs.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>

#include <utilpvt.h>

using namespace pvxs;

namespace {

void test_isHostname()
{
    testDiag("%s", __func__);

    testTrue(isHostname("localhost"));
    testTrue(isHostname("myhost.example.com"));
    testTrue(isHostname("myhost:5075"));
    testTrue(!isHostname("127.0.0.1"));
    testTrue(!isHostname("127.0.0.1:5075"));
    testTrue(!isHostname("::1"));
    testTrue(!isHostname("[::1]:5075"));
}

void test_config_hostname_preservation()
{
    testDiag("%s", __func__);

    client::Config conf;
    conf.udp_port = 5076;
    conf.tcp_port = 5075;

    epicsEnvSet("EPICS_PVA_NAME_SERVERS", "localhost:5075");
    epicsEnvSet("EPICS_PVA_ADDR_LIST", "");
    epicsEnvSet("EPICS_PVA_AUTO_ADDR_LIST", "NO");

    conf.applyEnv();

    testOk(conf.nameServers.size() == 1, "nameServers has one entry");
    testOk(conf.nameServerHostnames.size() == 1, "nameServerHostnames has one entry");

    if(!conf.nameServerHostnames.empty()) {
        auto it = conf.nameServerHostnames.begin();
        testOk(it->second == "localhost:5075",
               "hostname preserved: '%s'", it->second.c_str());
    } else {
        testSkip(1, "no hostname entries");
    }
}

void test_config_ip_no_hostname()
{
    testDiag("%s", __func__);

    client::Config conf;
    epicsEnvSet("EPICS_PVA_NAME_SERVERS", "127.0.0.1:5075");
    epicsEnvSet("EPICS_PVA_ADDR_LIST", "");
    epicsEnvSet("EPICS_PVA_AUTO_ADDR_LIST", "NO");

    conf.applyEnv();

    testOk(conf.nameServerHostnames.empty(),
           "no hostname stored for bare IP (size=%zu)", conf.nameServerHostnames.size());
}

} // namespace

MAIN(testdnsresolve)
{
    SockAttach attach;
    testPlan(11);
    testSetup();
    test_isHostname();
    test_config_hostname_preservation();
    test_config_ip_no_hostname();
    cleanup_for_valgrind();
    return testDone();
}
