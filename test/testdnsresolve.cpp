/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdlib>

#include <testMain.h>
#include <epicsUnitTest.h>
#include <envDefs.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>

#include <utilpvt.h>

using namespace pvxs;

namespace {

// epicsEnvUnset() is not available on older EPICS base (e.g. 3.14)
void unsetEnv(const char *name)
{
#ifdef _WIN32
    _putenv((std::string(name)+"=").c_str());
#else
    unsetenv(name);
#endif
}

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

void test_config_hostname_no_port_defaults_tcp_port()
{
    testDiag("%s", __func__);

    client::Config conf;
    conf.udp_port = 5076;
    conf.tcp_port = 0;

    unsetEnv("EPICS_PVA_SERVER_PORT");
    epicsEnvSet("EPICS_PVA_NAME_SERVERS", "localhost");
    epicsEnvSet("EPICS_PVA_ADDR_LIST", "");
    epicsEnvSet("EPICS_PVA_AUTO_ADDR_LIST", "NO");

    conf.applyEnv();

    testOk(conf.tcp_port == 5075, "tcp_port defaulted to 5075 (got %u)", conf.tcp_port);

    testOk(conf.nameServers.size() == 1, "nameServers has one entry");
    if(!conf.nameServers.empty()) {
        auto& ep = conf.nameServers[0];
        testOk(ep.find(":0") == std::string::npos,
               "resolved nameserver endpoint doesn't carry port 0 ('%s')", ep.c_str());
    } else {
        testSkip(1, "no nameServers entries");
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
    testPlan(14);
    testSetup();
    test_isHostname();
    test_config_hostname_preservation();
    test_config_hostname_no_port_defaults_tcp_port();
    test_config_ip_no_hostname();
    cleanup_for_valgrind();
    return testDone();
}
