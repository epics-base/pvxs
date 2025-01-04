/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <sstream>

#include <epicsUnitTest.h>
#include <string.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/unittest.h>

#include "certstatusmanager.h"
#include "testcerts.h"
#include "utilpvt.h"

using namespace pvxs;

namespace {

/**
 * @brief WhoAmI is a server::Source that returns the credentials of the peer
 *
 * This is used to test the client and server credentials.
 */
struct WhoAmI final : public server::Source {
    const Value resultType;

    WhoAmI() : resultType(nt::NTScalar(TypeCode::String).create()) {}

    virtual void onSearch(Search& op) override final {
        for (auto& pv : op) {
            if (strcmp(pv.name(), WHO_AM_I_PV) == 0) pv.claim();
        }
    }

    virtual void onCreate(std::unique_ptr<server::ChannelControl>&& op) override final {
        if (op->name() != WHO_AM_I_PV) return;

        op->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
            cop->onGet([this](std::unique_ptr<server::ExecOp>&& eop) {
                auto cred(eop->credentials());
                std::ostringstream strm;
                strm << cred->method << '/' << cred->account;

                eop->reply(resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str()));
            });

            cop->connect(resultType);
        });

        std::shared_ptr<server::MonitorControlOp> sub;
        op->onSubscribe([this, sub](std::unique_ptr<server::MonitorSetupOp>&& sop) mutable {
            sub = sop->connect(resultType);
            auto cred(sub->credentials());
            std::ostringstream strm;
            strm << cred->method << '/' << cred->account;

            sub->post(resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str()));
        });
    }
};

/**
 * @brief pop is a helper function that pops a value from a subscription
 *
 * This is used to test the client and server protocol messages and subscriptions.
 */
Value pop(const std::shared_ptr<client::Subscription>& sub, epicsEvent& evt) {
    while (true) {
        if (auto ret = sub->pop()) {
            return ret;

        } else if (!evt.wait(5.0)) {
            testFail("timeout waiting for event");
            return Value();
        }
    }
}

/**
 * @brief clearMonitoredFiles is a helper function that clears the monitored cert files
 *
 * For testing changes to cert files that are referenced by server or client configurations.
 * The test will verify that when the cert files are changed, the server or client will be reconfigured
 * and the changes will take effect.
 *
 * This function is used to clear the cert files, triggering the reconfiguration.
 */
void clearMonitoredFiles() {
    // remove any file monitoring cert files that are left over from other tests
    std::remove(SUPER_SERVER2_CERT_FILE);
    std::remove(CLIENT3_CERT_FILE);
}

/**
 * @brief addMonitoredCertFiles is a helper function that adds the cert files to be monitored
 *
 * For testing changes to cert files that are referenced by server or client configurations.
 * The test will verify that when the cert files are changed, the server or client will be reconfigured
 * and the changes will take effect.
 *
 * This function is used to add the cert files, triggering the reconfiguration.
 */
void addMonitoredCertFiles() {
    std::ifstream serv_src(SUPER_SERVER_CERT_FILE, std::ios::binary);
    std::ofstream serv_dst(SUPER_SERVER2_CERT_FILE, std::ios::binary);
    serv_dst << serv_src.rdbuf();

    std::ifstream cli_src(CLIENT1_CERT_FILE, std::ios::binary);
    std::ofstream cli_dst(CLIENT3_CERT_FILE, std::ios::binary);
    cli_dst << cli_src.rdbuf();
}

/**
 * @brief testLegacyMode is a test that verifies the legacy mode of the client and server still works
 *
 */
void testLegacyMode() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testClientBackwardsCompatibility is a test that verifies the client backwards compatibility
 *
 * This is used to verify that a updated server can connect to a legacy client without any modifications.
 */
void testClientBackwardsCompatibility() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SUPER_SERVER_CERT_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testServerBackwardsCompatibility is a test that verifies the server backwards compatibility
 *
 * This is used to verify that a updated client can connect to a legacy server without any modifications.
 */
void testServerBackwardsCompatibility() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testGetSuper is a test that verifies the client can connect to the server using a standard cert file
 *
 * This is used to verify that the client can connect to the server using a standard cert file on a TLS connection.
 */
void testGetSuper() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SUPER_SERVER_CERT_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testGetIntermediate is a test that verifies the client can connect to the server that has an cert file that has intermediate certs in its chain
 *
 * This is used to verify that the client can connect to the server using an intermediate cert file on a TLS connection.
 */
void testGetIntermediate() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SERVER1_CERT_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

void testGetNameServer() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SERVER1_CERT_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

    for (auto& addr : cli_conf.addressList) cli_conf.nameServers.push_back(SB() << "pvas://" << addr /*<<':'<<cli_conf.tls_port*/);
    cli_conf.autoAddrList = false;
    cli_conf.addressList.clear();

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
}

/**
 * @brief testClientReconfig is a test that verifies the client can be reconfigured on the fly
 *
 * This is used to verify that the client can be reconfigured and the changes will take effect.
 * Existing connections will be disconnected and new connections will use the new configuration.
 * If going from a TLS connection to a non-TLS configuration, then TLS connections will be disconnected.
 * If going from a non-TLS connection to a TLS configuration, then non-TLS connections will be disconnected.
 */
void testClientReconfig() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = "ioc1.p12";

    auto serv(serv_conf.build().addSource("whoami", std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor("whoami").maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());
    Value update;

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, "x509");
        testEq(e.cred->account, "ioc1");
    }
    testDiag("Connect");

    update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), "x509/client1");

    cli_conf = cli.config();
    cli_conf.tls_cert_filename = "client2.p12";
    cli_conf.tls_cert_password = "oraclesucks";
    testDiag("cli.reconfigure()");
    cli.reconfigure(cli_conf);

    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });
    testDiag("Disconnect");

    try {
        (void)pop(sub, evt);
        testFail("Missing expected Connected");
    } catch (client::Connected& e) {
        testOk1(e.cred && e.cred->isTLS);
    } catch (...) {
        testFail("Unexpected exception instead of Connected");
    }
    testDiag("Reconnect");

    update = pop(sub, evt);
    if (update.valid()) testEq(update[TEST_PV_FIELD].as<std::string>(), "x509/client2");
}

/**
 * @brief testServerReconfig is a test that verifies the server can be reconfigured on the fly
 *
 * This is used to verify that the server can be reconfigured and the changes will take effect.
 * Existing connections will be disconnected and new connections will use the new configuration.
 * If going from a TLS connection to a non-TLS configuration, then TLS connections will be disconnected.
 * If going from a non-TLS connection to a TLS configuration, then non-TLS connections will be disconnected.
 */
void testServerReconfig() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SERVER1_CERT_FILE;

    auto serv(serv_conf.build().addSource("whoami", std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = "ioc1.p12";

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor("whoami").maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());
    Value update;

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, "x509");
        testEq(e.cred->account, "server1");
    }
    testDiag("Connect");

    update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), "x509/ioc1");

    serv_conf = serv.config();
    serv_conf.tls_cert_filename = "ioc1.p12";
    testDiag("serv.reconfigure()");
    serv.reconfigure(serv_conf);

    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });
    testDiag("Disconnect");

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, "x509");
        testEq(e.cred->account, "ioc1");
    }
    testDiag("Reconnect");

    update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), "x509/ioc1");
}

/**
 * @brief testServerFileMonitoring is a test that verifies changes to server cert files
 *
 * This is used to verify that changes to server cert files will be detected and the server will be reconfigured.
 * Existing connections will not disconnected but new connections will use the new configuration.
 * The test will :
 * - configer the server with a non-existent cert file
 * - connect to the server and verify the connection is successful but is not TLS
 * - add the cert file that is referenced by the server configuration
 * - verify the server is reconfigured and the connection is successful and is TLS
 * - remove the cert file from being monitored
 * - verify the server is reconfigured and the connection is successful and is not TLS
 *
 * @note that the checkFileStatus() function is used to trigger the reconfiguration
 * rather than waiting for the file monitor to notice the change and trigger the reconfiguration.
 */
void testServerFileMonitoring() {
    testShow() << __func__;

    clearMonitoredFiles();
    testDiag("Server Configured without cert file");

    // Initial test setup
    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Setup the server with a non-existent cert file
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SUPER_SERVER2_CERT_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    auto cli_conf(serv.clientConfig());
    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // Connect to the server and verify the connection is successful but is not TLS
    {
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;
        auto cli(cli_conf.build());
        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());
        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        conn.reset();
    }

    // Add the cert file that is referenced by the server configuration
    addMonitoredCertFiles();
    serv.checkFileStatus();
    testDiag("Server Reconfigured with cert file");

    // Verify the server is reconfigured and the connection is successful and is TLS
    {
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;
        auto cli(cli_conf.build());
        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());
        auto reply(cli.get(TEST_PV).exec()->wait(50.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        conn.reset();
    }

    // Remove the cert file from being monitored
    clearMonitoredFiles();
    serv.checkFileStatus();
    testDiag("Server Reconfigured without cert file");

    // Verify the server is reconfigured and the connection is successful and is not TLS
    {
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;
        auto cli(cli_conf.build());
        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());
        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        conn.reset();
    }
}

/**
 * @brief testClientFileMonitoring is a test that verifies changes to client cert files will be detected and the client will be reconfigured.
 *
 * This is used to verify that changes to client cert files will be detected and the client will be reconfigured.
 * Existing connections will be disconnected and new connections will use the new configuration.
 * The test will :
 * - configure the client with a non-existent cert file
 * - monitor PV on the server and verify the connection is successful but is not TLS
 * - add the cert file that is referenced by the client configuration
 * - verify the client connection is reconfigured, the existing connection dropped, and the new connection is successful and is TLS
 * - remove the cert file from being monitored
 * - verify the client connection is reconfigured, the existing connection dropped, and the new connection is successful and is not TLS
 *
 * @note that the checkFileStatus() function is used to trigger the reconfiguration
 * rather than waiting for the file monitor to notice the change and trigger the reconfiguration.
 */
void testClientFileMonitoring() {
    testShow() << __func__;

    // Initial test setup
    clearMonitoredFiles();

    // Setup the server with a cert file
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_cert_filename = SUPER_SERVER_CERT_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    // Setup the client with a non-existent cert file
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_cert_filename = CLIENT3_CERT_FILE;
    testDiag("Client configured without cert file");

    auto cli(cli_conf.build());

    serv.start();

    // Start monitoring the PV on the server and verify the connection is successful but is not TLS
    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());
    Value update;

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(!e.cred->isTLS);
        testEq(e.cred->method, "anonymous");
        testEq(e.cred->account, "");
    }

    // Verify that the updated value triggers an update of the subscription
    update = pop(sub, evt);
    if (update.valid()) testEq(update[TEST_PV_FIELD].as<std::string>().find("ca/"), 0);

    addMonitoredCertFiles();
    cli.checkFileStatus();
    testDiag("Client reconfigured with cert file");

    // Verify that the existing connection is disconnected and the new connection is successful and is TLS
    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });

    try {
        (void)pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testOk1(e.cred && e.cred->isTLS);
        testEq(e.cred->method, "x509");
        testEq(e.cred->account, "superserver1");
    } catch (...) {
        testFail("Unexpected exception instead of Connected");
        testSkip(2, "oops");
    }

    // Verify that the updated value triggers an update of the subscription
    update = pop(sub, evt);
    if (update.valid()) testEq(update[TEST_PV_FIELD].as<std::string>(), "x509/client1");

    // Remove the cert file referenced by the client configuration
    clearMonitoredFiles();
    cli.checkFileStatus();
    testDiag("Client reconfigured without cert file again");

    // Verify that the existing connection is disconnected and the new connection is successful and is not TLS
    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });

    try {
        (void)pop(sub, evt);
        testFail("Missing expected Connected");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(!e.cred->isTLS);
        testEq(e.cred->method, "anonymous");
        testEq(e.cred->account, "");
    }

    // Verify that the updated value triggers an update of the subscription
    update = pop(sub, evt);
    if (update.valid()) testEq(update[TEST_PV_FIELD].as<std::string>().find("ca/"), 0);
}

}  // namespace

MAIN(testtls) {
    testPlan(48);
    testSetup();
    logger_config_env();
    testLegacyMode();
    testClientBackwardsCompatibility();
    testServerBackwardsCompatibility();
    testGetSuper();
    testGetIntermediate();
    testGetNameServer();
    testClientReconfig();
    testServerReconfig();
    testServerFileMonitoring();
    testClientFileMonitoring();
    cleanup_for_valgrind();
    return testDone();
}
