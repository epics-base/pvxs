/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <cstring>
#include <sstream>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/unittest.h>

#include "certcontext.h"
#include "certstatus.h"
#include "utilpvt.h"

using namespace pvxs;

namespace {

/**
 * @brief WhoAmI is a server::Source that returns the credentials of the peer
 *
 * This is used to test the client and server credentials.
 */
struct WhoAmI final : server::Source {
    const Value resultType;

    WhoAmI() : resultType(nt::NTScalar(TypeCode::String).create()) {}

    void onSearch(Search& op) override {
        for (auto& pv : op) {
            if (strcmp(pv.name(), WHO_AM_I_PV) == 0) pv.claim();
        }
    }

    void onCreate(std::unique_ptr<server::ChannelControl>&& op) override {
        if (op->name() != WHO_AM_I_PV) return;

        op->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
            cop->onGet([this](std::unique_ptr<server::ExecOp>&& eop) {
                const auto cred(eop->credentials());
                std::ostringstream strm;
                strm << cred->method << '/' << cred->account;

                eop->reply(resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str()));
            });

            cop->connect(resultType);
        });

        std::shared_ptr<server::MonitorControlOp> sub;
        op->onSubscribe([this, sub](std::unique_ptr<server::MonitorSetupOp>&& sop) mutable {
            sub = sop->connect(resultType);
            const auto cred(sub->credentials());
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
        if (auto ret = sub->pop()) return ret;
        if (!evt.wait(5.0)) {
            testFail("timeout waiting for event");
            return {};
        }
    }
}

/**
 * @brief testLegacyMode is a test that verifies the legacy mode of the client and server still works
 *
 */
void testLegacyMode() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    const auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    const auto cli_conf(serv.clientConfig());

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
 * This is used to verify that an updated server can connect to a legacy client without any modifications.
 */
void testClientBackwardsCompatibility() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    const auto cli_conf(serv.clientConfig());

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
 * This is used to verify that an updated client can connect to a legacy server without any modifications.
 */
void testServerBackwardsCompatibility() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    const auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testServerOnly is a test that verifies the client can connect in server-only authenticated TLS mode
 *
 * This is used to verify that a client that is configured with a certificate authority certificate but no entity cert
 * will be able to connect in server-only authenticated TLS mode
 */
void testServerOnly() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) { is_tls = c.cred && c.cred->isTLS; }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testStrictServer is a test that verifies that strict servers allow only mutually authenticated TLS connections
 *
 * This is used to verify that a server that is configured to accept only TLS clients enforces that rule
 */
void testStrictServer() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
    serv_conf.tls_client_cert_required = ConfigCommon::Require;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto cli_conf(serv.clientConfig());

    {
        // Test without any client TLS configuration
        auto cli(cli_conf.build());

        auto is_tls{false};
        auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) { is_tls = c.cred && c.cred->isTLS; }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testTrue(!is_tls);
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    }

    try {
        // Test with server only TLS config
        cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;

        auto cli(cli_conf.build());

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) { testFail("Unexpected connection with server only setup"); }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testFail("Unexpected reply with server only setup");
    } catch (std::exception& e) {
        testTrue(std::string{e.what()} == "Timeout");
    }
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
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testGetIntermediate is a test that verifies the client can connect to the server that has a cert file that has intermediate certs in its chain
 *
 * This is used to verify that the client can connect to the server using an intermediate cert file on a TLS connection.
 */
void testGetIntermediate() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

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
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    for (auto& addr : cli_conf.addressList) cli_conf.nameServers.push_back(SB() << "pvas://" << addr /*<<':'<<cli_conf.tls_port*/);
    cli_conf.autoAddrList = false;
    cli_conf.addressList.clear();

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    try {
        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    } catch (std::exception&) {
        testFail("timeout waiting for event");
    }
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
    serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, TLS_METHOD_STRING);
        testEq(e.cred->account, CERT_CN_IOC1);
    }
    testDiag("Connect");

    Value update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);

    cli_conf = cli.config();
    cli_conf.tls_keychain_file = CLIENT2_KEYCHAIN_FILE;
    cli_conf.setKeychainPassword(CLIENT2_KEYCHAIN_FILE_PWD);
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
    if (update.valid()) testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT2);
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
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, TLS_METHOD_STRING);
        testEq(e.cred->account, CERT_CN_SERVER1);
    }
    testDiag("Connect");

    Value update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_IOC1);

    serv_conf = serv.config();
    serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;
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
        testEq(e.cred->method, TLS_METHOD_STRING);
        testEq(e.cred->account, CERT_CN_IOC1);
    }
    testDiag("Reconnect");

    update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_IOC1);
}

/**
 * @brief testMutualTLSWithMismatchedTrustRoot tests that mutual TLS fails
 * when the client's certificate is signed by a different root than the server trusts.
 *
 * This verifies that TLS handshake properly validates certificate chains
 * and rejects connections where trust anchors don't match.
 */
void testMutualTLSWithMismatchedTrustRoot() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses main root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client uses alternate root CA hierarchy (different trust anchor)
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = ALT_CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // Connection should fail because client's cert chain doesn't link to server's trust anchor
    try {
        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) {
            testFail("Unexpected successful connection with mismatched trust roots");
        }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testFail("Unexpected reply received - connection should have failed");
    } catch (std::exception& e) {
        // Expected: connection timeout or authentication failure
        auto msg = std::string{e.what()};
        bool expected = (msg == "Timeout") ||
                       (msg.find("SSL") != std::string::npos) ||
                       (msg.find("auth") != std::string::npos) ||
                       (msg.find("certificate") != std::string::npos);
        testDiag("Expected error, got: %s", e.what());
        testTrue(expected);
    }
}

/**
 * @brief testServerOnlyAuthWithMismatchedTrustAnchor tests that server-only
 * TLS authentication fails when the client's trust anchor differs from the server's cert chain.
 *
 * In server-only auth, the client trusts the server based on the server's certificate chain.
 * If the client's trust anchor doesn't include the server's root, the handshake fails.
 */
void testServerOnlyAuthWithMismatchedTrustAnchor() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses alternate root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = ALT_SERVER1_KEYCHAIN_FILE;
    testDiag("Server using: %s", ALT_SERVER1_KEYCHAIN_FILE);

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client uses main root CA as trust anchor only (server-only auth, no entity cert)
    // cert_authcert.p12 contains the main root CA certificate only
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;
    testDiag("Client using: %s (trust anchor only, no entity cert)", CERT_AUTH_CERT_FILE);

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // Connection should fail because client's trust anchor (main root) doesn't match
    // server's certificate chain (alt root) - client can't verify server
    bool connection_succeeded = false;
    bool got_callback = false;

    try {
        auto conn(cli.connect(TEST_PV).onConnect([&connection_succeeded, &got_callback](const client::Connected& c) {
            got_callback = true;
            connection_succeeded = c.cred && c.cred->isTLS;
            if (connection_succeeded) {
                testDiag("UNEXPECTED: Connection succeeded with TLS=%s, method=%s, account=%s",
                         c.cred->isTLS ? "true" : "false",
                         c.cred->method.c_str(),
                         c.cred->account.c_str());
            }
        }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testDiag("UNEXPECTED: Reply received with value=%d", reply[TEST_PV_FIELD].as<int32_t>());
        testFail("Unexpected reply received - connection should have failed");
    } catch (std::exception& e) {
        testDiag("Caught exception: %s", e.what());
        if (!got_callback) {
            testPass("Connection failed before onConnect callback (expected)");
        } else if (!connection_succeeded) {
            testPass("Connection succeeded but without TLS (unexpected but non-TLS connection)");
        } else {
            testFail("Connection succeeded with TLS when it should have failed");
        }
    }
}

/**
 * @brief testServerOnlyAuthWithMatchingTrustAnchor is a positive test that
 * server-only TLS authentication succeeds when trust anchors match.
 */
void testServerOnlyAuthWithMatchingTrustAnchor() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client has only trust anchor (main root), no entity cert (server-only auth)
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testMutualTLSWithMatchingTrustAnchors is a positive test that
 * mutual TLS succeeds when both client and server use matching trust anchors.
 */
void testMutualTLSWithMatchingTrustAnchors() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses alternate root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = ALT_SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client also uses alternate root CA hierarchy (matching trust anchor)
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = ALT_CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testClientWithMismatchedChainFallback tests that when a client's p12 file
 * contains an entity certificate that doesn't chain to the trust anchor in the p12,
 * TLS is disabled and connections fall back to TCP.
 *
 * This is expected behavior: if the entity cert can't be verified against the trust store
 * built from the p12's CA certificates, the client can't use mutual TLS and falls back to TCP.
 *
 * The p12 file contains:
 * - Entity cert: alt_client1 (signed by alt_root via alt_intermediate)
 * - Trust store: main_root (NOT alt_root)
 *
 * Since alt_client1 doesn't chain to main_root, the client detects this mismatch and
 * disables TLS, falling back to TCP-only mode.
 */
void testClientWithMismatchedChainFallback() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses main root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client has entity cert (alt_client1) that doesn't chain to trust anchor (main_root)
    // This should cause the client to fall back to TCP mode
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = ALT_CLIENT1_WITH_MAIN_ROOT_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // The client should detect that its entity cert doesn't chain to the trust store
    // and disable TLS, falling back to TCP mode
    bool is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
        testDiag("Connection established with TLS=%s, method=%s, account=%s",
                  c.cred && c.cred->isTLS ? "true" : "false",
                  c.cred ? c.cred->method.c_str() : "none",
                  c.cred ? c.cred->account.c_str() : "none");
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));

    // Expected: TCP-only connection (TLS disabled due to chain mismatch)
    testDiag("Expected: TCP-only connection (TLS disabled due to chain mismatch)");
    testTrue(!is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testFakeCertificateNameMatchingAttack tests that TLS authentication
 * is based on cryptographic verification, not just CN name matching.
 *
 * This test creates fake certificates with the SAME CNs as the real certificates
 * but signed by different (fake) Certificate Authorities. The test verifies that:
 * - Having the same CN is NOT sufficient for authentication
 * - The certificate must chain cryptographically to a trusted root
 * - Fake CAs that share CNs with real CAs are NOT trusted
 *
 * Test scenarios (all combinations of real/fake server and client certs):
 * 1. Real server + Real client → TLS succeeds (baseline)
 * 2. Fake server + Real client → TLS fails (fake server not trusted by real CA)
 * 3. Real server + Fake client → TLS fails (fake client not trusted by real CA)
 * 4. Fake server + Fake client → TLS succeeds (both share the same fake CA)
 *    This is expected - they authenticate each other, but this is NOT secure
 *    because neither chain traces back to a REAL trusted root.
 */
void testFakeCertificateNameMatchingAttack() {
    // Test 1: Real server + Real client (baseline - should succeed)
    {
        testShow() << __func__ << ": === Test 1: Real server + Real client (baseline) ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        bool is_tls{false};
        auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
            is_tls = c.cred && c.cred->isTLS;
        }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testTrue(is_tls);
        testDiag("Real server + Real client: TLS should succeed");
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        conn.reset();
    }

    // Test 2: Fake server + Real client (should FAIL - fake server not trusted)
    {
        testShow() << __func__ << ":=== Test 2: Fake server + Real client ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = FAKE_SUPERSERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        try {
            auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) {
                // Should not reach here
            }).exec());

            auto reply(cli.get(TEST_PV).exec()->wait(3.0));
            testFail("Fake server + Real client: Connection should have failed");
        } catch (std::exception& e) {
            testPass("Fake server + Real client: TLS correctly rejected fake server");
        }
    }

    // Test 3: Real server + Fake client (should FAIL - fake client not trusted)
    {
        testShow() << __func__ << ": === Test 3: Real server + Fake client ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = FAKE_CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        try {
            auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) {
                // Should not reach here
            }).exec());

            auto reply(cli.get(TEST_PV).exec()->wait(3.0));
            testFail("Real server + Fake client: Connection should have failed");
        } catch (std::exception& e) {
            testPass("Real server + Fake client: TLS correctly rejected fake client");
        }
    }

    // Test 4: Fake server + Fake client (both share same fake CA - succeeds but insecure!)
    {
        testShow() << __func__ << ": === Test 4: Fake server + Fake client ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = FAKE_SUPERSERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = FAKE_CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        bool is_tls{false};
        try {
            auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
                is_tls = c.cred && c.cred->isTLS;
            }).exec());

            auto reply(cli.get(TEST_PV).exec()->wait(5.0));
            testTrue(is_tls);
            testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
            conn.reset();
            testDiag("Fake+Fake: Connection succeeded (expected - both share fake CA)");
        } catch (std::exception& e) {
            testFail("Fake server + Fake client: Should have succeeded (both share fake CA)");
        }
    }
}

}  // namespace

MAIN(testtls) {
    testPlan(47);
    testSetup();
    logger_config_env();
    testLegacyMode();
    testClientBackwardsCompatibility();
    testServerBackwardsCompatibility();
    testServerOnly();
    testStrictServer();
    testGetSuper();
    testGetIntermediate();
    testGetNameServer();
    testClientReconfig();
    testServerReconfig();
    testMutualTLSWithMismatchedTrustRoot();
    testServerOnlyAuthWithMismatchedTrustAnchor();
    testServerOnlyAuthWithMatchingTrustAnchor();
    testMutualTLSWithMatchingTrustAnchors();
    testClientWithMismatchedChainFallback();
    testFakeCertificateNameMatchingAttack();
    cleanup_for_valgrind();
    return testDone();
}
