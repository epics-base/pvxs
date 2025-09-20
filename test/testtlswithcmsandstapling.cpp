/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <atomic>
#include <iostream>
#include <sstream>
#include <string>

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
#include "certfactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "configcms.h"
#include "openssl.h"
#include "opensslgbl.h"
#include "serverev.h"
#include "utilpvt.h"
#include "wildcardpv.h"

/**
 * @brief This tester uses a Tester object and a bunch of MACROS that rely on a very opinionated
 * set of named variables to function.  prefixes `cert_auth`, `super_server`, `intermediate_server`,
 * `server1`, `server2`, `ioc`, `client1`, and `client2` refer to the certificates generated
 * by `gen_test_certs`.  `cert_auth` is used for the Certificate Authority and `super_server` is used
 * for the Mock PVACMS.
 *
 * `gen_test_certs` has been modified to generate the cert authority cert and the Mock PVACMS cert without
 * status extensions for obvious reasons.
 *
 * The tests initially follow the exact same sequence as those in the `testtls` suite and then try out some
 * edge conditions such as requesting stapling but none being provided.
 *
 */
using namespace pvxs;
using namespace pvxs::certs;

namespace {

/**
 * @class Tester
 * @brief A class used for testing tls while stapling certificate status from a Mock PVACMS server.
 */
struct Tester {
    const CertDate now;
    const CertDate status_valid_until_time;
    const CertDate revocation_date;

    const Value status_value_prototype{CertStatus::getStatusPrototype()};
    CertCtx<tag::cert_auth> cert_auth;
    CertCtx<tag::super_server> super_server;
    CertCtx<tag::intermediate_server> intermediate_server;
    CertCtx<tag::server1> server1;
    CertCtx<tag::server2> server2;
    CertCtx<tag::ioc> ioc;
    CertCtx<tag::client1> client1;
    CertCtx<tag::client2> client2;

    const std::string issuer_id{CertStatus::getSkId(cert_auth.cert.cert)};

    server::WildcardPV status_pv{server::WildcardPV::buildMailbox()};
    server::Config server_config;
    server::ServerEv pvacms;
    client::Context client;
    CounterMap cert_status_request_counters;
    epicsMutex counter_lock;

    Tester()
        : now(time(nullptr)),
          status_valid_until_time(now.t + STATUS_VALID_FOR_SECS),
          revocation_date(now.t - REVOKED_SINCE_SECS)

    {
        // Set up the Mock PVACMS server certificate (does not contain custom status extension)
        auto wildcard_source = server::WildcardSource::build();
        wildcard_source->add(getCertStatusPv("CERT", issuer_id), status_pv);
        // Set up a mock source that counts requests
        const auto pvacms_mock   = std::make_shared<server::MockSource>(wildcard_source, [this] (std::string const& pv_name) {
            if (cert_status_request_counters.find(pv_name) == cert_status_request_counters.end()) {
                cert_status_request_counters[pv_name] = std::make_shared<std::atomic<uint32_t>>(0);
            }
            cert_status_request_counters[pv_name]->fetch_add(1);

        });

        auto pvacms_config = ConfigCms::mockCms();
        pvacms_config.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
        pvacms = pvacms_config.build().addSource("__wildcard", pvacms_mock);
        server_config = pvacms.config();
        server_config.tls_port+=2; // optional avoid clash with PVACMS
        server_config.tcp_port+=4;
        client = pvacms.clientConfig().build();

        if (!cert_auth.cert.cert || !cert_auth.cert.pkey || !super_server.cert.cert || !super_server.cert.pkey || !intermediate_server.cert.cert || !intermediate_server.cert.pkey ||
            !server1.cert.cert || !server1.cert.pkey || !server2.cert.cert || !server2.cert.pkey || !ioc.cert.cert || !ioc.cert.pkey ||
            !client1.cert.cert || !client1.cert.pkey || !client2.cert.cert || !client2.cert.pkey) {
            testFail("Error loading one or more certificates");
            return;
        }
        testShow() << "Loaded all test certs\n";
    }

    ~Tester() = default;

    /**
     * @brief Creates certificate statuses.
     *
     * This function generates mock statuses to be returned by the Mock CMS server.
     * These statuses are replete with valid OCSP responses that are valid for `STATUS_VALID_FOR_MINS` minutes
     */
    void createCertStatuses() { // NOLINT(*-convert-member-functions-to-static)
        testShow() << __func__;
        try {
            const auto cert_status_creator(CertStatusFactory(cert_auth.cert.cert, cert_auth.cert.pkey, cert_auth.cert.chain, 0, STATUS_VALID_FOR_SECS));
            createCertStatus(cert_auth, {VALID},cert_status_creator, now,{});
            createCertStatus(intermediate_server, {VALID},cert_status_creator, now,{});
            createCertStatus(server1, {VALID},cert_status_creator, now,{});
            createCertStatus(server2, {VALID},cert_status_creator, now,{});
            createCertStatus(ioc, {VALID},cert_status_creator, now,{});
            createCertStatus(client1, {VALID},cert_status_creator, now,{});
            createCertStatus(client2, {VALID},cert_status_creator, now,{});
        } catch (std::exception& e) {
            testFail("Failed to read certificate in from file: %s\n", e.what());
        }
    }

    /**
     * @brief Make PVAccess Certificate Status Responses for each of the certificates
     */
    void makeStatusResponses() { // NOLINT(*-convert-member-functions-to-static)
        testShow() << __func__;
        const auto cert_status_creator(CertStatusFactory(cert_auth.cert.cert, cert_auth.cert.pkey, cert_auth.cert.chain, 0, STATUS_VALID_FOR_SECS));

        makeStatusResponse(cert_auth,cert_status_creator,now,revocation_date);
        makeStatusResponse(intermediate_server,cert_status_creator,now,revocation_date);
        makeStatusResponse(server1,cert_status_creator,now,revocation_date);
        makeStatusResponse(server2,cert_status_creator,now,revocation_date);
        makeStatusResponse(ioc,cert_status_creator,now,revocation_date);
        makeStatusResponse(client1,cert_status_creator,now,revocation_date);
        makeStatusResponse(client2,cert_status_creator,now,revocation_date);
    }

    /**
     * @brief Pop the next event off the subscribed PV's queue
     * @param sub the subscription
     * @param evt the EPICS event
     * @return the popped Value or empty on timeout
     */
    static Value pop(const std::shared_ptr<client::Subscription>& sub, epicsEvent& evt) {
        while (true) {
            if (auto ret = sub->pop()) return ret;
            if (!evt.wait(10.0)) {
                testFail("timeout waiting for event");
                return {};
            }
        }
    }

    /**
     * @brief Start the Mock PVACMS service
     *
     * Important; This server is implemented by using the standard WildcardPV so it
     * also tests this newly exposed feature.
     *
     * This essentially creates a server that will serve a `WildcardPV` that responds to
     * PVs  corresponding to the certificate status request pattern.  It will respond to only those PVs that were
     * generated by `gen_test_certs` anx only with the responses created in `createCertStatuses`
     * unless changed by putting values like 'APPROVED', 'DENIED', or 'REVOKED' to the 'state' field.
     *
     * During the setup tests are performed to verify that it works as expected
     *
     */
    void startMockCMS() { // NOLINT(*-convert-member-functions-to-static)
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Mock PVACMS Server");

            status_pv.onFirstConnect([this](server::WildcardPV& pv, const std::string& pv_name, const std::list<std::string>& parameters) {
                auto it = parameters.begin();
                const std::string& serial_string = *it;
                serial_number_t serial = std::stoull(serial_string);

                if (
                    postValueCase(serial, pv, pv_name, cert_auth,true) ||
                    postValueCase(serial, pv, pv_name, intermediate_server,true) ||
                    postValueCase(serial, pv, pv_name, server1,true) ||
                    postValueCase(serial, pv, pv_name, server2,true) ||
                    postValueCase(serial, pv, pv_name, ioc,true) ||
                    postValueCase(serial, pv, pv_name, client1,true) ||
                    postValueCase(serial, pv, pv_name, client2,true)
                    )
                    ; // handled
                else
                    testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());
        });
            status_pv.onLastDisconnect([](server::WildcardPV& pv, const std::string& pv_name, const std::list<std::string>&) {
                testOk(1, "Closing Status Request Connection: %s", pv_name.c_str());
                pv.close(pv_name);
            });

            pvacms.start();
            testStatusRequest(cert_auth, client,cert_auth.cert.trusted_store.get());

            testDiag("Set up: %s", "Mock PVACMS Server");
        } catch (std::exception& e) {
            testFail("Failed to set up Mock PVACMS Server: %s", e.what());
        }
    }

    /**
     * @brief Stop the Mock PVACMS Server
     */
    void stopMockCMS() { // NOLINT(*-convert-member-functions-to-static)
        testShow() << __func__;
        try {
            testDiag("Stopping: %s", "Mock PVACMS Server");
            pvacms.stop();
        } catch (std::exception& e) {
            testFail("Failed to stop Mock PVACMS Server: %s", e.what());
        }
    }

    /**
     * @brief A Secure PVAccess Server that responds to the "whoami" PV.
     *
     * It will return the credentials that are added to the PVAccess operations
     * by the implemented TLS framework that are taken from the provided certificates.
     * This can be used to test whether the correct credentials and attributions are being
     * assigned.
     *
     * It pulls the `method` and `account` from the PVAccess operation (GET/PUT/MONITOR/RPC).
     * The values correspond to the following:
     *   `method`: 'ca' for `tcp` connections, and `x509` for `tls` connections
     *   `account`: the subject `CN` (common name) encoded in the certificate for `tls` connections,
     *              or "ca" or "anonymous" for `tcp` connections
     */
    struct WhoAmI final : server::Source {
        const Value resultType;

        WhoAmI() : resultType(nt::NTScalar(TypeCode::String).create()) {} // NOLINT(*-use-equals-default)

        void onSearch(Search& op) override {
            for (auto& pv : op) {
                if (strcmp(pv.name(), WHO_AM_I_PV) == 0) pv.claim();
            }
        }

        void onCreate(std::unique_ptr<server::ChannelControl>&& op) override {
            if (op->name() != WHO_AM_I_PV) return;

            // Handle GET
            op->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
                cop->onGet([this](std::unique_ptr<server::ExecOp>&& eop) { eop->reply(getWhoAmIValue(eop->credentials())); });

                cop->connect(resultType);
            });

            // Handle MONITOR
            std::shared_ptr<server::MonitorControlOp> sub;
            op->onSubscribe([this, sub](std::unique_ptr<server::MonitorSetupOp>&& sop) mutable {
                sub = sop->connect(resultType);
                sub->post(getWhoAmIValue(sub->credentials()));
            });
        }

        // Create the concatenated whoami response string from the `method` and `account`
        Value getWhoAmIValue(const std::shared_ptr<const server::ClientCredentials>& cred) const { // NOLINT(*-convert-member-functions-to-static)
            std::ostringstream strm;
            strm << cred->method << '/' << cred->account;
            return resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str());
        }
    };

    /**
     * @brief testServerOnly is a test that verifies the client can connect in server-only authenticated TLS mode
     *
     * This is used to verify that a client that is configured with a certificate authority certificate but no entity cert
     * will be able to connect in server-only authenticated TLS mode
     */
    void testServerOnly() {
        testShow() << __func__;
        resetCounter(cert_status_request_counters, server1);

        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf = server_config;
        serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;
        serv_conf.tls_disable_status_check = false;
        serv_conf.tls_disable_stapling = false;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;
        cli_conf.tls_disable_status_check = false;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

        try {
            auto reply(cli.get(TEST_PV).exec()->wait(5.0));
            testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
            testCounterEq(cert_status_request_counters, server1, 2);
        } catch (std::exception& e) {
            testFail("Timeout: %s", e.what());
        }

        conn.reset();
    }

    /**
     * @brief Test getting a value using a certificate that is configured to use an intermediate Certificate Authority
     * Note that we don't disable status monitoring, so the framework will attempt to contact
     * PVACMS to verify certificate status for any certificates that contain the certificate status extension.
     *
     * We chose the SERVER1 and CLIENT1 certificates for this test which as well as both being
     * certificates that have an intermediate certificate between them and the root Certificate Authority, they
     * also have the certificate status extension embedded in them.  So this test will
     * verify that the statuses are verified and the TLS proceeds as expected.  If the
     * statuses are not verified, then the test count will be off because there is a test
     * in the Mock PVACMS when certificate statuses are posted.
     *
     * The test to make sure that the connection is a tls connection here serves to verify that
     * the successful status verification does indeed result in a secure PVAccess connection being
     * established.
     */
    void testGetIntermediate() {
        testShow() << __func__;
        resetCounter(cert_status_request_counters, server1);
        resetCounter(cert_status_request_counters, client1);

        auto test_pv_value(nt::NTScalar{TypeCode::Int32}.create());
        auto test_pv(server::SharedPV::buildReadonly());

        auto serv_conf = server_config;
        serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;
        serv_conf.tls_disable_status_check = false;
        serv_conf.tls_disable_stapling = false;
        auto serv(serv_conf.build().addPV(TEST_PV, test_pv));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
        auto cli(cli_conf.build());

        test_pv.open(test_pv_value.update(TEST_PV_FIELD, 42));
        serv.start();
        sleep(1);

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);

        testCounterEq(cert_status_request_counters, server1, 2);
        testCounterEq(cert_status_request_counters, client1, 2);
        conn.reset();
    }

    /**
     * @brief This test verifies that the client connection is successfully reestablished after a client reconfigure()
     * is triggered.
     *
     * A client can now reconfigure its connection to use different TLS configuration.  We will first create a connection
     * using one TLS configuration, then we will reconfigure the connection using a different configuration
     * and check whether the changes are successfully applied to the connection.
     *
     * The simple way we do this is to create a server that will simply return the common name of the identity
     * presented in the client certificate (via the Subject common name CN) and the method by which the connection
     * is made (x509 for tls connections).  If we change the configuration, then this value will change to the new
     * credentials presented by the newly configured client.
     *
     * CLIENT1 and CLIENT2 are used as the different client configurations, and IOC1 is used for the server's config.
     *
     * As this uses the Mock PVACMS, we verify that it checks certificate status before using the certificates
     */
    void testClientReconfig() {
        testShow() << __func__;
        resetCounter(cert_status_request_counters, ioc);
        resetCounter(cert_status_request_counters, client1);
        resetCounter(cert_status_request_counters, client2);

        auto serv_conf = server_config;
        serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;
        serv_conf.tls_disable_status_check = false;
        serv_conf.tls_disable_stapling = false;

        auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        serv.start();
        sleep(1);

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
            testCounterEq(cert_status_request_counters, ioc, 2);
            testCounterEq(cert_status_request_counters, client1, 2);
            testCounterEq(cert_status_request_counters, client2, 0);
        }
        testDiag("Connect");

        Value update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);
        testCounterEq(cert_status_request_counters, ioc, 2);
        testCounterEq(cert_status_request_counters, client1, 2);
        testCounterEq(cert_status_request_counters, client2, 0);

        cli_conf = cli.config();
        cli_conf.tls_keychain_file = CLIENT2_KEYCHAIN_FILE;
        cli_conf.tls_keychain_pwd = CLIENT2_KEYCHAIN_FILE_PWD;
        testDiag("cli.reconfigure()");
        cli.reconfigure(cli_conf);

        testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });
        testDiag("Disconnect");

        try {
            (void)pop(sub, evt);
            testFail("Missing expected Connected");
        } catch (client::Connected& e) {
            testOk1(e.cred && e.cred->isTLS);
            testCounterEq(cert_status_request_counters, ioc, 3);
            testCounterEq(cert_status_request_counters, client1, 2);
            testCounterEq(cert_status_request_counters, client2, 2);
        } catch (...) {
            testFail("Unexpected exception instead of Connected");
        }
        testDiag("Reconnect");

        update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT2);
        // Cached responses so no checks
        testCounterEq(cert_status_request_counters, ioc, 3);
        testCounterEq(cert_status_request_counters, client1, 2);
        testCounterEq(cert_status_request_counters, client2, 2);
    }

    /**
     * @brief Tests that a new configuration is applied to all server connections when the server reconfigure() is executed.
     *
     * Here we use the SERVER1 and IOC1 certificates for the server and check that after a reconfigure() the
     * tls session is re-established but using the new configuration.
     *
     * As this uses the Mock PVACMS, we verify that it checks certificate status before using the certificates
     */
    void testServerReconfig() {
        testShow() << __func__;
        resetCounter(cert_status_request_counters, server1);
        resetCounter(cert_status_request_counters, client1);
        resetCounter(cert_status_request_counters, ioc);

        auto serv_conf = server_config;
        serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;
        serv_conf.tls_disable_status_check = false;
        serv_conf.tls_disable_stapling = false;

        auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        serv.start();
        sleep(1);

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
            testCounterEq(cert_status_request_counters, server1, 2);
            testCounterEq(cert_status_request_counters, client1, 2);
            testCounterEq(cert_status_request_counters, ioc, 0);
        }
        testDiag("Connect");

        Value update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);
        testCounterEq(cert_status_request_counters, server1, 2);
        testCounterEq(cert_status_request_counters, client1, 2);
        testCounterEq(cert_status_request_counters, ioc, 0);

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
            testCounterEq(cert_status_request_counters, server1, 2);
            testCounterEq(cert_status_request_counters, client1, 3);
            testCounterEq(cert_status_request_counters, ioc, 2);
        }
        testDiag("Reconnect");

        update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);
        testCounterEq(cert_status_request_counters, server1, 2);
        testCounterEq(cert_status_request_counters, client1, 3);
        testCounterEq(cert_status_request_counters, ioc, 2);
    }

    /**
     * @brief This test checks that tls connections are prohibited when CMS is unavailable, but configuration requires it
     *
     * The Mock PVACMS must be previously stopped prior to this test
     *
     */
    static void testCMSUnavailable(const server::Config &server_config) {
        testShow() << __func__;
        // Create a test PV and set the value to 42
        auto test_pv_value(nt::NTScalar{TypeCode::Int32}.create());
        auto test_pv(server::SharedPV::buildReadonly());
        test_pv.open(test_pv_value.update(TEST_PV_FIELD, 42));
        {
            // Configure a server with status checking enabled
            auto serv_conf = server_config;
            serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;
            serv_conf.tls_disable_status_check = false;
            serv_conf.tls_throw_if_no_cert = true;
            serv_conf.tls_disable_stapling = false;

            try {
                auto serv_no_cms(serv_conf.build().addPV(TEST_PV, test_pv));
                testOk(1, "Created server when CMS is unavailable");
            } catch (std::exception& e) {
                testFail("Unexpected Failure: %s", e.what());
            }

            // Now let's do it again with status checking and stapling disabled so we can test the client
            serv_conf.tls_disable_status_check = true;
            serv_conf.tls_disable_stapling = true;
            auto serv(serv_conf.build().addPV(TEST_PV1, test_pv));
            // Start the server
            serv.start();
            sleep(1);

            // Configure a client with status checking enabled
            auto cli_conf(serv.clientConfig());
            cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
            cli_conf.tls_disable_status_check = false;
            cli_conf.tls_disable_stapling = false;
            auto cli(cli_conf.build());

            try {
                auto val(cli.get(TEST_PV1).exec()->wait(1.0));
                testFail("Unexpected Success");
            } catch (std::exception& e) {
                testStrEq("Timeout", e.what());
            }
        }

        {
            // Configure a server with status checking and stapling disabled
            auto serv_conf2 = server_config;
            serv_conf2.tls_keychain_file = IOC1_KEYCHAIN_FILE;
            serv_conf2.tls_disable_status_check = false;
            serv_conf2.tls_disable_stapling = true;
            auto serv2(serv_conf2.build().addPV(TEST_PV2, test_pv));

            // Configure a client with status checking disabled
            auto cli_conf2(serv2.clientConfig());
            cli_conf2.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
            auto cli2(cli_conf2.build());

            // Start the server
            serv2.start();

            // Try to get the value of the PV
            try {
                auto reply(cli2.get(TEST_PV2).exec()->wait(3.0));
                testFail("Unexpected Success");
                if (reply) testFalse(reply[TEST_PV_FIELD].as<int32_t>() == 42);  // Should not get here
            } catch (std::exception& e) {
                testStrEq("Timeout", e.what());
            }
        }
    }

    /**
     * @brief Test that if client requests stapling but server does not send it
     * communication is established by out-of-band status request to CMS
     */
    void testClientStaplingNoServerStapling() {
        testShow() << __func__;
        resetCounter(cert_status_request_counters, server1);
        resetCounter(cert_status_request_counters, client1);
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf = server_config;
        serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;
        serv_conf.tls_disable_status_check = false;
        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
        cli_conf.tls_disable_stapling = false;
        auto cli(cli_conf.build());

        mbox.open(initial.update("value", 42));
        serv.start();
        sleep(1);
        testCounterEq(cert_status_request_counters, server1, 1);
        testCounterEq(cert_status_request_counters, client1, 1);

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());
        testCounterEq(cert_status_request_counters, server1, 1);
        testCounterEq(cert_status_request_counters, client1, 1);

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply["value"].as<int32_t>(), 42);
        testCounterEq(cert_status_request_counters, server1, 2);
        testCounterEq(cert_status_request_counters, client1, 2);

        conn.reset();
    }

    /**
     * @brief Test that if server sends stapling but client is not expecting it
     * communication is established by out-of-band status request to CMS
     */
    void testServerStaplingNoClientStapling() {
        testShow() << __func__;
        resetCounter(cert_status_request_counters, server1);
        resetCounter(cert_status_request_counters, client1);
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf = server_config;
        serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;
        serv_conf.tls_disable_status_check = false;
        serv_conf.tls_disable_stapling = false;
        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
        cli_conf.tls_disable_stapling = true;
        auto cli(cli_conf.build());

        mbox.open(initial.update("value", 42));
        serv.start();
        sleep(1);
        testCounterEq(cert_status_request_counters, server1, 1);
        testCounterEq(cert_status_request_counters, client1, 1);

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());
        testCounterEq(cert_status_request_counters, server1, 1);
        testCounterEq(cert_status_request_counters, client1, 1);

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply["value"].as<int32_t>(), 42);
        testCounterEq(cert_status_request_counters, server1, 2);
        testCounterEq(cert_status_request_counters, client1, 2);

        conn.reset();
    }
};

}  // namespace

/**
 * @brief The main test runner
 * @return test runner status (non-zero for errors)
 */
MAIN(testtlswithcmsandstapling) {
    testPlan(128);
    testSetup();
    logger_config_env();
    const auto tester = new Tester();
    tester->createCertStatuses();
    tester->makeStatusResponses();
    tester->startMockCMS();
    try {
        tester->testServerOnly();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->testGetIntermediate();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->testClientReconfig();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->testServerReconfig();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->testClientStaplingNoServerStapling();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->testServerStaplingNoClientStapling();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->stopMockCMS();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        Tester::testCMSUnavailable(tester->server_config);
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    delete tester;

    cleanup_for_valgrind();

    return testDone();
}
