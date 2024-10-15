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

#include "certfactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "testcerts.h"
#include "utilpvt.h"

/**
 * @brief This tester uses a Tester object and a bunch of MACROS that rely on a very opinionated
 * set of named variables to function.  prefixes `ca`, `super_server`, `intermediate_server`,
 * `server1`, `server2`, `ioc`, `client1`, and `client2` refer to the certificates generated
 * by `gen_test_certs`.  `ca` is used for the Certificate Authority and `super_server` is used
 * for the Mock PVACMS.
 *
 * `gen_test_certs` has been modified to generate the ca cert and the Mock PVACMS cert without
 * status extensions for obvious reasons.
 *
 * The tests initially follow the exact same sequence as those in the `testtls` suite and then try out some
 * edge conditions such as the Mock PVACMS being unavailable and the Mock PVACMS returning non GOOD statuses.
 *
 */
using namespace pvxs;
using namespace pvxs::certs;

namespace {

/**
 * @class Tester
 * @brief A class used for testing tls while monitoring certificate statuses against a Mock PVACMS server.
 */
struct Tester {
    const StatusDate now;
    const StatusDate status_valid_until_time;
    const StatusDate revocation_date;

    const Value status_value_prototype{CertStatus::getStatusPrototype()};
    DEFINE_MEMBERS(ca)
    DEFINE_MEMBERS(super_server)
    DEFINE_MEMBERS(intermediate_server)
    DEFINE_MEMBERS(server1)
    DEFINE_MEMBERS(server2)
    DEFINE_MEMBERS(ioc)
    DEFINE_MEMBERS(client1)
    DEFINE_MEMBERS(client2)

    server::SharedWildcardPV status_pv{server::SharedWildcardPV::buildMailbox()};
    server::Server pvacms;
    client::Context client;

    Tester()
        : now(time(nullptr)),
          status_valid_until_time(now.t + STATUS_VALID_FOR_SECS),
          revocation_date(now.t - REVOKED_SINCE_SECS)

              INIT_CERT_MEMBER_FROM_FILE(ca, CA) INIT_CERT_MEMBER_FROM_FILE(super_server, SUPER_SERVER)
                  INIT_CERT_MEMBER_FROM_FILE(intermediate_server, INTERMEDIATE_SERVER) INIT_CERT_MEMBER_FROM_FILE(server1, SERVER1)
                      INIT_CERT_MEMBER_FROM_FILE(server2, SERVER2) INIT_CERT_MEMBER_FROM_FILE(ioc, IOC1) INIT_CERT_MEMBER_FROM_FILE(client1, CLIENT1)
                          INIT_CERT_MEMBER_FROM_FILE(client2, CLIENT2)

    {
        // Set up the Mock PVACMS server certificate (does not contain custom status extension)
        auto pvacms_config = server::Config::fromEnv();
        pvacms_config.tls_cert_filename = SUPER_SERVER_CERT_FILE;
        pvacms_config.tls_disable_status_check = true;
        pvacms_config.tls_disable_stapling = true;
        pvacms_config.config_target = pvxs::impl::ConfigCommon::CMS;
        pvacms = pvacms_config.build().addPV(GET_MONITOR_CERT_STATUS_PV, status_pv);
        client = pvacms.clientConfig().build();

        if (CHECK_CERT_MEMBER_CONDITION(ca) || CHECK_CERT_MEMBER_CONDITION(super_server) || CHECK_CERT_MEMBER_CONDITION(intermediate_server) ||
            CHECK_CERT_MEMBER_CONDITION(server1) || CHECK_CERT_MEMBER_CONDITION(server2) || CHECK_CERT_MEMBER_CONDITION(ioc) ||
            CHECK_CERT_MEMBER_CONDITION(client1) || CHECK_CERT_MEMBER_CONDITION(client2)) {
            testFail("Error loading one or more certificates");
            return;
        }
        testShow() << "Loaded all test certs\n";
    }

    ~Tester() {};

    /**
     * @brief Creates certificate statuses.
     *
     * This function generates mock statuses to be returned by the Mock CMS server.
     * These statuses are replete with valid OCSP responses that are valid for `STATUS_VALID_FOR_MINS` minutes
     */
    void createCertStatuses() {
        testShow() << __func__;
        try {
            auto cert_status_creator(CertStatusFactory(ca_cert.cert, ca_cert.pkey, ca_cert.chain, 0, STATUS_VALID_FOR_SECS));
            CREATE_CERT_STATUS(ca, {VALID})
            CREATE_CERT_STATUS(intermediate_server, {VALID})
            CREATE_CERT_STATUS(server1, {VALID})
            CREATE_CERT_STATUS(server2, {VALID})
            CREATE_CERT_STATUS(ioc, {VALID})
            CREATE_CERT_STATUS(client1, {VALID})
            CREATE_CERT_STATUS(client2, {VALID})
        } catch (std::exception& e) {
            testFail("Failed to read certificate in from file: %s\n", e.what());
        }
    }

    /**
     * @brief Make PVAccess Certificate Status Responses for each of the certificates
     */
    void makeStatusResponses() {
        testShow() << __func__;
        auto cert_status_creator(CertStatusFactory(ca_cert.cert, ca_cert.pkey, ca_cert.chain, 0, STATUS_VALID_FOR_SECS));
        MAKE_STATUS_RESPONSE(ca)
        MAKE_STATUS_RESPONSE(intermediate_server)
        MAKE_STATUS_RESPONSE(server1)
        MAKE_STATUS_RESPONSE(server2)
        MAKE_STATUS_RESPONSE(ioc)
        MAKE_STATUS_RESPONSE(client1)
        MAKE_STATUS_RESPONSE(client2)
    }

    /**
     * @brief Pop the next event off the subscribed PV's queue
     * @param sub the subscription
     * @param evt the epics event
     * @return the popped Value or empty on timeout
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
     * @brief Start the Mock PVACMS service]
     *
     * Important; This server is implemented by using the standard SharedWildcardPV so it
     * also tests this newly exposed feature.
     *
     * This essentially creates a server that will serve a `SharedWildcardPV` that responds to
     * PVs  corresponding to the certificate status request pattern.  It will respond to only those PVs that were
     * generated by `gen_test_certs` anx only with the responses created in `createCertStatuses`
     * unless changed by putting values like 'APPROVED', 'DENIED', or 'REVOKED' to the 'state' field.
     *
     * During the setup tests are performed to verify that it works as expected
     *
     */
    void startMockCMS() {
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Mock PVACMS Server");

            SET_PV(ca)
            SET_PV(intermediate_server)
            SET_PV(server1)
            SET_PV(server2)
            SET_PV(ioc)
            SET_PV(client1)
            SET_PV(client2)

            status_pv.onFirstConnect([this](server::SharedWildcardPV& pv, const std::string& pv_name, const std::list<std::string>& parameters) {
                auto it = parameters.begin();
                const std::string& issuer_id = *it;
                const std::string& serial_string = *++it;
                uint64_t serial = std::stoull(serial_string);

                if (pv.isOpen(pv_name)) {
                    switch (serial) {
                        POST_VALUE_CASE(ca, post)
                        POST_VALUE_CASE(intermediate_server, post)
                        POST_VALUE_CASE(server1, post)
                        POST_VALUE_CASE(server2, post)
                        POST_VALUE_CASE(ioc, post)
                        POST_VALUE_CASE(client1, post)
                        POST_VALUE_CASE(client2, post)
                        default:
                            testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());
                    }
                } else {
                    switch (serial) {
                        POST_VALUE_CASE(ca, open)
                        POST_VALUE_CASE(intermediate_server, open)
                        POST_VALUE_CASE(server1, open)
                        POST_VALUE_CASE(server2, open)
                        POST_VALUE_CASE(ioc, open)
                        POST_VALUE_CASE(client1, open)
                        POST_VALUE_CASE(client2, open)
                        default:
                            testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());
                    }
                }
            });
            status_pv.onLastDisconnect([](server::SharedWildcardPV& pv, const std::string& pv_name, const std::list<std::string>& parameters) {
                testOk(1, "Closing Status Request Connection: %s", pv_name.c_str());
                pv.close(pv_name);
            });

            pvacms.start();

            testDiag("Set up: %s", "Mock PVACMS Server");
        } catch (std::exception& e) {
            testFail("Failed to set up Mock PVACMS Server: %s", e.what());
        }
    }

    /**
     * @brief Stop the Mock PVACMS Server
     */
    void stopMockCMS() {
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
     * The values corresponds to the following:
     *   `method`: 'ca' for `tcp` connections, and `x509` for `tls` connections
     *   `account`: the subject `CN` (common name) encoded in the certificate for `tls` connections,
     *              or "ca" or "anonymous" for `tcp` connections
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
        inline Value getWhoAmIValue(std::shared_ptr<const server::ClientCredentials> cred) {
            std::ostringstream strm;
            strm << cred->method << '/' << cred->account;
            return resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str());
        }
    };

    /**
     * @brief Test getting a value using a certificate that is configured to use an intermediate CA
     * Note that we don't disable status monitoring so therefore the framework will attempt to contact
     * PVACMS to verify certificate status for any certificates that contain the certificate status extension.
     *
     * We chose the SERVER1 and CLIENT1 certificates for this test which as well as both being
     * certificates that have an intermediate certificate between them and the root CA, they
     * also have the certificate status extension embedded in them.  So this test will
     * verify that the statuses are verified and the TLS proceeds as expected.  If the
     * statuses are not verified then the test count will be off because there is a test
     * in the Mock PVACMS when certificate statuses are posted.
     *
     * The test to make sure that the connection is a tls connection here serves to verify that
     * the successful status verification does indeed result in a secure PVAccess connection being
     * established.
     */
    void testGetIntermediate() {
        testShow() << __func__;
        RESET_COUNTER(server1)
        RESET_COUNTER(client1)

        auto test_pv_value(nt::NTScalar{TypeCode::Int32}.create());
        auto test_pv(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = SERVER1_CERT_FILE;
        serv_conf.tls_disable_status_check = false;
        auto serv(serv_conf.build().addPV(TEST_PV, test_pv));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;
        auto cli(cli_conf.build());

        test_pv.open(test_pv_value.update(TEST_PV_FIELD, 42));
        serv.start();

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        TEST_COUNTER_EQ(server1, 2)
        TEST_COUNTER_EQ(client1, 1)

        conn.reset();
    }

    /**
     * @brief This test verifies that the client connection is successfully reestablished after a client reconfigure
     * is triggered.
     *
     * A client can now reconfigure its connection to use different tls configuration.  We will first create a connection
     * using one tls configuration then we will reconfigure the connection using a different configuration
     * and check whether the changes are successfully applied to the connection.
     *
     * The simple way we do this is to create a server that will simply return the common name of the identity
     * presented in the client certificate (via the Subject common name CN) and the method by which the connection
     * is made (x509 for tls connections).  If we change configuration then this value will change to the new
     * credentials presented by the newly configured client.
     *
     * CLIENT1 and CLIENT2 are used as the different client configuration and IOC1 is used for the server's config.
     *
     * As this uses the Mock PVACMS we verify that it checks certificate status before using the certificates
     */
    void testClientReconfig() {
        testShow() << __func__;
        RESET_COUNTER(ioc)
        RESET_COUNTER(client1)
        RESET_COUNTER(client2)

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = IOC1_CERT_FILE;
        serv_conf.tls_disable_status_check = false;

        auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

        auto cli(cli_conf.build());

        serv.start();

        epicsEvent evt;
        auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());
        Value update;

        try {
            pop(sub, evt);
            testFail("Unexpected success");
            testSkip(2, "oops");
        } catch (client::Connected& e) {
            testTrue(e.cred->isTLS);
            testEq(e.cred->method, TLS_METHOD_STRING);
            testEq(e.cred->account, CERT_CN_IOC1);
            TEST_COUNTER_EQ(ioc, 2)
            TEST_COUNTER_EQ(client1, 1)
            TEST_COUNTER_EQ(client2, 0)
        }
        testDiag("Connect");

        update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);
        TEST_COUNTER_EQ(ioc, 2)
        TEST_COUNTER_EQ(client1, 1)
        TEST_COUNTER_EQ(client2, 0)

        cli_conf = cli.config();
        cli_conf.tls_cert_filename = CLIENT2_CERT_FILE;
        cli_conf.tls_cert_password = CLIENT2_CERT_FILE_PWD;
        cli_conf.tls_disable_stapling = true;
        testDiag("cli.reconfigure()");
        cli.reconfigure(cli_conf);

        testThrows<client::Disconnect>([this, &sub, &evt] { pop(sub, evt); });
        testDiag("Disconnect");

        try {
            (void)pop(sub, evt);
            testFail("Missing expected Connected");
        } catch (client::Connected& e) {
            testOk1(e.cred && e.cred->isTLS);
            TEST_COUNTER_EQ(ioc, 2)
            TEST_COUNTER_EQ(client1, 1)
            TEST_COUNTER_EQ(client2, 1)
        } catch (...) {
            testFail("Unexpected exception instead of Connected");
        }
        testDiag("Reconnect");

        update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT2);
        TEST_COUNTER_EQ(ioc, 2)
        TEST_COUNTER_EQ(client1, 1)
        TEST_COUNTER_EQ(client2, 1)
    }

    /**
     * @brief Tests that new configuration is applied to all server connections when the server reconfigure is executed.
     *
     * Here we use the SERVER1 and IOC1 certificates for the server and check that after a reconfigure the
     * tls session is re-established but using the new configuration.
     *
     * As this uses the Mock PVACMS we verify that it checks certificate status before using the certificates
     */
    void testServerReconfig() {
        testShow() << __func__;
        RESET_COUNTER(server1)
        RESET_COUNTER(client1)
        RESET_COUNTER(ioc)

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = SERVER1_CERT_FILE;
        serv_conf.tls_disable_status_check = false;

        auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

        auto cli(cli_conf.build());

        serv.start();

        epicsEvent evt;
        auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());
        Value update;

        try {
            pop(sub, evt);
            testFail("Unexpected success");
            testSkip(2, "oops");
        } catch (client::Connected& e) {
            testTrue(e.cred->isTLS);
            testEq(e.cred->method, TLS_METHOD_STRING);
            testEq(e.cred->account, CERT_CN_SERVER1);
            TEST_COUNTER_EQ(server1, 2)
            TEST_COUNTER_EQ(client1, 1)
            TEST_COUNTER_EQ(ioc, 0)
        }
        testDiag("Connect");

        update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);
        TEST_COUNTER_EQ(server1, 2)
        TEST_COUNTER_EQ(client1, 1)
        TEST_COUNTER_EQ(ioc, 0)

        serv_conf = serv.config();
        serv_conf.tls_cert_filename = IOC1_CERT_FILE;
        testDiag("serv.reconfigure()");
        serv.reconfigure(serv_conf);

        testThrows<client::Disconnect>([this, &sub, &evt] { pop(sub, evt); });
        testDiag("Disconnect");

        try {
            pop(sub, evt);
            testFail("Unexpected success");
            testSkip(2, "oops");
        } catch (client::Connected& e) {
            testTrue(e.cred->isTLS);
            testEq(e.cred->method, TLS_METHOD_STRING);
            testEq(e.cred->account, CERT_CN_IOC1);
            TEST_COUNTER_EQ(server1, 2)
            TEST_COUNTER_EQ(client1, 1)
            TEST_COUNTER_EQ(ioc, 2)
        }
        testDiag("Reconnect");

        update = pop(sub, evt);
        testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);
        TEST_COUNTER_EQ(server1, 2)
        TEST_COUNTER_EQ(client1, 1)
        TEST_COUNTER_EQ(ioc, 2)
    }

    /**
     * @brief Test getting a value using a certificate that is configured to use an intermediate CA
     * Note that we don't disable status monitoring so therefore the framework will attempt to contact
     * PVACMS to verify certificate status for any certificates that contain the certificate status extension.
     *
     * We chose the SERVER1 and CLIENT1 certificates for this test which as well as both being
     * certificates that have an intermediate certificate between them and the root CA, they
     * also have the certificate status extension embedded in them.  So this test will
     * verify that the statuses are verified and the TLS proceeds as expected.  If the
     * statuses are not verified then the test count will be off because there is a test
     * in the Mock PVACMS when certificate statuses are posted.
     *
     * The test to make sure that the connection is a tls connection (isTLS) here serves to verify that
     * the successful status verification does indeed result in a secure PVAccess connection being
     * established.
     */
    void testUnCachedStatus() {
        testShow() << __func__;
        auto cert_status_creator(CertStatusFactory(ca_cert.cert, ca_cert.pkey, ca_cert.chain, 0, STATUS_VALID_FOR_SHORT_SECS));
        MAKE_STATUS_RESPONSE(ca)
        MAKE_STATUS_RESPONSE(intermediate_server)
        MAKE_STATUS_RESPONSE(server1)
        MAKE_STATUS_RESPONSE(server2)
        MAKE_STATUS_RESPONSE(ioc)
        MAKE_STATUS_RESPONSE(client1)
        MAKE_STATUS_RESPONSE(client2)

        RESET_COUNTER(server1)
        RESET_COUNTER(client1)

        auto test_pv_value(nt::NTScalar{TypeCode::Int32}.create());
        auto test_pv(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = SERVER1_CERT_FILE;
        serv_conf.tls_disable_status_check = false;
        auto serv(serv_conf.build().addPV(TEST_PV, test_pv));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

        auto cli(cli_conf.build());

        test_pv.open(test_pv_value.update(TEST_PV_FIELD, 42));
        serv.start();
        sleep(1);

        auto conn(cli.connect(TEST_PV)
                      .onConnect([](const client::Connected& c) {
                          testTrue(c.cred && c.cred->isTLS);
                          sleep(1);
                      })
                      .exec());
        sleep(1);

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        TEST_COUNTER_EQ(server1, 2)
        TEST_COUNTER_EQ(client1, 1)

        conn.reset();
    }

    /**
     * @brief This test checks that tls connections are prohibited when CMS is unavailable but configuration requires it
     *
     * The Mock PVACMS must be previously stopped prior to this test
     *
     */
    void testCMSUnavailable() {
        testShow() << __func__;

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = IOC1_CERT_FILE;
        serv_conf.tls_disable_status_check = false;

        auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;

        auto cli(cli_conf.build());

        serv.start();

        epicsEvent evt;
        auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());

        try {
            testTrue(!evt.wait(5.0));
        } catch (client::Connected& e) {
            testFail("Unexpected success");
            testSkip(1, "oops");
        }
        testDiag("Expected to not connect");
    }
};

}  // namespace

/**
 * @brief The main test runner
 * @return test runner status (non-zero for errors)
 */
MAIN(testtlswithcms) {
    // Initialize SSL
    pvxs::ossl::SSLContext::sslInit();

    testPlan(153);
    testSetup();
    logger_config_env();
    auto tester = new Tester();
    tester->createCertStatuses();
    tester->makeStatusResponses();
    tester->startMockCMS();
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
        tester->testUnCachedStatus();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->stopMockCMS();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    try {
        tester->testCMSUnavailable();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    delete (tester);
    cleanup_for_valgrind();
    return testDone();
}
