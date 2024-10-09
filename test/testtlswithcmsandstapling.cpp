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

using namespace pvxs;
using namespace pvxs::certs;

namespace {

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
        auto pvacms_config = server::Config::fromEnv();
        pvacms_config.tls_cert_filename = SUPER_SERVER_CERT_FILE;  // Set up the Mock PVACMS server certificate (does not contain custom status extension)
        //        pvacms_config.tls_cert_filename.clear();  // Set up the Mock PVACMS server with no certificate
        pvacms_config.tls_disable_status_check = true;
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

    void createCertStatuses() {
        testShow() << __func__;
        try {
            auto cert_status_creator(CertStatusFactory(ca_cert.cert, ca_cert.pkey, ca_cert.chain, STATUS_VALID_FOR_MINS));
            CREATE_CERT_STATUS(intermediate_server, VALID)
            CREATE_CERT_STATUS(server1, VALID)
            CREATE_CERT_STATUS(server2, VALID)
            CREATE_CERT_STATUS(ioc, VALID)
            CREATE_CERT_STATUS(client1, VALID)
            CREATE_CERT_STATUS(client2, VALID)
        } catch (std::exception& e) {
            testFail("Failed to read certificate in from file: %s\n", e.what());
        }
    }

    void makeStatusResponses() {
        testShow() << __func__;
        MAKE_STATUS_RESPONSE(intermediate_server)
        MAKE_STATUS_RESPONSE(server1)
        MAKE_STATUS_RESPONSE(server2)
        MAKE_STATUS_RESPONSE(ioc)
        MAKE_STATUS_RESPONSE(client1)
        MAKE_STATUS_RESPONSE(client2)
    }

    void startMockCMS() {
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Mock PVACMS Server");

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

                testOk(1, "Status Request for: issuer %s, serial %s", issuer_id.c_str(), serial_string.c_str());
                if (pv.isOpen(pv_name)) {
                    switch (serial) {
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
                testDiag("Posted Value for request: %s", pv_name.c_str());
            });
            status_pv.onLastDisconnect([](server::SharedWildcardPV& pv, const std::string& pv_name, const std::list<std::string>& parameters) {
                testOk(1, "Closing Status Request Connection: %s", pv_name.c_str());
                pv.close(pv_name);
            });

            pvacms.start();

            TEST_STATUS_REQUEST(intermediate_server)
            TEST_STATUS_REQUEST(server1)
            TEST_STATUS_REQUEST(server2)
            TEST_STATUS_REQUEST(ioc)
            TEST_STATUS_REQUEST(client1)
            TEST_STATUS_REQUEST(client2)

            testDiag("Set up: %s", "Mock PVACMS Server");
        } catch (std::exception& e) {
            testFail("Failed to set up Mock PVACMS Server: %s", e.what());
        }
    }

    void stopMockCMS() {
        testShow() << __func__;
        try {
            testDiag("Stopping: %s", "Mock PVACMS Server");
            pvacms.stop();
        } catch (std::exception& e) {
            testFail("Failed to stop Mock PVACMS Server: %s", e.what());
        }
    }

    void testGetIntermediate() {
        testShow() << __func__;
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = SERVER1_CERT_FILE;
        auto serv(serv_conf.build().addPV("mailbox", mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = CLIENT1_CERT_FILE;
        auto cli(cli_conf.build());

        mbox.open(initial.update("value", 42));
        serv.start();

        auto conn(cli.connect("mailbox").onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

        auto reply(cli.get("mailbox").exec()->wait(5.0));
        testEq(reply["value"].as<int32_t>(), 42);

        conn.reset();
    }

    struct WhoAmI final : public server::Source {
        const Value resultType;

        WhoAmI() : resultType(nt::NTScalar(TypeCode::String).create()) {}

        virtual void onSearch(Search& op) override final {
            for (auto& pv : op) {
                if (strcmp(pv.name(), "whoami") == 0) pv.claim();
            }
        }

        virtual void onCreate(std::unique_ptr<server::ChannelControl>&& op) override final {
            if (op->name() != "whoami") return;

            op->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
                cop->onGet([this](std::unique_ptr<server::ExecOp>&& eop) {
                    auto cred(eop->credentials());
                    std::ostringstream strm;
                    strm << cred->method << '/' << cred->account;

                    eop->reply(resultType.cloneEmpty().update("value", strm.str()));
                });

                cop->connect(resultType);
            });

            std::shared_ptr<server::MonitorControlOp> sub;
            op->onSubscribe([this, sub](std::unique_ptr<server::MonitorSetupOp>&& sop) mutable {
                sub = sop->connect(resultType);
                auto cred(sub->credentials());
                std::ostringstream strm;
                strm << cred->method << '/' << cred->account;

                sub->post(resultType.cloneEmpty().update("value", strm.str()));
            });
        }
    };

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

    void testClientReconfig() {
        testShow() << __func__;

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = IOC1_CERT_FILE;

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
        testEq(update["value"].as<std::string>(), "x509/client1");

        cli_conf = cli.config();
        cli_conf.tls_cert_filename = CLIENT2_CERT_FILE;
        cli_conf.tls_cert_password = CLIENT2_CERT_FILE_PWD;
        testDiag("cli.reconfigure()");
        cli.reconfigure(cli_conf);

        testThrows<client::Disconnect>([this, &sub, &evt] { pop(sub, evt); });
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
        testEq(update["value"].as<std::string>(), "x509/client2");
    }

    void testServerReconfig() {
        testShow() << __func__;

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_cert_filename = SERVER1_CERT_FILE;

        auto serv(serv_conf.build().addSource("whoami", std::make_shared<WhoAmI>()));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_cert_filename = IOC1_CERT_FILE;

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
        testEq(update["value"].as<std::string>(), "x509/ioc1");

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
            testEq(e.cred->method, "x509");
            testEq(e.cred->account, "ioc1");
        }
        testDiag("Reconnect");

        update = pop(sub, evt);
        testEq(update["value"].as<std::string>(), "x509/ioc1");
    }
};

}  // namespace

MAIN(testtlswithcms) {
    // Initialize SSL
    pvxs::ossl::SSLContext::sslInit();

    testPlan(142);
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
        tester->stopMockCMS();
    } catch (std::runtime_error& e) {
        testFail("FAILED with errors: %s\n", e.what());
    }
    delete (tester);
    cleanup_for_valgrind();
    return testDone();
}
