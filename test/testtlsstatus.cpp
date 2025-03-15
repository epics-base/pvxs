/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <iostream>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <openssl/crypto.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <pvxs/log.h>
#include <pvxs/sharedwildcardpv.h>
#include <pvxs/sslinit.h>
#include <pvxs/unittest.h>

#include "certfactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "openssl.h"
#include "ownedptr.h"
#include "testcerts.h"

namespace {
using namespace pvxs;
using namespace pvxs::certs;

struct Tester {
    // Pristine values
    const StatusDate now;
    const StatusDate status_valid_until_time;
    const StatusDate revocation_date;
    const Value status_value_prototype{CertStatus::getStatusPrototype()};

    DEFINE_MEMBERS(cert_auth)
    DEFINE_MEMBERS(server1)
    DEFINE_MEMBERS(client1)
    ossl_ptr<X509_STORE> trusted_store{cert_auth_cert.createTrustStore()};

    server::SharedWildcardPV status_pv{server::SharedWildcardPV::buildMailbox()};
    server::Server pvacms{server::Config::forCms().build().addPV(GET_MONITOR_CERT_STATUS_PV, status_pv)};
    client::Context client{pvacms.clientConfig().build()};

    Tester()
        : now(time(nullptr)),
          status_valid_until_time(now.t + STATUS_VALID_FOR_SECS),
          revocation_date(now.t - REVOKED_SINCE_SECS) INIT_CERT_MEMBER_FROM_FILE(cert_auth, CERT_AUTH) INIT_CERT_MEMBER_FROM_FILE(server1, SERVER1)
              INIT_CERT_MEMBER_FROM_FILE(client1, CLIENT1) {
        if (CHECK_CERT_MEMBER_CONDITION(cert_auth) || CHECK_CERT_MEMBER_CONDITION(server1) || CHECK_CERT_MEMBER_CONDITION(client1)) {
            testFail("Error loading one or more certificates");
            return;
        }
        testShow() << "Testing TLS Status Functions:\n";
    }

    ~Tester() = default;

    void initialisation() const {
        testShow() << __func__;
        testEq(now.t, status_valid_until_time.t - STATUS_VALID_FOR_SECS);
        testEq(now.t, revocation_date.t + REVOKED_SINCE_SECS);
    }

    void ocspPayload() {
        testShow() << __func__;
        try {
            const auto cert_status_creator(CertStatusFactory(cert_auth_cert.cert, cert_auth_cert.pkey, cert_auth_cert.chain, 0, STATUS_VALID_FOR_SECS));
            CREATE_CERT_STATUS(cert_auth, {VALID});
            CREATE_CERT_STATUS(server1, {PENDING});
            CREATE_CERT_STATUS(client1, {REVOKED});
        } catch (std::exception &e) {
            testFail("Failed to read certificate in from file: %s\n", e.what());
        }
    }

    void parse() const {
        testShow() << __func__;
        try {
            testDiag("Parsing OCSP Response: %s", "Client certificate");
            auto parsed_response = CertStatusManager::parse(client1_cert_status.ocsp_bytes, trusted_store.get());
            testDiag("Parsed OCSP Response: %s", "Client certificate");

            testEq(parsed_response.serial, client1_serial);
            testEq(parsed_response.ocsp_status.i, OCSP_CERTSTATUS_REVOKED);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, revocation_date.t);
        } catch (std::exception &e) {
            testFail("Failed to parse Client OCSP response: %s", e.what());
        }

        try {
            testDiag("Parsing OCSP Response: %s", "Server certificate");
            auto parsed_response = CertStatusManager::parse(server1_cert_status.ocsp_bytes, trusted_store.get());
            testDiag("Parsed OCSP Response: %s", "Server certificate");

            testEq(parsed_response.serial, server1_serial);
            testEq(parsed_response.ocsp_status.i, OCSP_CERTSTATUS_UNKNOWN);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse Server OCSP response: %s", e.what());
        }

        try {
            testDiag("Parsing OCSP Response: %s", "Certificate Authority Certificate");
            auto parsed_response = CertStatusManager::parse(cert_auth_cert_status.ocsp_bytes, trusted_store.get());
            testDiag("Parsed OCSP Response: %s", "Certificate Authority Certificate");

            testEq(parsed_response.serial, cert_auth_serial);
            testEq(parsed_response.ocsp_status.i, OCSP_CERTSTATUS_GOOD);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse CA OCSP response: %s", e.what());
        }
    }

    void makeStatusResponses() {
        testShow() << __func__;
        const auto cert_status_creator(CertStatusFactory(cert_auth_cert.cert, cert_auth_cert.pkey, cert_auth_cert.chain, 0, STATUS_VALID_FOR_SECS));
        MAKE_STATUS_RESPONSE(cert_auth)
        MAKE_STATUS_RESPONSE(server1)
        MAKE_STATUS_RESPONSE(client1)
    }

    void testStatusConversions() {
        testShow() << __func__;
        try {
            auto unknown_status = UnknownCertificateStatus();
            {
                testDiag("PVACertificateStatus ==> CertificateStatus");
                auto client_cs = static_cast<CertifiedCertificateStatus>(client1_cert_status);
                auto server_cs = static_cast<CertifiedCertificateStatus>(server1_cert_status);
                auto cert_auth_cs = static_cast<CertifiedCertificateStatus>(cert_auth_cert_status);

                testDiag("CertificateStatus == PVACertificateStatus");
                testOk1(client_cs == client1_cert_status);  // REVOKED == REVOKED
                testOk1(server_cs == server1_cert_status);  // PENDING == PENDING
                testOk1(cert_auth_cs == cert_auth_cert_status);           // VALID == VALID

                testDiag("PVACertificateStatus == CertificateStatus");
                testOk1(client1_cert_status == client_cs);  // REVOKED == REVOKED
                testOk1(server1_cert_status == server_cs);  // PENDING == PENDING
                testOk1(cert_auth_cert_status == cert_auth_cs);           // VALID == VALID

                testDiag("CertificateStatus != PVACertificateStatus");
                testOk1(client_cs != cert_auth_cert_status);       // REVOKED != VALID
                testOk1(server_cs != client1_cert_status);  // PENDING != REVOKED
                testOk1(cert_auth_cs != server1_cert_status);      // VALID != PENDING

                testDiag("PVACertificateStatus != CertificateStatus");
                testOk1(cert_auth_cert_status != client_cs);       // VALID != REVOKED
                testOk1(client1_cert_status != server_cs);  // REVOKED != UNKNOWN
                testOk1(server1_cert_status != cert_auth_cs);      // PENDING != VALID
            }

            {
                testDiag("PVACertificateStatus ==> OCSPStatus");
                auto client_ocs = static_cast<OCSPStatus>(client1_cert_status);
                auto server_ocs = static_cast<OCSPStatus>(server1_cert_status);
                auto cert_auth_ocs = static_cast<OCSPStatus>(cert_auth_cert_status);

                testDiag("OCSPStatus == PVACertificateStatus");
                testOk1(client_ocs == client1_cert_status);  // REVOKED == REVOKED
                testOk1(cert_auth_ocs == cert_auth_cert_status);           // VALID == VALID

                testDiag("PVACertificateStatus == OCSPStatus");
                testOk1(client1_cert_status == client_ocs);  // REVOKED == REVOKED
                testOk1(cert_auth_cert_status == cert_auth_ocs);           // VALID == VALID

                testDiag("OCSPStatus != PVACertificateStatus");
                testOk1(client_ocs != cert_auth_cert_status);   // REVOKED != VALID
                testOk1(cert_auth_ocs != server1_cert_status);  // VALID != PENDING

                testOk1(server_ocs != server1_cert_status);  // UNKNOWN == PENDING
                testOk1(server_ocs != client1_cert_status);  // UNKNOWN != REVOKED

                testDiag("PVACertificateStatus != OCSPStatus");
                testOk1(cert_auth_cert_status != client_ocs);   // VALID != REVOKED
                testOk1(server1_cert_status != cert_auth_ocs);  // PENDING != VALID

                testOk1(server1_cert_status != server_ocs);  // PENDING == UNKNOWN
                testOk1(client1_cert_status != server_ocs);  // REVOKED != UNKNOWN
            }

            {
                testDiag("PVACertificateStatus ==> certstatus_t");
                auto client_cs_t = static_cast<certstatus_t>(client1_cert_status.status.i);
                auto server_cs_t = static_cast<certstatus_t>(server1_cert_status.status.i);
                auto cert_auth_cs_t = static_cast<certstatus_t>(cert_auth_cert_status.status.i);

                testDiag("certstatus_t == PVACertificateStatus");
                testOk1(client_cs_t == client1_cert_status);  // REVOKED == REVOKED
                testOk1(server_cs_t == server1_cert_status);  // PENDING == PENDING
                testOk1(cert_auth_cs_t == cert_auth_cert_status);           // VALID == VALID

                testDiag("PVACertificateStatus == certstatus_t");
                testOk1(client1_cert_status == client_cs_t);  // REVOKED == REVOKED
                testOk1(server1_cert_status == server_cs_t);  // PENDING == PENDING
                testOk1(cert_auth_cert_status == cert_auth_cs_t);           // VALID == VALID

                testDiag("certstatus_t != PVACertificateStatus");
                testOk1(client_cs_t != cert_auth_cert_status);       // REVOKED != VALID
                testOk1(server_cs_t != client1_cert_status);  // PENDING != REVOKED
                testOk1(cert_auth_cs_t != server1_cert_status);      // VALID != PENDING

                testDiag("PVACertificateStatus != certstatus_t");
                testOk1(cert_auth_cert_status != client_cs_t);       // VALID != REVOKED
                testOk1(client1_cert_status != server_cs_t);  // REVOKED != UNKNOWN
                testOk1(server1_cert_status != cert_auth_cs_t);      // PENDING != VALID
            }

            {
                testDiag("PVACertificateStatus ==> certstatus_t & OCSPStatus");
                auto client_cs_t = static_cast<certstatus_t>(client1_cert_status.status.i);
                auto server_cs_t = static_cast<certstatus_t>(server1_cert_status.status.i);
                auto cert_auth_cs_t = static_cast<certstatus_t>(cert_auth_cert_status.status.i);

                auto client_ocs = static_cast<OCSPStatus>(client1_cert_status);
                auto server_ocs = static_cast<OCSPStatus>(server1_cert_status);
                auto cert_auth_ocs = static_cast<OCSPStatus>(cert_auth_cert_status);

                testDiag("OCSPStatus == certstatus_t");
                testOk1(client_ocs == client_cs_t);  // REVOKED == REVOKED
                testOk1(server_ocs != server_cs_t);  // UNKNOWN != PENDING
                testOk1(cert_auth_ocs == cert_auth_cs_t);          // VALID == VALID

                testDiag("certstatus_t == OCSPStatus");
                testOk1(client_cs_t == client_ocs);  // REVOKED == REVOKED
                testOk1(server_cs_t != server_ocs);  // PENDING != UNKNOWN
                testOk1(cert_auth_cs_t == cert_auth_ocs);          // VALID == VALID

                testDiag("certstatus_t != OCSPStatus");
                testOk1(client_ocs != cert_auth_cs_t);      // REVOKED != VALID
                testOk1(server_ocs != client_cs_t);  // UNKNOWN != REVOKED
                testOk1(cert_auth_ocs != server_cs_t);      // VALID != PENDING

                testDiag("OCSPStatus != certstatus_t");
                testOk1(client_cs_t != cert_auth_ocs);      // VALID != REVOKED
                testOk1(server_cs_t != client_ocs);  // REVOKED != UNKNOWN
                testOk1(cert_auth_cs_t != server_ocs);      // PENDING != VALID
            }

        } catch (std::exception &e) {
            testFail("Failed test status conversions: %s", e.what());
        }
    }

    void makeStatusRequest() {
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Mock PVACMS Server");

            SET_PV(cert_auth)
            SET_PV(server1)
            SET_PV(client1)

            status_pv.onFirstConnect([this](server::SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
                auto it = parameters.begin();
                const std::string &serial_string = *++it;
                const serial_number_t serial = std::stoull(serial_string);

                if (pv.isOpen(pv_name)) {
                    switch (serial) {
                        POST_VALUE_CASE(cert_auth, post)
                        POST_VALUE_CASE(server1, post)
                        POST_VALUE_CASE(client1, post)
                        default:
                            testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());
                    }
                } else {
                    switch (serial) {
                        POST_VALUE_CASE(cert_auth, open)
                        POST_VALUE_CASE(server1, open)
                        POST_VALUE_CASE(client1, open)
                        default:
                            testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());
                    }
                }

                testDiag("Posted Value for request: %s", pv_name.c_str());
            });
            status_pv.onLastDisconnect([](server::SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
                testOk(1, "Closing Status Request Connection: %s", pv_name.c_str());
                pv.close(pv_name);
            });

            pvacms.start();

            testDiag("Set up: %s", "Mock PVACMS Server");

            TEST_STATUS_REQUEST(client1)
            TEST_STATUS_REQUEST(server1)
            TEST_STATUS_REQUEST(client1)

            testDiag("Stop Mock PVACMS server");
            pvacms.stop();
        } catch (std::exception &e) {
            testFail("Failed to set up Mock PVACMS Server: %s", e.what());
        }
    }
};

}  // namespace

MAIN(testtlsstatus) {
    // Initialize SSL
    ossl::sslInit();

    testPlan(121);
    testSetup();
    logger_config_env();
    const auto tester = new Tester();
    tester->initialisation();
    tester->ocspPayload();
    tester->parse();
    tester->makeStatusResponses();
    tester->testStatusConversions();
    tester->makeStatusRequest();
    delete tester;
    cleanup_for_valgrind();
    return testDone();
}
