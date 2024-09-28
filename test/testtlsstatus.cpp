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
#include <pvxs/unittest.h>

#include "certfactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "openssl.h"
#include "ownedptr.h"

namespace {
using namespace pvxs;

#define STATUS_VALID_FOR_MINS 30
#define STATUS_VALID_FOR_SECS (STATUS_VALID_FOR_MINS * 60)
#define REVOKED_SINCE_MINS (60 * 12)
#define REVOKED_SINCE_SECS (REVOKED_SINCE_MINS * 60)

#define TEST_FIRST_SERIAL 9876543210

#define GET_MONITOR_CERT_STATUS_PV "CERT:STATUS:????????:*"

constexpr uint64_t ca_serial = TEST_FIRST_SERIAL;
constexpr uint64_t server_serial = ca_serial+3;
constexpr uint64_t client_serial = ca_serial+6;

#define CA_CERT_FILE "ca.p12"
// #define CA_CERT_FILE "/Users/george/.epics/certs/ca.p12"
#define CA_CERT_FILE_PWD ""
#define SERVER_CERT_FILE "server1.p12"
#define SERVER_CERT_FILE_PWD ""
#define CLIENT_CERT_FILE "client1.p12"
#define CLIENT_CERT_FILE_PWD ""

template <typename T>
void setValue(Value &target, const std::string &field, const T &source) {
    auto current = target[field];
    if (current.as<T>() == source) {
        target[field].unmark();  // Assuming unmark is a valid method for indicating no change needed
    } else {
        target[field] = source;
    }
}

struct TestCert {
    ossl_ptr<X509> cert;
    ossl_shared_ptr<STACK_OF(X509)> chain;
    ossl_ptr<EVP_PKEY> pkey;

    TestCert(ossl_ptr<X509> cert, ossl_shared_ptr<stack_st_X509> chain, ossl_ptr<EVP_PKEY> pkey)
        : cert(std::move(cert)), chain(std::move(chain)), pkey(std::move(pkey)) {}
};

TestCert getTestCerts(std::string filename, std::string password) {
    char buffer[PATH_MAX];
    getcwd(buffer, sizeof(buffer));

    testDiag("Opening %s certs file", filename.c_str());
    file_ptr fp(fopen(filename.c_str(), "rb"), false);
    if (!fp) {
        testFail("Error opening certs file for reading binary contents: %s", filename.c_str());
        return TestCert(nullptr, nullptr, nullptr);
    }

    testDiag("Opening %s certs file as a PKCS#12 object", filename.c_str());
    ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), NULL));
    if (!p12) {
        testFail("Error opening certs file as a PKCS#12 object: %s", filename.c_str());
        return TestCert(nullptr, nullptr, nullptr);
    }

    ossl_ptr<X509> cert;
    ossl_ptr<EVP_PKEY> pkey;
    ossl_shared_ptr<STACK_OF(X509)> chain;
    STACK_OF(X509) *chain_ptr = nullptr;
    testDiag("Parsing PKCS#12 object to get certificate, key and chain");
    if (!PKCS12_parse(p12.get(), password.c_str(), pkey.acquire(), cert.acquire(), &chain_ptr)) {
        testFail("Error Parsing PKCS#12 object: %s", filename.c_str());
        return TestCert(nullptr, nullptr, nullptr);
    }

    testTrue(cert.get());
    testTrue(pkey.get());

    if (!cert || !pkey) {
        testFail("Error loading certificate: %s", filename.c_str());
        return TestCert(nullptr, nullptr, nullptr);
    }

    if (chain_ptr) {
        chain = ossl_shared_ptr<STACK_OF(X509)>(chain_ptr);
        testDiag("Acquired %d element Certificate Chain from: %s", sk_X509_num(chain.get()), filename.c_str());
    } else {
        chain = ossl_shared_ptr<STACK_OF(X509)>(sk_X509_new_null());
    }

    if (filename == CA_CERT_FILE)
        testEq(sk_X509_num(chain.get()), 0);
    else
        testEq(sk_X509_num(chain.get()), 2);

    // Test issuer load
    X509_NAME *subject_name = X509_get_subject_name(cert.get());
    ossl_ptr<char> name(X509_NAME_oneline(subject_name, nullptr, 0), false);
    testTrue(name.get());
    testDiag("Subject of %s: %s", filename.c_str(), name.get());

    testOk(1, "Loaded certificate from: %s", filename.c_str());
    return TestCert(std::move(cert), std::move(chain), std::move(pkey));
}

struct Tester {
    // Pristine values
    const certs::StatusDate now;
    const certs::StatusDate status_valid_until_time;
    const certs::StatusDate revocation_date;
    const TestCert ca_cert;
    const TestCert server_cert;
    const TestCert client_cert;
    certs::CertificateStatus ca_cert_status;
    certs::CertificateStatus server_cert_status;
    certs::CertificateStatus client_cert_status;
    const Value status_value_prototype{certs::CertStatus::getStatusPrototype()};
    Value client_status_response_value{status_value_prototype.cloneEmpty()};
    Value server_status_response_value{status_value_prototype.cloneEmpty()};
    Value ca_status_response_value{status_value_prototype.cloneEmpty()};
    std::string client_status_pv_name;
    std::string server_status_pv_name;
    std::string ca_status_pv_name;
    server::SharedWildcardPV status_pv{server::SharedWildcardPV::buildMailbox()};
    server::Server pvacms{server::Config::isolated().build().addPV(GET_MONITOR_CERT_STATUS_PV, status_pv)};
    client::Context client{pvacms.clientConfig().build()};
    bool monitor_test{false};

    Tester()
        : now(time(nullptr)),
          status_valid_until_time(now.t + STATUS_VALID_FOR_SECS),
          revocation_date(now.t - REVOKED_SINCE_SECS),
          ca_cert(getTestCerts(CA_CERT_FILE, CA_CERT_FILE_PWD)),
          server_cert(getTestCerts(SERVER_CERT_FILE, SERVER_CERT_FILE_PWD)),
          client_cert(getTestCerts(CLIENT_CERT_FILE, CLIENT_CERT_FILE_PWD)) {
        if (!ca_cert.cert || !ca_cert.pkey || !server_cert.cert || !server_cert.pkey || !client_cert.cert || !client_cert.pkey) {
            testFail("Error loading one or more certificates");
            return;
        }
        testShow() << "Testing TLS Status Functions:\n";
    }

    ~Tester() = default;

    void initialisation() {
        testShow() << __func__;
        testEq(now.t, status_valid_until_time.t - STATUS_VALID_FOR_SECS);
        testEq(now.t, revocation_date.t + REVOKED_SINCE_SECS);
    }

    void ocspPayload() {
        testShow() << __func__;
        try {
            auto ca_cert_status_creator(certs::CertStatusFactory(ca_cert.cert, ca_cert.pkey, ca_cert.chain, STATUS_VALID_FOR_MINS));
            auto server_cert_status_creator(certs::CertStatusFactory(server_cert.cert, server_cert.pkey, server_cert.chain, STATUS_VALID_FOR_MINS));
            auto client_cert_status_creator(certs::CertStatusFactory(client_cert.cert, client_cert.pkey, client_cert.chain, STATUS_VALID_FOR_MINS));

            try {
                testDiag("Creating OCSP REVOKED status from: %s", "Client certificate");
                client_cert_status = client_cert_status_creator.createOCSPStatus(client_cert.cert, certs::REVOKED, now, revocation_date);
                testOk(1, "Created OCSP REVOKED status from: %s", "Client certificate");
            } catch (std::exception &e) {
                testFail("Failed to create REVOKED status: %s\n", e.what());
            }

            try {
                testDiag("Creating OCSP PENDING status from: %s", "Server certificate");
                server_cert_status = server_cert_status_creator.createOCSPStatus(server_cert.cert, certs::PENDING, now);
                testOk(1, "Created OCSP PENDING status from: %s", "Server certificate");
            } catch (std::exception &e) {
                testFail("Failed to create PENDING status: %s\n", e.what());
            }
            try {
                testDiag("Creating OCSP VALID status from: %s", "CA certificate");
                ca_cert_status = ca_cert_status_creator.createOCSPStatus(ca_cert.cert, certs::VALID, now);
                testOk(1, "Created OCSP VALID status from: %s", "CA certificate");
            } catch (std::exception &e) {
                testFail("Failed to create VALID status: %s\n", e.what());
            }
        } catch (std::exception &e) {
            testFail("Failed to read certificate in from file: %s\n", e.what());
        }
    }

    void parse() {
        testShow() << __func__;
        try {
            testDiag("Parsing OCSP Response: %s", "Client certificate");
            auto parsed_response = certs::CertStatusManager::parse(client_cert_status.ocsp_bytes);
            testDiag("Parsed OCSP Response: %s", "Client certificate");

            testEq(parsed_response.serial, client_serial);
            testEq(parsed_response.ocsp_status.i, certs::OCSP_CERTSTATUS_REVOKED);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, revocation_date.t);
        } catch (std::exception &e) {
            testFail("Failed to parse Client OCSP response: %s", e.what());
        }

        testShow() << __func__;
        try {
            testDiag("Parsing OCSP Response: %s", "Server certificate");
            auto parsed_response = certs::CertStatusManager::parse(server_cert_status.ocsp_bytes);
            testDiag("Parsed OCSP Response: %s", "Server certificate");

            testEq(parsed_response.serial, server_serial);
            testEq(parsed_response.ocsp_status.i, certs::OCSP_CERTSTATUS_UNKNOWN);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse Server OCSP response: %s", e.what());
        }

        testShow() << __func__;
        try {
            testDiag("Parsing OCSP Response: %s", "CA certificate");
            auto parsed_response = certs::CertStatusManager::parse(ca_cert_status.ocsp_bytes);
            testDiag("Parsed OCSP Response: %s", "CA certificate");

            testEq(parsed_response.serial, ca_serial);
            testEq(parsed_response.ocsp_status.i, certs::OCSP_CERTSTATUS_GOOD);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse CA OCSP response: %s", e.what());
        }
    }

    void response() {
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Client Certificate Response");
            client_status_response_value = certs::CertStatus::getStatusPrototype();
            setValue<uint64_t>(client_status_response_value, "serial", client_serial);
            setValue<uint32_t>(client_status_response_value, "status.value.index", client_cert_status.status.i);
            setValue<time_t>(client_status_response_value, "status.timeStamp.secondsPastEpoch", time(nullptr));
            setValue<std::string>(client_status_response_value, "state", client_cert_status.status.s);
            setValue<uint32_t>(client_status_response_value, "ocsp_status.value.index", client_cert_status.ocsp_status.i);
            setValue<time_t>(client_status_response_value, "ocsp_status.timeStamp.secondsPastEpoch", time(nullptr));
            setValue<std::string>(client_status_response_value, "ocsp_state", SB() << "**UNCERTIFIED**: " << client_cert_status.ocsp_status.s);

            if (!client_cert_status.ocsp_bytes.empty()) {
                setValue<uint32_t>(client_status_response_value, "ocsp_status.value.index", client_cert_status.ocsp_status.i);
                setValue<std::string>(client_status_response_value, "ocsp_state", client_cert_status.ocsp_status.s);
                setValue<std::string>(client_status_response_value, "ocsp_status_date", client_cert_status.status_date.s);
                setValue<std::string>(client_status_response_value, "ocsp_certified_until", client_cert_status.status_valid_until_date.s);
                setValue<std::string>(client_status_response_value, "ocsp_revocation_date", client_cert_status.revocation_date.s);
                auto ocsp_bytes = shared_array<const uint8_t>(client_cert_status.ocsp_bytes.begin(), client_cert_status.ocsp_bytes.end());
                client_status_response_value["ocsp_response"] = ocsp_bytes.freeze();
            }
            testDiag("Set up: %s", "Client certificate Status Response");

            // We're not testing the wire at this point so we assume we get the same value that we sent so just test that status is correctly transferred
            auto received_client_status = certs::CertificateStatus(client_status_response_value);
            testOk1(received_client_status == client_cert_status);
            testEq(received_client_status.ocsp_bytes.size(), client_cert_status.ocsp_bytes.size());
        } catch (std::exception &e) {
            testFail("Failed to setup Client status response: %s", e.what());
        }

        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Server Certificate Status Response");
            server_status_response_value = certs::CertStatus::getStatusPrototype();
            setValue<uint64_t>(server_status_response_value, "serial", server_serial);
            setValue<uint32_t>(server_status_response_value, "status.value.index", server_cert_status.status.i);
            setValue<time_t>(server_status_response_value, "status.timeStamp.secondsPastEpoch", time(nullptr));
            setValue<std::string>(server_status_response_value, "state", server_cert_status.status.s);
            setValue<uint32_t>(server_status_response_value, "ocsp_status.value.index", server_cert_status.ocsp_status.i);
            setValue<time_t>(server_status_response_value, "ocsp_status.timeStamp.secondsPastEpoch", time(nullptr));
            setValue<std::string>(server_status_response_value, "ocsp_state", SB() << "**UNCERTIFIED**: " << server_cert_status.ocsp_status.s);

            if (!server_cert_status.ocsp_bytes.empty()) {
                setValue<uint32_t>(server_status_response_value, "ocsp_status.value.index", server_cert_status.ocsp_status.i);
                setValue<std::string>(server_status_response_value, "ocsp_state", server_cert_status.ocsp_status.s);
                setValue<std::string>(server_status_response_value, "ocsp_status_date", server_cert_status.status_date.s);
                setValue<std::string>(server_status_response_value, "ocsp_certified_until", server_cert_status.status_valid_until_date.s);
                setValue<std::string>(server_status_response_value, "ocsp_revocation_date", server_cert_status.revocation_date.s);
                auto ocsp_bytes = shared_array<const uint8_t>(server_cert_status.ocsp_bytes.begin(), server_cert_status.ocsp_bytes.end());
                server_status_response_value["ocsp_response"] = ocsp_bytes.freeze();
            }
            testDiag("Set up: %s", "Server certificate Status Response");

            auto received_server_status = certs::CertificateStatus(server_status_response_value);
            testOk1(received_server_status == server_cert_status);
            testEq(received_server_status.ocsp_bytes.size(), server_cert_status.ocsp_bytes.size());
        } catch (std::exception &e) {
            testFail("Failed to setup Server status response: %s", e.what());
        }

        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "CA Certificate Status Response");
            ca_status_response_value = certs::CertStatus::getStatusPrototype();
            setValue<uint64_t>(ca_status_response_value, "serial", ca_serial);
            setValue<uint32_t>(ca_status_response_value, "status.value.index", ca_cert_status.status.i);
            setValue<time_t>(ca_status_response_value, "status.timeStamp.secondsPastEpoch", time(nullptr));
            setValue<std::string>(ca_status_response_value, "state", ca_cert_status.status.s);
            setValue<uint32_t>(ca_status_response_value, "ocsp_status.value.index", ca_cert_status.ocsp_status.i);
            setValue<time_t>(ca_status_response_value, "ocsp_status.timeStamp.secondsPastEpoch", time(nullptr));
            setValue<std::string>(ca_status_response_value, "ocsp_state", SB() << "**UNCERTIFIED**: " << ca_cert_status.ocsp_status.s);

            if (!ca_cert_status.ocsp_bytes.empty()) {
                setValue<uint32_t>(ca_status_response_value, "ocsp_status.value.index", ca_cert_status.ocsp_status.i);
                setValue<std::string>(ca_status_response_value, "ocsp_state", ca_cert_status.ocsp_status.s);
                setValue<std::string>(ca_status_response_value, "ocsp_status_date", ca_cert_status.status_date.s);
                setValue<std::string>(ca_status_response_value, "ocsp_certified_until", ca_cert_status.status_valid_until_date.s);
                setValue<std::string>(ca_status_response_value, "ocsp_revocation_date", ca_cert_status.revocation_date.s);
                auto ocsp_bytes = shared_array<const uint8_t>(ca_cert_status.ocsp_bytes.begin(), ca_cert_status.ocsp_bytes.end());
                ca_status_response_value["ocsp_response"] = ocsp_bytes.freeze();
            }
            testDiag("Set up: %s", "CA certificate Status Response");

            auto received_ca_status = certs::CertificateStatus(ca_status_response_value);
            testOk1(received_ca_status == ca_cert_status);
            testEq(received_ca_status.ocsp_bytes.size(), ca_cert_status.ocsp_bytes.size());
        } catch (std::exception &e) {
            testFail("Failed to setup CA status response: %s", e.what());
        }
    }

    void request() {
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Mock PVACMS Server");
            client_status_pv_name = certs::CertStatusManager::getStatusPvFromCert(client_cert.cert);
            server_status_pv_name = certs::CertStatusManager::getStatusPvFromCert(server_cert.cert);
            ca_status_pv_name = certs::CertStatusManager::getStatusPvFromCert(ca_cert.cert);
            status_pv.onFirstConnect([=](server::SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
                auto it = parameters.begin();
                const std::string &issuer_id = *it;
                const std::string &serial_string = *++it;
                uint64_t serial = std::stoull(serial_string);

                testOk(1, "Status Request for: issuer %s, serial %s", issuer_id.c_str(), serial_string.c_str() );
                Value value_to_post;
                switch (serial) {
                    case client_serial: value_to_post = client_status_response_value; break;
                    case server_serial: value_to_post = server_status_response_value; break;
                    case ca_serial:     value_to_post = ca_status_response_value;     break;
                    default:testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());
                }
                if ( value_to_post ) {
                    // Set initial value if not open
                    auto open = status_pv.isOpen(pv_name);
                    if (!open) {
                        status_pv.open(pv_name, value_to_post.cloneEmpty());
                    }
                    status_pv.post(pv_name, value_to_post);

                    // If not a monitor test then close it if it was closed to begin with
                    if (!open && !monitor_test) {
//                        status_pv.close(pv_name);
                    }
                    testDiag("Posted Value for request: %s", pv_name.c_str());
                }
            });
            status_pv.onLastDisconnect([](server::SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
                testOk(1, "Closing Status Request Connection: %s", pv_name.c_str() );
                pv.close(pv_name);
            });

            pvacms.start();

            testDiag("Set up: %s", "Mock PVACMS Server");

            try {
                testDiag("Sending: %s", "Client Status Request");
                auto result = client.get(client_status_pv_name).exec()->wait(5.0);
                auto client_status_response = certs::CertificateStatus(result);
                testOk1(client_status_response == client_cert_status);
                testDiag("Successfully Received: %s", "Client Status Response");
            } catch (std::exception &e) {
                testFail("Failed to send Client Status Request: %s", e.what());
            }

            testShow() << __func__;
            try {
                testDiag("Sending: %s", "Server Status Request");
                auto result = client.get(server_status_pv_name).exec()->wait(5.0);
                auto server_status_response = certs::CertificateStatus(result);
                testOk1(server_status_response == server_cert_status);
                testDiag("Successfully Received: %s", "Server Status Response");
            } catch (std::exception &e) {
                testFail("Failed to send Server Status Request: %s", e.what());
            }

            testShow() << __func__;
            try {
                testDiag("Sending: %s", "CA Status Request");
                auto result = client.get(ca_status_pv_name).exec()->wait(5.0);
                auto ca_status_response = certs::CertificateStatus(result);
                testOk1(ca_status_response == ca_cert_status);
                testDiag("Successfully Received: %s", "CA Status Response");
            } catch (std::exception &e) {
                testFail("Failed to send CA Status Request: %s", e.what());
            }

            testDiag("Stop Mock PVACMS server");
            pvacms.stop();
        } catch (std::exception &e) {
            testFail("Failed to set up Mock PVACMS Server: %s", e.what());
        }
    }

    void certificateStatus() { testShow() << __func__; }
};

}  // namespace

MAIN(testget) {
    // Initialize SSL
    pvxs::ossl::SSLContext::sslInit();

    testPlan(50);
    testSetup();
    logger_config_env();
    auto tester = new Tester() ;
    tester->initialisation();
    tester->ocspPayload();
    tester->certificateStatus();
    tester->parse();
    tester->response();
    tester->request();
    delete(tester);
    cleanup_for_valgrind();
    return testDone();
}
