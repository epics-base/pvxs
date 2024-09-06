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
#include <pvxs/unittest.h>

#include "certfactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "ownedptr.h"

namespace {
using namespace pvxs;

#define STATUS_VALID_FOR_MINS 30
#define STATUS_VALID_FOR_SECS (STATUS_VALID_FOR_MINS * 60)
#define REVOKED_SINCE_MINS (60 * 12)
#define REVOKED_SINCE_SECS (REVOKED_SINCE_MINS * 60)

#define CA_CERT_FILE "ca.p12"
// #define CA_CERT_FILE "/Users/george/.epics/certs/ca.p12"
#define CA_CERT_FILE_PWD ""
#define SERVER_CERT_FILE "server1.p12"
#define SERVER_CERT_FILE_PWD ""
#define CLIENT_CERT_FILE "client1.p12"
#define CLIENT_CERT_FILE_PWD ""

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
                client_cert_status = client_cert_status_creator.createOCSPStatus(3, certs::REVOKED, now, revocation_date);
                testOk(1, "Created OCSP REVOKED status from: %s", "Client certificate");
            } catch (std::exception &e) {
                testFail("Failed to create REVOKED status: %s\n", e.what());
            }

            try {
                testDiag("Creating OCSP PENDING status from: %s", "Server certificate");
                server_cert_status = server_cert_status_creator.createOCSPStatus(1, certs::PENDING, now);
                testOk(1, "Created OCSP PENDING status from: %s", "Server certificate");
            } catch (std::exception &e) {
                testFail("Failed to create PENDING status: %s\n", e.what());
            }
            try {
                testDiag("Creating OCSP VALID status from: %s", "CA certificate");
                ca_cert_status = ca_cert_status_creator.createOCSPStatus(0, certs::VALID, now);
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

            testEq(parsed_response.ocsp_status.i, certs::OCSP_CERTSTATUS_GOOD);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse CA OCSP response: %s", e.what());
        }
    }

    void certificateStatus() { testShow() << __func__; }
};

}  // namespace

MAIN(testget) {
    testPlan(32);
    testSetup();
    logger_config_env();
    Tester tester;
    tester.initialisation();
    tester.ocspPayload();
    tester.certificateStatus();
    tester.parse();
    cleanup_for_valgrind();
    return testDone();
}
