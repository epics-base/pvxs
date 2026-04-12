/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>
#include <pvxs/source.h>

#ifdef PVXS_ENABLE_OPENSSL
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  include <openssl/evp.h>
#  include <openssl/asn1.h>
#  include "openssl.h"
#endif

namespace {
using namespace pvxs;

void testSanEntryBasics()
{
    testShow()<<__func__;

    SanEntry entry;
    testOk(entry.type.empty(), "default SanEntry type is empty");
    testOk(entry.value.empty(), "default SanEntry value is empty");

    SanEntry ip{"ip", "10.0.0.1"};
    testEq(ip.type, "ip");
    testEq(ip.value, "10.0.0.1");

    SanEntry dns{"dns", "host.example.com"};
    testEq(dns.type, "dns");
    testEq(dns.value, "host.example.com");

    SanEntry copy(ip);
    testEq(copy.type, "ip");
    testEq(copy.value, "10.0.0.1");
}

void testPeerCredentialsSanDefault()
{
    testShow()<<__func__;

    PeerCredentials cred;
    testOk(cred.san.empty(), "PeerCredentials::san defaults to empty");
}

void testOperatorStreamWithSans()
{
    testShow()<<__func__;

    PeerCredentials cred;
    cred.method = "x509";
    cred.account = "testuser";
    cred.peer = "192.168.1.1:5076";

    {
        std::ostringstream strm;
        strm << cred;
        std::string out = strm.str();
        testOk(out.find("SAN:") == std::string::npos,
               "no SAN in output when san is empty: %s", out.c_str());
    }

    cred.san.push_back(SanEntry{"ip", "10.0.0.1"});
    cred.san.push_back(SanEntry{"dns", "host.example.com"});

    {
        std::ostringstream strm;
        strm << cred;
        std::string out = strm.str();
        testOk(out.find("SAN:") != std::string::npos,
               "SAN: present in output: %s", out.c_str());
        testOk(out.find("ip=10.0.0.1") != std::string::npos,
               "ip SAN in output: %s", out.c_str());
        testOk(out.find("dns=host.example.com") != std::string::npos,
               "dns SAN in output: %s", out.c_str());
    }
}

#ifdef PVXS_ENABLE_OPENSSL

X509* makeTestCert(EVP_PKEY* key, const std::vector<SanEntry>& sans)
{
    X509* cert = X509_new();
    if(!cert) throw std::runtime_error("X509_new failed");

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365*24*60*60);
    X509_set_pubkey(cert, key);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("TestCN"), -1, -1, 0);
    X509_set_issuer_name(cert, name);

    if(!sans.empty()) {
        GENERAL_NAMES* gnames = sk_GENERAL_NAME_new_null();
        for(const auto& san : sans) {
            GENERAL_NAME* gn = GENERAL_NAME_new();
            if(san.type == "ip") {
                ASN1_OCTET_STRING* ip = a2i_IPADDRESS(san.value.c_str());
                if(ip) {
                    GENERAL_NAME_set0_value(gn, GEN_IPADD, ip);
                } else {
                    GENERAL_NAME_free(gn);
                    continue;
                }
            } else if(san.type == "dns") {
                ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
                ASN1_STRING_set(ia5, san.value.c_str(), static_cast<int>(san.value.size()));
                GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
            } else if(san.type == "email") {
                ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
                ASN1_STRING_set(ia5, san.value.c_str(), static_cast<int>(san.value.size()));
                GENERAL_NAME_set0_value(gn, GEN_EMAIL, ia5);
            } else {
                GENERAL_NAME_free(gn);
                continue;
            }
            sk_GENERAL_NAME_push(gnames, gn);
        }
        X509_add1_ext_i2d(cert, NID_subject_alt_name, gnames, 0, 0);
        GENERAL_NAMES_free(gnames);
    }

    X509_sign(cert, key, EVP_sha256());
    return cert;
}

// Note: extractSansFromCert() duplicates the SAN extraction algorithm from
// SSLContext::getPeerCredentials() in openssl.cpp.  This tests the extraction
// logic (OpenSSL API usage, IP formatting, DNS lowercasing) in isolation,
// without requiring a live SSL context.  It does NOT test the production
// integration path — that is covered by the TLS integration tests.
EVP_PKEY* makeTestKey()
{
    EVP_PKEY* key = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if(!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    if(!key) throw std::runtime_error("keygen failed");
    return key;
}

PeerCredentials extractSansFromCert(X509* cert)
{
    PeerCredentials cred;

    auto* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if(names) {
        const int count = sk_GENERAL_NAME_num(names);
        for(int i = 0; i < count; i++) {
            const GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;

            if(entry->type == GEN_IPADD) {
                const auto* data = entry->d.ip;
                if(!data) continue;
                char buf[INET6_ADDRSTRLEN];
                const char* result = nullptr;
                if(data->length == 4) {
                    result = evutil_inet_ntop(AF_INET, data->data, buf, sizeof(buf));
                } else if(data->length == 16) {
                    result = evutil_inet_ntop(AF_INET6, data->data, buf, sizeof(buf));
                }
                if(result) {
                    cred.san.push_back(SanEntry{"ip", result});
                }
            } else if(entry->type == GEN_DNS) {
                const auto* data = entry->d.dNSName;
                if(!data || !data->data || data->length <= 0) continue;
                std::string dns(reinterpret_cast<const char*>(data->data),
                                static_cast<size_t>(data->length));
                std::transform(dns.begin(), dns.end(), dns.begin(),
                               [](unsigned char c){ return std::tolower(c); });
                cred.san.push_back(SanEntry{"dns", std::move(dns)});
            }
        }
        GENERAL_NAMES_free(names);
    }
    return cred;
}

void testSanExtractionIPandDNS()
{
    testShow()<<__func__;

    EVP_PKEY* key = makeTestKey();
    std::vector<SanEntry> sans = {
        {"ip", "10.0.0.1"},
        {"dns", "host.example.com"},
    };
    X509* cert = makeTestCert(key, sans);

    auto cred = extractSansFromCert(cert);

    X509_free(cert);
    EVP_PKEY_free(key);

    testEq(cred.san.size(), 2u);
    if(cred.san.size() >= 2) {
        testEq(cred.san[0].type, "ip");
        testEq(cred.san[0].value, "10.0.0.1");
        testEq(cred.san[1].type, "dns");
        testEq(cred.san[1].value, "host.example.com");
    } else {
        testSkip(4, "not enough SAN entries extracted");
    }
}

void testSanExtractionIPv6()
{
    testShow()<<__func__;

    EVP_PKEY* key = makeTestKey();
    std::vector<SanEntry> sans = {
        {"ip", "2001:db8::1"},
    };
    X509* cert = makeTestCert(key, sans);

    auto cred = extractSansFromCert(cert);

    X509_free(cert);
    EVP_PKEY_free(key);

    testEq(cred.san.size(), 1u);
    if(cred.san.size() >= 1) {
        testEq(cred.san[0].type, "ip");
        testEq(cred.san[0].value, "2001:db8::1");
    } else {
        testSkip(2, "no SAN entries extracted");
    }
}

void testSanExtractionNoSans()
{
    testShow()<<__func__;

    EVP_PKEY* key = makeTestKey();
    X509* cert = makeTestCert(key, {});

    auto cred = extractSansFromCert(cert);

    X509_free(cert);
    EVP_PKEY_free(key);

    testOk(cred.san.empty(), "no SANs extracted from cert without SAN extension");
}

void testSanExtractionSkipsUnsupported()
{
    testShow()<<__func__;

    EVP_PKEY* key = makeTestKey();
    std::vector<SanEntry> sans = {
        {"ip", "10.0.0.1"},
        {"email", "test@example.com"},
        {"dns", "host.example.com"},
    };
    X509* cert = makeTestCert(key, sans);

    auto cred = extractSansFromCert(cert);

    X509_free(cert);
    EVP_PKEY_free(key);

    testEq(cred.san.size(), 2u);
    if(cred.san.size() >= 2) {
        testEq(cred.san[0].type, "ip");
        testEq(cred.san[1].type, "dns");
    } else {
        testSkip(2, "unexpected SAN count");
    }
}

void testSanDNSLowercased()
{
    testShow()<<__func__;

    EVP_PKEY* key = makeTestKey();
    std::vector<SanEntry> sans = {
        {"dns", "IOC01.SLAC.Stanford.EDU"},
    };
    X509* cert = makeTestCert(key, sans);

    auto cred = extractSansFromCert(cert);

    X509_free(cert);
    EVP_PKEY_free(key);

    testEq(cred.san.size(), 1u);
    if(cred.san.size() >= 1) {
        testEq(cred.san[0].value, "ioc01.slac.stanford.edu");
    } else {
        testSkip(1, "no SAN entries extracted");
    }
}

void testSanIPCanonicalForm()
{
    testShow()<<__func__;

    EVP_PKEY* key = makeTestKey();
    std::vector<SanEntry> sans = {
        {"ip", "10.0.0.1"},
        {"ip", "2001:db8::1"},
    };
    X509* cert = makeTestCert(key, sans);

    auto cred = extractSansFromCert(cert);

    X509_free(cert);
    EVP_PKEY_free(key);

    testEq(cred.san.size(), 2u);
    if(cred.san.size() >= 2) {
        testEq(cred.san[0].value, "10.0.0.1");
        testEq(cred.san[1].value, "2001:db8::1");
    } else {
        testSkip(2, "not enough SAN entries extracted");
    }
}

#endif // PVXS_ENABLE_OPENSSL

}

MAIN(testsan)
{
#ifdef PVXS_ENABLE_OPENSSL
    testPlan(30);
#else
    testPlan(13);
#endif
    testSetup();
    testSanEntryBasics();
    testPeerCredentialsSanDefault();
    testOperatorStreamWithSans();
#ifdef PVXS_ENABLE_OPENSSL
    testSanExtractionIPandDNS();
    testSanExtractionIPv6();
    testSanExtractionNoSans();
    testSanExtractionSkipsUnsupported();
    testSanDNSLowercased();
    testSanIPCanonicalForm();
#endif
    return testDone();
}
