/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERT_FACTORY_H
#define PVXS_CERT_FACTORY_H

#include <tuple>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/version.h>

#include "auth.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace security {

constexpr uint16_t kForClient = 0x01;
constexpr uint16_t kForServer = 0x02;
constexpr uint16_t kForIntermediateCa = 0x04;
constexpr uint16_t kForCMS = 0x08;
constexpr uint16_t kForCa = 0x10;

constexpr uint16_t kForClientAndServer = kForClient | kForServer;
constexpr uint16_t kAnyServer = kForCMS | kForServer;

#define IS_USED_FOR_(USED,USAGE) ((USED & (USAGE)) == USAGE)
#define IS_FOR_A_SERVER_(USED) ((USED & (kAnyServer)) != 0x00)

#define PVXS_DEFAULT_AUTH_TYPE "x509"

#define METHOD_STRING(type) \
    (((type).compare(PVXS_DEFAULT_AUTH_TYPE) == 0) ? "default credentials" : ((type) + " credentials"))
#define NAME_STRING(name, org) name + (org.empty() ? "" : ("@" + (org)))

/**
 * @class CertFactory
 *
 * @brief Manages certificates and associated operations.
 *
 * This class provides methods for creating certificates, creating key
 * pairs, and verifying certificates.
 *
 * 1. static CertFactory *getInstance():
 *   This is the singleton access method. It checks if an instance of
 *   CertFactory already exists; if not, it creates one and returns it.
 * 2. std::shared_ptr<KeyPair> createKeyPair():
 *   This method creates a key pair. The specifics of key pair creation
 *   are not visible in the selected code.
 * 3. void createPKCS12File(...):
 *  This method creates a PKCS#12 file using a certificate, and a key pair.
 * 4. bool isTlsConfigured():
 *  This method checks if the environment is configured for TLS by verifying
 *  whether the tls_keychain_filename in the configuration is not empty.
 * 5. GenStatus generateNewKeychainFile(...):
 *  This method creates a new keychain is called from the client or server
 *  and makes a call to the PVACMS to create a certificate.
 * 6. ossl_ptr<X509> create(...):
 *  Called from PVACMS, this method creates an X509 certificate. The
 * parameters provide the necessary information such as the key pair,
 * not-before and not-after dates, a flag indicating whether the certificate
 * is for a client, a server, or a Certificate Authority (CA), etc.
 */
class PVXS_API CertFactory {
   public:
    uint64_t serial_;
    const std::shared_ptr<KeyPair> key_pair_;
    const std::string name_;
    const std::string country_;
    const std::string org_;
    const std::string org_unit_;
    const time_t not_before_;
    const time_t not_after_;
    const uint16_t usage_;
    X509* issuer_certificate_ptr_; // Will point to the issuer certificate when created
    EVP_PKEY *issuer_pkey_ptr_;  // Will point to the issuer private key when created
    STACK_OF(X509) *issuer_chain_ptr_; // issuer cert chain
    const ossl_shared_ptr<STACK_OF(X509)> certificate_chain_; // Will contain the

    CertFactory(uint64_t serial, const std::shared_ptr<KeyPair> &key_pair, const std::string &name,
                const std::string &country, const std::string &org, const std::string &org_unit,
                time_t not_before, time_t not_after, const uint16_t &usage,
                X509 *issuer_certificate_ptr = nullptr, EVP_PKEY *issuer_pkey_ptr = nullptr,
                STACK_OF(X509) *issuer_chain_ptr = nullptr)
       : serial_(serial), key_pair_(key_pair), name_(name),
         country_(country), org_(org), org_unit_(org_unit),
         not_before_(not_before), not_after_(not_after), usage_(usage),
         issuer_certificate_ptr_(issuer_certificate_ptr),
         issuer_pkey_ptr_(issuer_pkey_ptr),
         issuer_chain_ptr_(issuer_chain_ptr),
         certificate_chain_(sk_X509_new_null()) {};

    ossl_ptr<X509> PVXS_API create();

    static std::string PVXS_API certAndCasToPemString(const ossl_ptr<X509> &cert, const STACK_OF(X509) * ca);

    static std::string getCertsDirectory();

    static bool PVXS_API verifySignature(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data, const std::string &signature);

    static std::string sign(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data);

    static inline std::string getError() {
        unsigned long err;
        std::string error_string;
        std::string sep;
        while ((err = ERR_get_error()))  // get all error codes from the error queue
        {
            char buffer[256];
            ERR_error_string_n(err, buffer, sizeof(buffer));
            error_string += sep + buffer;
            sep = ", ";
        }
        return error_string;
    }

  private:
    static inline const char * nid2String(int nid) {
        switch (nid) {
            case NID_subject_key_identifier:
                return LN_subject_key_identifier;
            case NID_key_usage:
                return LN_key_usage;
            case NID_basic_constraints:
                return LN_basic_constraints;
            case NID_authority_key_identifier:
                return LN_authority_key_identifier;
            case NID_ext_key_usage:
                return LN_ext_key_usage;
            default:
                return "unknown";
        }
    }

    static bool isSelfSigned(X509 *cert);

    void setSubject(const ossl_ptr<X509> &certificate);

    void setValidity(const ossl_ptr<X509> &certificate) const ;

    void setSerialNumber(const ossl_ptr<X509> &certificate);

    void addExtensions(const ossl_ptr<X509> &certificate);

    void addExtension(const ossl_ptr<X509> &certificate, int nid, const char *value,
                             const X509 *subject = nullptr);

    static void writeCertToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<X509> &cert);

    static void writeCertsToBio(const ossl_ptr<BIO> &bio, const STACK_OF(X509) * certs);

    static ossl_ptr<BIO> newBio();

    static std::string bioToString(const ossl_ptr<BIO> &bio);

    static void writeP12ToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<PKCS12> &p12, std::string password,
                              bool root_only = false);

    static std::string certAndP12ToPemString(const ossl_ptr<PKCS12> &p12, const ossl_ptr<X509> &new_cert,
                                             std::string password);

    static std::string p12ToPemString(ossl_ptr<PKCS12> &p12, std::string password);

    static std::string rootCertToString(ossl_ptr<PKCS12> &p12, std::string password);
};

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_CERT_FACTORY_H
