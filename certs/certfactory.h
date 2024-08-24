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

#include "certstatus.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

#define PVXS_DEFAULT_AUTH_TYPE "x509"

#define METHOD_STRING(type) (((type).compare(PVXS_DEFAULT_AUTH_TYPE) == 0) ? "default credentials" : ((type) + " credentials"))
#define NAME_STRING(name, org) name + (org.empty() ? "" : ("@" + (org)))

/**
 * @class CertFactory
 *
 * @brief Manages certificates and associated operations.
 *
 * This class provides methods for creating certificates, creating key
 * pairs, and verifying certificates.
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
    X509 *issuer_certificate_ptr_;       // Will point to the issuer certificate when created
    EVP_PKEY *issuer_pkey_ptr_;          // Will point to the issuer private key when created
    STACK_OF(X509) * issuer_chain_ptr_;  // issuer cert chain
    const ossl_shared_ptr<STACK_OF(X509)> certificate_chain_;
    bool cert_status_subscription_required_;
    std::string skid_;
    certstatus_t initial_status_;

    static int NID_PvaCertStatusURI;

    CertFactory(uint64_t serial, const std::shared_ptr<KeyPair> &key_pair, const std::string &name, const std::string &country, const std::string &org,
                const std::string &org_unit, time_t not_before, time_t not_after, const uint16_t &usage, bool cert_status_subscription_required = false,
                X509 *issuer_certificate_ptr = nullptr, EVP_PKEY *issuer_pkey_ptr = nullptr, stack_st_X509 *issuer_chain_ptr = nullptr,
                certstatus_t initial_status = VALID)
        : serial_(serial),
          key_pair_(key_pair),
          name_(name),
          country_(country),
          org_(org),
          org_unit_(org_unit),
          not_before_(not_before),
          not_after_(not_after),
          usage_(usage),
          issuer_certificate_ptr_(issuer_certificate_ptr),
          issuer_pkey_ptr_(issuer_pkey_ptr),
          issuer_chain_ptr_(issuer_chain_ptr),
          certificate_chain_(sk_X509_new_null()),
          initial_status_(initial_status) {
        cert_status_subscription_required_ = cert_status_subscription_required;
    };

    ossl_ptr<X509> PVXS_API create();

    static std::string PVXS_API certAndCasToPemString(const ossl_ptr<X509> &cert, const STACK_OF(X509) * ca);

    static std::string getCertsDirectory();

    //    static bool PVXS_API verifySignature(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data, const std::string &signature);

    //    static std::string sign(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data);

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

    static std::string bioToString(const ossl_ptr<BIO> &bio);

  private:
    static inline const char *nid2String(int nid) {
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

    void setValidity(const ossl_ptr<X509> &certificate) const;

    void setSerialNumber(const ossl_ptr<X509> &certificate);

    void addExtensions(const ossl_ptr<X509> &certificate);

    void addExtension(const ossl_ptr<X509> &certificate, int nid, const char *value, const X509 *subject = nullptr);

    void addCustomExtensionByNid(const ossl_ptr<X509> &certificate, int nid, std::string value);

    static void writeCertToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<X509> &cert);

    static void writeCertsToBio(const ossl_ptr<BIO> &bio, const STACK_OF(X509) * certs);

    static ossl_ptr<BIO> newBio();

    static void writeP12ToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<PKCS12> &p12, std::string password, bool root_only = false);

    static std::string certAndP12ToPemString(const ossl_ptr<PKCS12> &p12, const ossl_ptr<X509> &new_cert, std::string password);

    static std::string p12ToPemString(ossl_ptr<PKCS12> &p12, std::string password);

    static std::string rootCertToString(ossl_ptr<PKCS12> &p12, std::string password);

    void set_skid(ossl_ptr<X509> &certificate);
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERT_FACTORY_H
