/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERT_FACTORY_H
#define PVXS_CERT_FACTORY_H

#include <tuple>

#include <certfilefactory.h>

#include <openssl/err.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/version.h>

#include "certstatus.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

#define PVXS_DEFAULT_AUTH_TYPE "std"

#define METHOD_STRING(type) ((type) + " credentials"))
#define NAME_STRING(name, org) name + (org.empty() ? "" : ("@" + (org)))

/**
 * @brief Enum to control whether certificates require status subscription
 */
enum CertStatusSubscription {
    DEFAULT=-1,  // Use the no_status flag from the client request
    YES=1,       // Always require status subscription
    NO=0         // Never require status subscription
};

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
    time_t renew_by_{0};
    const uint16_t usage_;
    std::string cert_pv_prefix_ ;
    X509 *issuer_certificate_ptr_;       // Will point to the issuer certificate when created
    EVP_PKEY *issuer_pkey_ptr_;          // Will point to the issuer private key when created
    STACK_OF(X509) * issuer_chain_ptr_;  // issuer cert chain
    const ossl_shared_ptr<STACK_OF(X509)> certificate_chain_;
    CertStatusSubscription cert_status_subscription_required_;
    bool no_status_;
    std::string cert_config_uri_base_;
    std::string skid_;
    certstatus_t initial_status_;
    bool allow_duplicates_{true};

    /**
     * @brief Constructor for CertFactory
     *
     * @param serial the serial number
     * @param key_pair the key pair
     * @param name the name
     * @param country the country
     * @param org the organization
     * @param org_unit the organizational unit
     * @param not_before the not-before time
     * @param not_after the not-after time
     * @param renew_by the renew-by date if specified
     * @param usage the usage
     * @param cert_pv_prefix the certificate management PV prefix for this factory
     * @param cert_status_subscription_required whether certificate status subscription is required
     * @param no_status whether to disable the status subscription for this certificate
     * @param allow_duplicates will duplicate subject names be allowed?
     * @param issuer_certificate_ptr the issuer certificate
     * @param issuer_pkey_ptr the issuer private key
     * @param issuer_chain_ptr the issuer certificate chain
     * @param initial_status the initial status
     */
    CertFactory(const uint64_t serial, const std::shared_ptr<KeyPair> &key_pair, const std::string &name, const std::string &country, const std::string &org,
                const std::string &org_unit, const time_t not_before, const time_t not_after, const time_t renew_by, const uint16_t &usage,
                const std::string &cert_pv_prefix, const CertStatusSubscription cert_status_subscription_required = DEFAULT, const bool no_status = false, const bool allow_duplicates = false,
                X509 *issuer_certificate_ptr = nullptr, EVP_PKEY *issuer_pkey_ptr = nullptr,
                STACK_OF(X509) *issuer_chain_ptr = nullptr, certstatus_t initial_status = VALID)
        : serial_(serial),
          key_pair_(key_pair),
          name_(name),
          country_(country),
          org_(org),
          org_unit_(org_unit),
          not_before_(not_before),
          not_after_(not_after),
          renew_by_(renew_by),
          usage_(usage),
          cert_pv_prefix_(cert_pv_prefix),
          issuer_certificate_ptr_(issuer_certificate_ptr),
          issuer_pkey_ptr_(issuer_pkey_ptr),
          issuer_chain_ptr_(issuer_chain_ptr),
          certificate_chain_(sk_X509_new_null()),
          cert_status_subscription_required_(cert_status_subscription_required),
          no_status_(no_status),
          initial_status_(initial_status),
          allow_duplicates_(allow_duplicates) {}

    /**
     * @brief Constructor for CertFactory
     *
     * @param serial the serial number
     * @param key_pair the key pair
     * @param name the name
     * @param country the country
     * @param org the organization
     * @param org_unit the organizational unit
     * @param not_before the not before time
     * @param not_after the not after time
     * @param renew_by the renew by date if specified
     * @param usage the usage
     * @param cert_pv_prefix the certificate management PV prefix for this factory
     * @param cert_config_uri_base the configuration uri base, normally empty but if non-empty will result in the config uri extension being added to the
     * certificate
     * @param cert_status_subscription_required whether certificate status subscription is required
     * @param no_status whether to disable status subscription for this certificate
     * @param allow_duplicates will duplicate subject names be allowed
     * @param issuer_certificate_ptr the issuer certificate
     * @param issuer_pkey_ptr the issuer private key
     * @param issuer_chain_ptr the issuer certificate chain
     * @param initial_status the initial status
     * @param issuer_certificate_ptr the issuer certificate optional
     * @param issuer_pkey_ptr the issuer private key optional
     * @param issuer_chain_ptr the issuer certificate chain optional
     * @param initial_status the initial status - defaults to VALID
     */
    CertFactory(const uint64_t serial, const std::shared_ptr<KeyPair> &key_pair, const std::string &name, const std::string &country, const std::string &org,
                const std::string &org_unit, const time_t not_before, const time_t not_after, const time_t renew_by, const uint16_t &usage, const std::string &cert_pv_prefix, const std::string &cert_config_uri_base,
                const CertStatusSubscription cert_status_subscription_required = DEFAULT, const bool no_status = false, const bool allow_duplicates = false, X509 *issuer_certificate_ptr = nullptr, EVP_PKEY *issuer_pkey_ptr = nullptr,
                STACK_OF(X509) *issuer_chain_ptr = nullptr, const certstatus_t initial_status = VALID)
        : serial_(serial),
          key_pair_(key_pair),
          name_(name),
          country_(country),
          org_(org),
          org_unit_(org_unit),
          not_before_(not_before),
          not_after_(not_after),
          renew_by_(renew_by),
          usage_(usage),
          cert_pv_prefix_(cert_pv_prefix),
          issuer_certificate_ptr_(issuer_certificate_ptr),
          issuer_pkey_ptr_(issuer_pkey_ptr),
          issuer_chain_ptr_(issuer_chain_ptr),
          certificate_chain_(sk_X509_new_null()),
          cert_status_subscription_required_(cert_status_subscription_required),
          no_status_(no_status),
          cert_config_uri_base_(cert_config_uri_base),
          initial_status_(initial_status),
          allow_duplicates_(allow_duplicates) {}

    ossl_ptr<X509> PVXS_API create();

    static time_t getNotAfterTimeFromCert(const ossl_ptr<X509> &cert);

    static std::string PVXS_API certAndCasToPemString(const ossl_ptr<X509> &cert, const STACK_OF(X509) * cert_auth_chain_ptr);

    //    static bool PVXS_API verifySignature(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data, const std::string &signature);

    //    static std::string sign(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data);

    /**
     * @brief Get the error string from the error queue
     * @return the error string
     */
    static std::string getError() {
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
    static void addCustomExtensionByNid(const ossl_ptr<X509> &certificate, int nid, const std::string &value);
    static void addCustomTimeExtensionByNid(const ossl_ptr<X509> &certificate, int nid, time_t value);

    static std::string sign(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data);
    static bool verifySignature(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data, const std::string &signature);

   private:
    /**
     * @brief Convert a NID to a string
     * @param nid the NID
     * @return the string representation of the NID
     */
    static const char *nid2String(int nid) {
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

    void setSubject(const ossl_ptr<X509> &certificate) const;

    void setValidity(const ossl_ptr<X509> &certificate) const;

    void setSerialNumber(const ossl_ptr<X509> &certificate) const;

    void addExtensions(const ossl_ptr<X509> &certificate) const;

    void addExtension(const ossl_ptr<X509> &certificate, int nid, const char *value, const X509 *subject = nullptr) const;

    static void writeCertToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<X509> &cert);

    static void writeCertsToBio(const ossl_ptr<BIO> &bio, const STACK_OF(X509) * certs);

    static ossl_ptr<BIO> newBio();

    void set_skid(const ossl_ptr<X509> &certificate);
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERT_FACTORY_H
