/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_KEYCHAIN_FACTORY_H
#define PVXS_KEYCHAIN_FACTORY_H

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
#include "authregistry.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace security {
struct KeyChainData {
    ossl_ptr<EVP_PKEY> pkey;
    ossl_ptr<X509> cert;
    ossl_shared_ptr<STACK_OF(X509)> ca;

    KeyChainData(ossl_ptr<EVP_PKEY> &newPkey, ossl_ptr<X509> &newCert, ossl_shared_ptr<STACK_OF(X509)> &newCa)
        : pkey(std::move(newPkey)), cert(std::move(newCert)), ca(newCa) {}
};

enum CertAvailability {
    OK,
    NOT_AVAILABLE,
    ROOT_CERT_INSTALLED,
    AVAILABLE,  // Certificate file already exists
};

/**
 * @class KeychainFactory
 *
 * @brief Manages certificates and associated operations.
 */
class KeychainFactory {
   public:
    KeychainFactory(const std::string &keychain_filename, const std::string &password,
                    const std::shared_ptr<KeyPair> &key_pair, X509 *cert_ptr, stack_st_X509 *certs_ptr)
        : keychain_filename_(keychain_filename), password_(password), key_pair_(key_pair),
          cert_ptr_(cert_ptr), certs_ptr_(certs_ptr) {}

    KeychainFactory(const std::string &keychain_filename, const std::string &password,
                    const std::shared_ptr<KeyPair> &key_pair, const std::string &pem_string)
        : keychain_filename_(keychain_filename), password_(password), key_pair_(key_pair), pem_string_(pem_string) {}

    KeychainFactory(const std::string &keychain_filename, const std::string &password,
                    const std::shared_ptr<KeyPair> &key_pair, PKCS12 *p_12_ptr)
        : keychain_filename_(keychain_filename), password_(password), key_pair_(key_pair), p12_ptr_(p_12_ptr) {}

    static CertAvailability generateNewKeychainFile(const impl::ConfigCommon &config, const uint16_t &usage);

    static KeyChainData PVXS_API getKeychainDataFromKeychainFile(std::string keychain_filename, std::string password);
    ;

    static inline const std::unique_ptr<Auth> &getAuth(const std::string &type) { return AuthRegistry::getAuth(type); }

    static std::shared_ptr<KeyPair> PVXS_API createKeyPair();

    static bool createRootPemFile(const std::string &p12PemString, bool overwrite = false);

    void PVXS_API writePKCS12File();

    bool PVXS_API writeRootPemFile(const std::string &pem_string, bool overwrite = false);

   private:
    const std::string keychain_filename_;
    const std::string password_;
    const std::shared_ptr<KeyPair> key_pair_;
    X509 *cert_ptr_;
    STACK_OF(X509) * certs_ptr_;
    std::string pem_string_;
    PKCS12 *p12_ptr_;

    static ossl_ptr<PKCS12> pemStringToP12(std::string password, EVP_PKEY *keys_ptr, std::string pem_string);

    static ossl_ptr<PKCS12> toP12(std::string password, EVP_PKEY *keys_ptr, X509 *cert_ptr,
                                  STACK_OF(X509) *cert_chain_ptr = nullptr);

    static void backupKeychainFileIfExists(std::string keychain_filename);

    static CertAvailability genNewKeychainFileForAuthMethod(const impl::ConfigCommon &config, const uint16_t &usage, const Auth &authenticator);

    static void chainFromRootCertPtr(STACK_OF(X509) * &chain, X509 *root_cert_ptr);

#ifdef NID_oracle_jdk_trustedkeyusage
    static int jdkTrust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept {
        try {
            // Only add trustedkeyusage when bag is an X509 cert. with an
            // associated key (when localKeyID is present) which does not
            // already have trustedkeyusage.
            if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag || PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate ||
                !!PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID) ||
                !!PKCS12_SAFEBAG_get0_attr(bag, NID_oracle_jdk_trustedkeyusage))
                return 1;

            auto curattrs(PKCS12_SAFEBAG_get0_attrs(bag));
            // PKCS12_SAFEBAG_get0_attrs() returns const.  Make a paranoia copy.
            pvxs::ossl_ptr<STACK_OF(X509_ATTRIBUTE)> newattrs(
                sk_X509_ATTRIBUTE_deep_copy(curattrs, &X509_ATTRIBUTE_dup, &X509_ATTRIBUTE_free));

            pvxs::ossl_ptr<ASN1_OBJECT> trust(OBJ_txt2obj("anyExtendedKeyUsage", 0));
            pvxs::ossl_ptr<X509_ATTRIBUTE> attr(
                X509_ATTRIBUTE_create(NID_oracle_jdk_trustedkeyusage, V_ASN1_OBJECT, trust.get()));

            if (sk_X509_ATTRIBUTE_push(newattrs.get(), attr.get()) != 1) {
                std::cerr << "Error: unable to add JDK trust attribute\n";
                return 0;
            }
            attr.release();

            PKCS12_SAFEBAG_set0_attrs(bag, newattrs.get());
            newattrs.release();

            return 1;
        } catch (std::exception &e) {
            std::cerr << "Error: unable to add JDK trust attribute: " << e.what() << "\n";
            return 0;
        }
    };
#else
    static int jdkTrust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept { return 0; }
    static inline PKCS12 *PKCS12_create_ex2(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert,
                                            STACK_OF(X509) * ca, int nid_key, int nid_cert, int iter, int mac_iter,
                                            int keytype, OSSL_LIB_CTX *ctx, const char *propq,
                                            int (*cb)(PKCS12_SAFEBAG *bag, void *cbarg), void *cbarg) {
        return PKCS12_create_ex(pass, name, pkey, cert, ca, nid_key, nid_cert, iter, mac_iter, keytype, ctx, propq);
    }
#endif
};

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_KEYCHAIN_FACTORY_H
