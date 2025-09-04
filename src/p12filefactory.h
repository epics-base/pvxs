/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_P12_FILE_FACTORY_H
#define PVXS_P12_FILE_FACTORY_H

#include <iostream>
#include <memory>
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

#include "certfilefactory.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

/**
 * @class P12FileFactory
 *
 * @brief Manages certificate file operations.
 */
class P12FileFactory final : public IdFileFactory {
   public:
    P12FileFactory(const std::string &filename, const std::string &password, const std::shared_ptr<KeyPair> &key_pair, X509 *cert_ptr, stack_st_X509 *certs_ptr)
        : IdFileFactory(filename, password, key_pair, cert_ptr, certs_ptr, "") {}

    P12FileFactory(const std::string &filename, const std::string &password, const std::shared_ptr<KeyPair> &key_pair, const std::string &pem_string)
        : IdFileFactory(filename, password, key_pair, nullptr, nullptr, pem_string) {}

    P12FileFactory(const std::string &filename, const std::string &password, const std::shared_ptr<KeyPair> &key_pair, PKCS12 *p12_ptr)
        : IdFileFactory(filename, password, key_pair, nullptr, nullptr, ""), p12_ptr_(p12_ptr) {}

    void writePKCS12File();

    void writeIdentityFile() override { writePKCS12File(); }

    CertData getCertDataFromFile() override;
    std::shared_ptr<KeyPair> getKeyFromFile() override;

   private:
    PKCS12 *p12_ptr_{};

    static ossl_ptr<PKCS12> pemStringToP12(const std::string &password, EVP_PKEY *keys_ptr, const std::string &pem_string);

    static ossl_ptr<PKCS12> toP12(const std::string &password, EVP_PKEY *keys_ptr, X509 *cert_ptr, STACK_OF(X509) *cert_chain_ptr = nullptr);

#ifdef NID_oracle_jdk_trustedkeyusage
    /**
     * @brief Add the JDK trusted key usage attribute to the p12 object
     *
     * This is done by using the callback mechanism that is triggered by PKCS12_create_ex2 for every bag.
     * We can then ignore all bags except X509 certificates with an associated key.
     *
     * This is conditionally compiled in for platforms that support it.
     *
     * @param bag the p12 safe bag to add the attribute to
     * @return 1 if the attribute was added, 0 if it was not added
     */
    static int jdkTrust(PKCS12_SAFEBAG *bag, void *) noexcept {
        try {
            // Only add trustedkeyusage when bag is an X509 cert. with an
            // associated key (when localKeyID is present) which does not
            // already have trustedkeyusage.
            if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag || PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate ||
                !!PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID) || !!PKCS12_SAFEBAG_get0_attr(bag, NID_oracle_jdk_trustedkeyusage))
                return 1;

            const auto curattrs(PKCS12_SAFEBAG_get0_attrs(bag));
            pvxs::ossl_ptr<STACK_OF(X509_ATTRIBUTE)> newattrs(sk_X509_ATTRIBUTE_deep_copy(curattrs, &X509_ATTRIBUTE_dup, &X509_ATTRIBUTE_free));

            const ossl_ptr<ASN1_OBJECT> trust(OBJ_txt2obj("anyExtendedKeyUsage", 0));
            ossl_ptr<X509_ATTRIBUTE> attr(X509_ATTRIBUTE_create(NID_oracle_jdk_trustedkeyusage, V_ASN1_OBJECT, trust.get()));

            if (sk_X509_ATTRIBUTE_push(newattrs.get(), attr.get()) != 1) {
                std::cerr << "Error: unable to add JDK trust attribute\n";
                return 1;
            }
            attr.release();

            PKCS12_SAFEBAG_set0_attrs(bag, newattrs.get());
            newattrs.release();

            return 1;
        } catch (std::exception &e) {
            std::cerr << "Error: unable to add JDK trust attribute: " << e.what() << "\n";
            return 0;
        }
    }
#else
    static int jdkTrust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept { return 0; }
    static inline PKCS12 *PKCS12_create_ex2(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) * cert_auth_chain_ptr, int nid_key, int nid_cert,
                                            int iter, int mac_iter, int keytype, OSSL_LIB_CTX *ctx, const char *propq,
                                            int (*cb)(PKCS12_SAFEBAG *bag, void *cbarg), void *cbarg) {
        return PKCS12_create_ex(pass, name, pkey, cert, cert_auth_chain_ptr, nid_key, nid_cert, iter, mac_iter, keytype, ctx, propq);
    }
#endif
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_P12_FILE_FACTORY_H
