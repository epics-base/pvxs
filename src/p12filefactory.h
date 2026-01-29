/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_P12_FILE_FACTORY_H
#define PVXS_P12_FILE_FACTORY_H

#include <memory>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

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

    PVXS_API void writePKCS12File();

    void writeIdentityFile() override { writePKCS12File(); }

    CertData getCertDataFromFile() override;
    std::shared_ptr<KeyPair> getKeyFromFile() override;

   private:
    PKCS12 *p12_ptr_{};

    static ossl_ptr<PKCS12> pemStringToP12(const std::string &password, EVP_PKEY *keys_ptr, const std::string &pem_string);

    static ossl_ptr<PKCS12> toP12(const std::string &password, EVP_PKEY *keys_ptr, X509 *cert_ptr, STACK_OF(X509) *cert_chain_ptr = nullptr);

#ifdef NID_oracle_jdk_trustedkeyusage
    static int jdkTrust(PKCS12_SAFEBAG *bag, void *) noexcept;
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
