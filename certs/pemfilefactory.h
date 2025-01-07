#ifndef PVXS_PEM_FILE_FACTORY_H
#define PVXS_PEM_FILE_FACTORY_H

#include "certfilefactory.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

class PEMFileFactory : public IdFileFactory {
   public:
    explicit PEMFileFactory(const std::string& filename, const std::string& password = "", const std::shared_ptr<KeyPair>& key_pair = nullptr)
        : IdFileFactory(filename, password, key_pair), password_(password) {}
    explicit PEMFileFactory(const std::string& filename, const std::string& password = "", const std::shared_ptr<KeyPair>& key_pair = nullptr,
                            X509* cert_ptr = nullptr, STACK_OF(X509) * certs_ptr = nullptr, bool certs_only = false)
        : IdFileFactory(filename, password, key_pair, cert_ptr, certs_ptr, "certificate", "", certs_only), password_(password) {}
    explicit PEMFileFactory(const std::string& filename, const std::string& password = "", const std::shared_ptr<KeyPair>& key_pair = nullptr,
                            const std::string& pem_string = "", bool certs_only = false)
        : IdFileFactory(filename, password, key_pair, nullptr, nullptr, "certificate", pem_string, certs_only), password_(password) {}

    std::shared_ptr<KeyPair> getKeyFromFile() override;
    CertData getCertDataFromFile() override;

    void writeIdentityFile() override { writePEMFile(); }
    void writePEMFile();

   private:
    const std::string password_{};
};

}  // namespace certs
}  // namespace pvxs

#endif
