#ifndef PVXS_PEM_FILE_FACTORY_H
#define PVXS_PEM_FILE_FACTORY_H

#include "certfilefactory.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

class PEMFileFactory : public CertFileFactory {
   public:
    explicit PEMFileFactory(const std::string& filename) : CertFileFactory(filename) {}

    PEMFileFactory(const std::string& filename, X509* cert_ptr, STACK_OF(X509) * certs_ptr, bool certs_only = false) : CertFileFactory(filename, cert_ptr, certs_ptr, "certificate", "", certs_only) {}

    PEMFileFactory(const std::string& filename, const std::string& pem_string, bool certs_only = false) : CertFileFactory(filename, nullptr, nullptr, "certificate", pem_string, certs_only) {}

    static bool createRootPemFile(const std::string& pemString, bool overwrite = false);

    std::shared_ptr<KeyPair> getKeyFromFile() override;
    CertData getCertDataFromFile() override;

    void writeCertFile() override { writePEMFile(); }
    void writePEMFile();
};

}  // namespace certs
}  // namespace pvxs

#endif
