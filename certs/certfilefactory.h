#ifndef PVXS_CERT_FILE_FACTORY_H
#define PVXS_CERT_FILE_FACTORY_H

#include <memory>
#include <string>
#include <utility>

#include <openssl/x509.h>

#include <pvxs/log.h>

#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

// Forward declarations
class P12FileFactory;
class IdFileFactory;

// C++11 implementation of make_unique
template <typename T, typename... Args>
std::unique_ptr<T> make_factory_ptr(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

// CertData structure definition
struct CertData {
    ossl_ptr<X509> cert;
    ossl_shared_ptr<STACK_OF(X509)> ca;
    std::shared_ptr<KeyPair> key_pair;

    CertData(ossl_ptr<X509>& newCert, ossl_shared_ptr<STACK_OF(X509)>& newCa) : cert(std::move(newCert)), ca(newCa) {}
    CertData(ossl_ptr<X509>& newCert, ossl_shared_ptr<STACK_OF(X509)>& newCa, std::shared_ptr<KeyPair> key_pair)
        : cert(std::move(newCert)), ca(newCa), key_pair(key_pair) {}
};

/**
 * @brief The availability of a certificate file
 *
 * This is returned when when authentication daemons are trying to provision the configured certificate files.
 *  - `NOT_AVAILABLE` is returned if the file does not exist and can't be provisioned.
 *  - `ROOT_CERT_INSTALLED` is returned if the file exists or has been provisioned but
 *     the root CA certificate was downloaded and installed during the call.  This signals to the caller
 *     the configured certificate will be unusable until the user trusts the root CA certificate.
 *  - `AVAILABLE` is returned if the file already exists.
 *  - `OK` is returned if the certificate file was provisioned and is ready for use.
 */
enum CertAvailability {
    OK,
    NOT_AVAILABLE,
    ROOT_CERT_INSTALLED,
    AVAILABLE,
};

typedef std::unique_ptr<IdFileFactory> cert_factory_ptr;

class IdFileFactory {
   public:
    /**
     * @brief Creates a new CertFileFactory object.
     *
     * This method creates a new CertFileFactory object.
     */
    static cert_factory_ptr create(const std::string& filename, const std::string& password = "", const std::shared_ptr<KeyPair>& key_pair = nullptr,
                                   X509* cert_ptr = nullptr, STACK_OF(X509) * certs_ptr = nullptr, const std::string& usage = "certificate",
                                   const std::string& pem_string = "");

    static cert_factory_ptr createReader(const std::string& filename, const std::string& password = "", const std::string& key_filename = "",
                                         const std::string& key_password = "") {
        auto cert_file_factory = create(filename, password);
        if (!key_filename.empty()) cert_file_factory->key_file_ = create(key_filename, key_password);

        return cert_file_factory;
    }

    virtual ~IdFileFactory() = default;

    /**
     * @brief Writes the credentials file.
     *
     * This method writes an identity file which can be:
     *   - the private key
     *   - the X.509 certificate and CA chain
     *   - both
     * The format (PKCS#12, or Base64-encoded ASCII) is determined by the filename extension.
     */
    virtual void writeIdentityFile() = 0;

    /**
     * @brief Gets the certificate data from the file.
     *
     * This method gets the certificate data from the file.
     * The format (PKCS#12, or Base64-encoded ASCII) is determined by the filename extension.
     */
    virtual CertData getCertDataFromFile() = 0;

    /**
     * @brief Gets the key from the file.
     *
     * This method gets the key from the file.
     * The format (PKCS#12, or Base64-encoded ASCII) is determined by the filename extension.
     */
    virtual std::shared_ptr<KeyPair> getKeyFromFile() = 0;

    /**
     * @brief Creates a key pair.
     *
     * This method creates a key pair.  Private key is generated and public key is extracted from the private key.
     */
    static std::shared_ptr<KeyPair> createKeyPair();

    CertData getCertData(const std::shared_ptr<KeyPair>& key_pair);

   protected:
    IdFileFactory(const std::string& filename, const std::string& password = "", const std::shared_ptr<KeyPair>& key_pair = nullptr, X509* cert_ptr = nullptr,
                  STACK_OF(X509) * certs_ptr = nullptr, const std::string& usage = "certificate", const std::string& pem_string = "")
        : filename_(filename),
          password_(password),
          key_pair_(key_pair),
          cert_ptr_(cert_ptr),
          certs_ptr_(certs_ptr),
          usage_(usage),
          pem_string_(pem_string) {}

    const std::string filename_{};
    std::string password_{};
    const std::shared_ptr<KeyPair> key_pair_;
    X509* cert_ptr_{nullptr};
    STACK_OF(X509) * certs_ptr_ { nullptr };
    const std::string usage_{};
    const std::string pem_string_{};
    std::unique_ptr<IdFileFactory> key_file_;

    static void backupFileIfExists(const std::string& filename);
    static void chainFromRootCertPtr(STACK_OF(X509) * &chain, X509* root_cert_ptr);
    static std::string getExtension(const std::string& filename) {
        auto pos = filename.find_last_of('.');
        if (pos == std::string::npos) {
            return "";
        }
        return filename.substr(pos + 1);
    }
};

}  // namespace certs
}  // namespace pvxs

#endif
