/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_ID_FILE_READER_H
#define PVXS_ID_FILE_READER_H

#include <memory>
#include <string>
#include <utility>

#include <openssl/x509.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

// Forward declarations
class P12FileReader;
class IdFileReader;

// C++11 implementation of make_unique
template <typename T, typename... Args>
std::unique_ptr<T> make_factory_ptr(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

struct KeyPair final {
    std::string public_key;
    ossl_ptr<EVP_PKEY> pkey;

    // Default constructor
    KeyPair() = default;

    explicit KeyPair(ossl_ptr<EVP_PKEY> new_pkey) : pkey(std::move(new_pkey)) {
        const ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()));

        if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
            throw std::runtime_error("Failed to write public key to BIO");
        }

        BUF_MEM *bptr;                      // to hold a pointer to data in the BIO object.
        BIO_get_mem_ptr(bio.get(), &bptr);  // set to point into a BIO object

        // Create a string from the BIO
        const std::string result(bptr->data, bptr->length);
        public_key = result;
    }
};

// CertData structure definition
struct CertData {
    ossl_ptr<X509> cert;
    ossl_shared_ptr<STACK_OF(X509)> cert_auth_chain;
    std::shared_ptr<KeyPair> key_pair;
    time_t renew_by{0};

    CertData(ossl_ptr<X509>& new_cert, const ossl_shared_ptr<STACK_OF(X509)>& new_ca) : cert(std::move(new_cert)), cert_auth_chain(new_ca) {}
    CertData(ossl_ptr<X509>& new_cert, const ossl_shared_ptr<STACK_OF(X509)>& new_ca, std::shared_ptr<KeyPair> key_pair)
        : cert(std::move(new_cert)), cert_auth_chain(new_ca), key_pair(std::move(key_pair)) {}
    CertData() = default;
};

typedef std::unique_ptr<IdFileReader> cert_factory_ptr;

class PVXS_API IdFileReader {
   public:
    /**
     * @brief Creates a new IdFile Reader object.
     *
     * This method creates a new CertFileFactory object.
     */
    static cert_factory_ptr createReader(const std::string& filename, const std::string& password = "");

    virtual ~IdFileReader() = default;

    /**
     * @brief Gets the certificate data from the file.
     *
     * This method gets the certificate data including the key from the file.
     * The format (PKCS#12, or Base64-encoded ASCII) is determined by the filename extension.
     */
    virtual CertData getCertDataFromFile() = 0;

   protected:
    explicit IdFileReader(std::string  filename, std::string  password = "")
        : filename_(std::move(filename)), password_(std::move(password)) {}

    std::string filename_{};
    std::string password_{};

    static std::string getExtension(const std::string& filename) {
        const auto pos = filename.find_last_of('.');
        if (pos == std::string::npos) {
            return "";
        }
        return filename.substr(pos + 1);
    }
};

/**
 * @class P12FileReader
 *
 * @brief Manages certificate file operations.
 */
class P12FileReader final : public IdFileReader {
    public:
        P12FileReader(const std::string &filename, const std::string &password)
            : IdFileReader(filename, password) {}

        CertData getCertDataFromFile() override;
};

}  // namespace certs
}  // namespace pvxs

#endif // PVXS_ID_FILE_READER_H
