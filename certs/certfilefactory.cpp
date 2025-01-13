#include "certfilefactory.h"

#include <ctime>
#include <fstream>
#include <iomanip>

#include <openssl/rand.h>  // For RAND_seed

#include <pvxs/log.h>

#include <sys/stat.h>

#include "p12filefactory.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(certs, "pvxs.certs.file");

/**
 * @brief Backs-up a file if it exists.
 *
 * This method creates a backup of the file by renaming it with a timestamp
 * if the file is non-existent it does nothing, if the file is empty it deletes it
 * then does nothing else.
 *
 * @param filename The filename and path of the file to backup.
 */
void IdFileFactory::backupFileIfExists(const std::string& filename) {
    std::fstream file(filename, std::ios_base::in);
    if (!file.is_open())
        // File does not exist, return
        return;

    file.close();

    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%y%m%d%H%M");

    // new filename is {base filename}.{yy}{mm}{dd}{HH}{MM}.p12
    std::string extension = getExtension(filename);
    std::string new_filename = filename.substr(0, filename.size() - 4) + "." + oss.str() + "." + extension;

    // Rename the file
    std::rename(filename.c_str(), new_filename.c_str());

    log_warn_printf(certs, "Cert file backed up: %s ==> %s\n", filename.c_str(), new_filename.c_str());
}

/**
 * @brief Creates a certificate chain from a root certificate pointer.
 *
 * This method creates a certificate chain from a root certificate pointer.
 * The chain is allocated and the root certificate is added to it.
 * The chain will always have only one certificate in it.
 *
 * Use this function when you need to have a CA certificate chain but its a self signed
 * certificate.
 *
 * @param chain The certificate chain reference that will be allocated and populated.
 * @param root_cert_ptr The root certificate to add to the chain.
 */
void IdFileFactory::chainFromRootCertPtr(STACK_OF(X509) * &chain, X509* root_cert_ptr) {
    if (!root_cert_ptr) {
        throw std::runtime_error("Root certificate pointer is null");
    }

    chain = sk_X509_new_null();
    if (!chain) {
        throw std::runtime_error("Unable to allocate space for certificate chain");
    }

    if (sk_X509_push(chain, root_cert_ptr) != 1) {
        sk_X509_free(chain);
        throw std::runtime_error("Unable to add root certificate to chain");
    }
}

/**
 * @brief Gets the certificate data.
 *
 * This method gets the certificate data.  This can only be called if a certificate is available after a call to writeIdentityFile.
 *
 * @param key_pair The key pair to include in the certificate data.
 * @return The certificate data.
 */
CertData IdFileFactory::getCertData(const std::shared_ptr<KeyPair>& key_pair) {
    if (pem_string_.empty() && !cert_ptr_) {
        throw std::runtime_error("No certificate data available");
    }

    ossl_ptr<X509> cert;
    ossl_shared_ptr<STACK_OF(X509)> chain(sk_X509_new_null());
    if (!chain) {
        throw std::runtime_error("Failed to create certificate chain");
    }

    if (!pem_string_.empty()) {
        // Parse certificates from PEM string
        ossl_ptr<BIO> bio(BIO_new_mem_buf(pem_string_.data(), pem_string_.size()), false);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for PEM data");
        }

        // Read first certificate (the main cert)
        cert.reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!cert) {
            throw std::runtime_error("Failed to read certificate from PEM data");
        }

        // Read remaining certificates into chain
        while (true) {
            ossl_ptr<X509> chain_cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), false);
            if (!chain_cert) {
                ERR_clear_error();  // Clear EOF error
                break;
            }
            if (sk_X509_push(chain.get(), chain_cert.get()) != 1) {
                throw std::runtime_error("Failed to add certificate to chain");
            }
            chain_cert.reset();
        }
    } else {
        // Use certificate pointers
        cert.reset(X509_dup(cert_ptr_));
        if (!cert) {
            throw std::runtime_error("Failed to duplicate certificate");
        }

        if (certs_ptr_) {
            // Duplicate each certificate in the chain
            for (int i = 0; i < sk_X509_num(certs_ptr_); i++) {
                ossl_ptr<X509> int_cert(X509_dup(sk_X509_value(certs_ptr_, i)), false);
                if (!int_cert || sk_X509_push(chain.get(), int_cert.get()) != 1) {
                    throw std::runtime_error("Failed to duplicate chain certificate");
                }
                int_cert.reset();
            }
        }
    }

    return CertData(cert, chain, key_pair);
}

cert_factory_ptr IdFileFactory::create(const std::string& filename, const std::string& password, const std::shared_ptr<KeyPair>& key_pair, X509* cert_ptr,
                                       STACK_OF(X509) * certs_ptr, const std::string& pem_string) {
    std::string ext = getExtension(filename);
    if (ext == "p12" || ext == "pfx") {
        if (cert_ptr)
            return make_factory_ptr<P12FileFactory>(filename, password, key_pair, cert_ptr, certs_ptr);
        else
            return make_factory_ptr<P12FileFactory>(filename, password, key_pair, pem_string);

    }
    throw std::runtime_error(SB() << ": Unsupported keychain file extension (expected p12 or pfx): \"" << (ext.empty() ? "<none>" : ext) << "\"");
}

/**
 * @brief Creates a key pair.
 *
 * This method generates a new private key and a corresponding public key pair,
 *
 * @return a unique pointer to a managed KeyPair object.
 */
std::shared_ptr<KeyPair> IdFileFactory::createKeyPair() {
    // Create a new KeyPair object
    auto key_pair = std::make_shared<KeyPair>();

    const int kKeySize = 2048;          // Key size
    const int kKeyType = EVP_PKEY_RSA;  // Key type

    // Initialize the context for the key generation operation
    ossl_ptr<EVP_PKEY_CTX> context(EVP_PKEY_CTX_new_id(kKeyType, nullptr), false);
    if (!context) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    // Initialize key generation context for RSA algorithm
    if (EVP_PKEY_keygen_init(context.get()) != 1) {
        throw std::runtime_error("Failed to initialize EVP_KEY context for key generation");
    }

    // Set the RSA key size for key generation
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), kKeySize) != 1) {
        throw std::runtime_error("Failed to set RSA key size for key generation");
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(context.get(), key_pair->pkey.acquire()) != 1) {
        throw std::runtime_error("Failed to generate key pair");
    }

    // Create a memory buffer BIO for storing the public key
    ossl_ptr<BIO> bio_public(BIO_new(BIO_s_mem()));

    // Write the public key into the buffer
    if (!PEM_write_bio_PUBKEY(bio_public.get(), key_pair->pkey.get())) {
        throw std::runtime_error("Failed to write public key to BIO");
    }

    // Get the public key data as binary and store it in the buffer
    char* bio_buffer_pub = nullptr;
    long public_key_length = BIO_get_mem_data(bio_public.get(), &bio_buffer_pub);

    // Convert buffer containing public key data into std::string format
    std::string public_key(bio_buffer_pub, public_key_length);
    key_pair->public_key = public_key;
    log_debug_printf(certs, "Key Pair Generated: %s\n", public_key.c_str());

    return key_pair;
}

}  // namespace certs
}  // namespace pvxs
