#include "pemfilefactory.h"

#include <ctime>
#include <fstream>
#include <iomanip>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "certfactory.h"
#include "openssl.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(pemcerts, "pvxs.certs.pem");

/**
 * @brief Write the PEM file and set permissions to protect it
 *
 * @throw std::runtime_error if the file cannot be written
 */
void PEMFileFactory::writePEMFile() {
    // Backup existing file if necessary
    backupFileIfExists(filename_);

    // Open file for writing
    file_ptr fp(fopen(filename_.c_str(), "w"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening certificate file for writing: " << filename_);
    }

    if (!pem_string_.empty()) {
        // Write the PEM string directly
        if (fputs(pem_string_.c_str(), fp.get()) == EOF) {
            throw std::runtime_error("Failed to write PEM string to file");
        }
    } else if (cert_ptr_) {
        // Write the certificate
        if (PEM_write_X509(fp.get(), cert_ptr_) != 1) {
            throw std::runtime_error("Failed to write certificate to file");
        }

        // Write the certificate chain
        if (certs_ptr_) {
            for (int i = 0; i < sk_X509_num(certs_ptr_); i++) {
                X509* chain_cert = sk_X509_value(certs_ptr_, i);
                if (PEM_write_X509(fp.get(), chain_cert) != 1) {
                    throw std::runtime_error("Failed to write certificate chain to file");
                }
            }
        }

        // Write private key if available
        if (key_pair_ && key_pair_->pkey) {
            if (!password_.empty()) {
                // Write encrypted private key using PKCS8 format
                const EVP_CIPHER* cipher = EVP_aes_256_cbc();
                if (PEM_write_PKCS8PrivateKey(fp.get(), key_pair_->pkey.get(), cipher, nullptr, 0, nullptr, const_cast<char*>(password_.c_str())) != 1) {
                    throw std::runtime_error("Failed to write encrypted private key");
                }
            } else {
                // Write unencrypted private key
                if (PEM_write_PrivateKey(fp.get(), key_pair_->pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                    throw std::runtime_error("Failed to write private key");
                }
            }
        }
    } else {
        throw std::runtime_error("No certificate or PEM string available to write");
    }

    chmod(filename_.c_str(), S_IRUSR | S_IWUSR);  // Protect PEM file
    log_info_printf(pemcerts, "Certificate file created: %s\n", filename_.c_str());
}

/**
 * @brief Get the certificate data from a PEM file
 *
 * @param filename the path to the PEM file
 * @return a CertData object containing the certificate and the chain
 * @throw std::runtime_error if the file cannot be opened or read
 */
CertData PEMFileFactory::getCertDataFromFile() {
    file_ptr fp(fopen(filename_.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening certificate file: " << filename_);
    }

    // Read the first certificate (main cert)
    ossl_ptr<X509> cert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr), false);
    if (!cert) {
        throw std::runtime_error(SB() << "Error reading certificate from file: " << filename_);
    }

    // Read any additional certificates (chain)
    ossl_shared_ptr<STACK_OF(X509)> chain(sk_X509_new_null());
    if (!chain) {
        throw std::runtime_error("Unable to allocate certificate chain");
    }

    ossl_ptr<X509> ca;
    while (X509* ca_ptr = PEM_read_X509(fp.get(), nullptr, nullptr, nullptr)) {
        ca = ossl_ptr<X509>(ca_ptr);
        if (sk_X509_push(chain.get(), ca.get()) != 1) {
            throw std::runtime_error("Failed to add certificate to chain");
        }
        ca.release();
    }

    // Clear any end-of-file errors
    ERR_clear_error();

    // Read any private key
    std::shared_ptr<KeyPair> key_pair;

    // Try to read the private key
    try {
        ossl_ptr<EVP_PKEY> pkey;
        if (!password_.empty()) {
            // Use password if available
            pkey.reset(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, const_cast<char*>(password_.c_str())));
        } else {
            // Try reading without password
            pkey.reset(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr));
        }

        // Try to get key from file if it is configured
        if (!pkey && key_file_) {
            key_pair = key_file_->getKeyFromFile();
            pkey = std::move(key_pair->pkey);
        }
        if (pkey) return CertData(cert, chain, std::make_shared<KeyPair>(std::move(pkey)));
    } catch (...) {
    }

    return CertData(cert, chain);
}

/**
 * @brief Get a key pair from a PEM file
 *
 * @return a shared pointer to the KeyPair object
 * @throw std::runtime_error if the file cannot be opened or read
 */
std::shared_ptr<KeyPair> PEMFileFactory::getKeyFromFile() {
    file_ptr fp(fopen(filename_.c_str(), "r"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening private key file: \"" << filename_ << "\"");
    }

    // Try to read the private key
    ossl_ptr<EVP_PKEY> pkey(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr), false);
    if (!pkey) {
        ERR_clear_error();
        throw std::runtime_error(SB() << "No private key found in file: " << filename_);
    }

    return std::make_shared<KeyPair>(std::move(pkey));
}

}  // namespace certs
}  // namespace pvxs
