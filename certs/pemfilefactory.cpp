#include "pemfilefactory.h"

#include <ctime>
#include <fstream>
#include <iomanip>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "openssl.h"
#include "certfactory.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(pemcerts, "pvxs.certs.pem");

/**
 * @brief Create a root PEM file from a PEM string
 *
 * @param p12PemString the PEM string to convert
 * @param overwrite if true then an existing file will be overwritten
 * @return true if the file already exists, false otherwise
 * @throw std::runtime_error if the file cannot be written
 */
bool PEMFileFactory::createRootPemFile(const std::string& p12_pem_string, bool overwrite) {
    static constexpr auto kMaxAuthnNameLen = 256;

    ossl_ptr<BIO> bio(BIO_new_mem_buf(p12_pem_string.data(), p12_pem_string.size()));

    // Create a stack for the certs
    STACK_OF(X509_INFO) * inf(PEM_X509_INFO_read_bio(bio.get(), NULL, NULL, NULL));
    if (!inf || sk_X509_INFO_num(inf) == 0) {
        throw std::runtime_error("No certificates found in PEM data");
    }

    // Get the root CA certificate (either the only one or the last in chain)
    X509_INFO* xi = nullptr;
    int num_certs = sk_X509_INFO_num(inf);

    if (num_certs == 1) {
        // Single certificate case (self-signed CA)
        xi = sk_X509_INFO_value(inf, 0);
    } else {
        // Certificate chain case (get the last one)
        xi = sk_X509_INFO_value(inf, num_certs - 1);
    }

    if (!xi || !xi->x509) {
        throw std::runtime_error("Failed to get root certificate");
    }

    // Build filename based on the CA certificate's CN field
    ossl_ptr<X509_NAME> name(X509_get_subject_name(xi->x509), false);
    if (!name) {
        throw std::runtime_error("Failed to get subject name from certificate");
    }

    char cn[kMaxAuthnNameLen];
    if (X509_NAME_get_text_by_NID(name.get(), NID_commonName, cn, sizeof(cn)) < 0) {
        throw std::runtime_error("Failed to get CN from certificate");
    }

    std::string fileName(cn);
    std::replace(fileName.begin(), fileName.end(), ' ', '_');
    fileName += ".crt";

    // Prepare file to write
    std::string certs_directory_string = CertFactory::getCertsDirectory();
    std::string certs_file = certs_directory_string + "/" + fileName;
    std::string hash_link;

    // Check if file already exists, if it does, do nothing and return
    bool exists = (access(certs_file.c_str(), F_OK) != -1);
    if (!overwrite && exists) {
        log_debug_printf(pemcerts, "Root Certificate already installed: %s\n", certs_file.c_str());
    }

    // If it exists, and we must overwrite then remove the existing one
    if ( exists && overwrite )
        std::remove(certs_file.c_str());

    // Create if it doesn't exist or we must overwrite
    if ( !exists || overwrite )
    {
        file_ptr fp(fopen(certs_file.c_str(), "w"), false);
        if (!fp) {
            throw std::runtime_error(SB() << "Error opening root certificate file for writing: " << certs_file);
        }

        if (PEM_write_X509(fp.get(), xi->x509) != 1) {
            throw std::runtime_error("Failed to write certificate to file");
        }

        fclose(fp.get());
        fp.release();

        // Verify the file was written correctly
        if (std::ifstream(certs_file).peek() == std::ifstream::traits_type::eof()) {
            throw std::runtime_error(SB() << "Certificate file is empty after writing: " << certs_file);
        }

        // Create appropriate symlink
        hash_link = CertFactory::createCertSymlink(certs_file);
    }

    // if the certificate is trusted then return true
    // Should be already trusted because we've copied it to a trusted location,
    // but just in case we need to make sure before continuing
    try {
        auto cert_data = IdFileFactory::create(certs_file)->getCertDataFromFile();
        ossl::ensureTrusted(cert_data.cert, nullptr);
        log_warn_printf(pemcerts, "New Root CA certificate installed: %s\n", certs_file.c_str());
        return true;
    } catch (std::exception& e) {
        log_warn_printf(pemcerts, "New Root CA certificate: %s\n", e.what());
    }


#if defined(__linux__)
    log_warn_printf(pemcerts, "To trust this Root CA on Linux:%s", "\n");
    log_warn_printf(pemcerts, "1. Debian/Ubuntu:%s", "\n");
    log_warn_printf(pemcerts, "   sudo cp %s /usr/local/share/ca-certificates/\n", certs_file.c_str());
    log_warn_printf(pemcerts, "   sudo update-ca-certificates%s", "\n");
    log_warn_printf(pemcerts, "2. RHEL/CentOS:%s", "\n");
    log_warn_printf(pemcerts, "   sudo cp %s /etc/pki/ca-trust/source/anchors/\n", certs_file.c_str());
    log_warn_printf(pemcerts, "   sudo update-ca-trust%s", "\n");

#elif defined(__APPLE__)
    log_warn_printf(pemcerts, "To trust this Root CA on macOS:%s", "\n");
    log_warn_printf(pemcerts, "1. Add to System Keychain:%s", "\n");
    log_warn_printf(pemcerts, "   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certs_file.c_str());
    log_warn_printf(pemcerts, "2. Create hash symlink:%s", "\n");
    log_warn_printf(pemcerts, "   sudo ln -sf %s /etc/ssl/certs/%s\n", certs_file.c_str(), hash_link.c_str());

#elif defined(_WIN32)
    log_warn_printf(pemcerts, "To trust this Root CA on Windows:%s", "\n");
    log_warn_printf(pemcerts, "1. Double-click %s\n", certs_file.c_str());
    log_warn_printf(pemcerts, "2. Click 'Install Certificate'%s", "\n");
    log_warn_printf(pemcerts, "3. Select 'Local Machine' and click 'Next'%s", "\n");
    log_warn_printf(pemcerts, "4. Select 'Place all certificates in the following store'%s", "\n");
    log_warn_printf(pemcerts, "5. Click 'Browse' and select 'Trusted Root Certification Authorities'%s", "\n");
    log_warn_printf(pemcerts, "6. Click 'Next' and then 'Finish'%s", "\n");

#elif defined(__rtems__)
    log_warn_printf(pemcerts, "For RTEMS systems:%s", "\n");
    log_warn_printf(pemcerts, "Ensure %s is included in your SSL certificate directory\n", certs_file.c_str());
    log_warn_printf(pemcerts, "Hash link: %s\n", hash_link.c_str());
#endif

    return false;
}

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
                if (PEM_write_PKCS8PrivateKey(fp.get(),
                                            key_pair_->pkey.get(),
                                            cipher,
                                            nullptr, 0,
                                            nullptr,
                                            const_cast<char*>(password_.c_str())) != 1) {
                    throw std::runtime_error("Failed to write encrypted private key");
                }
            } else {
                // Write unencrypted private key
                if (PEM_write_PrivateKey(fp.get(),
                                       key_pair_->pkey.get(),
                                       nullptr, nullptr, 0,
                                       nullptr, nullptr) != 1) {
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
        if (pkey)
            return CertData(cert, chain, std::make_shared<KeyPair>(std::move(pkey)));
    } catch (...) {}

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
