/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <climits>
#include <cstdio>
#include <iostream>
#include <memory>

#include <libgen.h>

#ifdef __unix__
#include <pwd.h>
#endif
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_set>

#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "certfactory.h"
#include "osiFileName.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "security.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(certs, "pvxs.certs.fms");

/**
 * @brief Creates a key pair.
 *
 * This method generates a new private key and a corresponding public key pair,
 *
 * @return a unique pointer to a managed KeyPair object.
 */
std::shared_ptr<KeyPair> P12FileFactory::createKeyPair() {
    // Create a new KeyPair object
    auto key_pair = std::make_shared<KeyPair>();

    const int kKeySize = 2048;          // Key size
    const int kKeyType = EVP_PKEY_RSA;  // Key type

    // Initialize the context for the key generation operation
    ossl_ptr<EVP_PKEY_CTX> context(EVP_PKEY_CTX_new_id(kKeyType, NULL));
    if (!context) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX.");
    }

    // Initialize key generation context for RSA algorithm
    if (EVP_PKEY_keygen_init(context.get()) != 1) {
        throw std::runtime_error("Failed to initialize EVP_KEY context for key generation.");
    }

    // Set the RSA key size for key generation
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), kKeySize) != 1) {
        throw std::runtime_error("Failed to set RSA key size for key generation.");
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(context.get(), key_pair->pkey.acquire()) != 1) {
        throw std::runtime_error("Failed to generate key pair.");
    }

    // Create a memory buffer BIO for storing the public key
    ossl_ptr<BIO> bio_public(BIO_new(BIO_s_mem()));

    // Write the public key into the buffer
    if (!PEM_write_bio_PUBKEY(bio_public.get(), key_pair->pkey.get())) {
        throw std::runtime_error("Failed to write public key to BIO.");
    }

    // Get the public key data as binary and store it in the buffer
    char *bio_buffer_pub = nullptr;
    long public_key_length = BIO_get_mem_data(bio_public.get(), &bio_buffer_pub);

    // Convert buffer containing public key data into std::string format
    std::string public_key(bio_buffer_pub, public_key_length);
    key_pair->public_key = public_key;
    log_debug_printf(certs, "Key Pair Generated: %s\n", public_key.c_str());

    // Return the unique_ptr to the new KeyPair object
    return key_pair;
};

std::shared_ptr<KeyPair> P12FileFactory::getKeyFromFile(std::string filename, std::string password) {
    file_ptr fp(fopen(filename.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening private key file for reading binary contents: \"" << filename << "\"");
    }

    ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), NULL));
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening private key file as a PKCS#12 object: " << filename);
    }

    ossl_ptr<EVP_PKEY> pkey;
    if (!PKCS12_parse(p12.get(), password.c_str(), pkey.acquire(), nullptr, nullptr)) {
        throw std::runtime_error(SB() << "Error parsing private key file: " << filename);
    }

    return std::make_shared<KeyPair>(std::move(pkey));
}

CertData P12FileFactory::getCertDataFromFile(std::string filename, std::string password) {
    ossl_ptr<X509> cert;
    STACK_OF(X509) *chain_ptr = nullptr;

    auto file(fopen(filename.c_str(), "rb"));
    if (!file) {
        throw std::runtime_error(SB() << "Error opening certificate file for reading binary contents: \"" << filename << "\"");
    }
    file_ptr fp(file);

    ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), NULL));
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening certificate file as a PKCS#12 object: " << filename);
    }

    ossl_ptr<EVP_PKEY> pkey;  // To be discarded
    if (!PKCS12_parse(p12.get(), password.c_str(), pkey.acquire(), cert.acquire(), &chain_ptr)) {
        throw std::runtime_error(SB() << "Error parsing certificate file: " << filename);
    }
    ossl_shared_ptr<STACK_OF(X509)> chain;
    if (chain_ptr)
        chain = ossl_shared_ptr<STACK_OF(X509)>(chain_ptr);
    else
        chain = ossl_shared_ptr<STACK_OF(X509)>(sk_X509_new_null());

    CertData key_chain_data(cert, chain);

    return key_chain_data;
}

/**
 * @brief Backup the given P12 file
 *
 * This function backs up the given P12 file by renaming it to a date
 * stamped filename thus: {base filename}.{YY}{MM}{DD}{hh}{mm}.p12
 *
 * It assumes that the given filename ends with ".p12" without verifying it
 * so please make sure the filename corresponds to this restriction.
 *
 * As the file is renamed it will retain the same operating system permissions
 * as the original file.
 *
 * @param filename
 */
void P12FileFactory::backupFileIfExists(std::string filename) {
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
    std::string new_filename = filename.substr(0, filename.size() - 4) + "." + oss.str() + ".p12";

    // Rename the file
    std::rename(filename.c_str(), new_filename.c_str());

    log_warn_printf(certs, "P12 file backed up: %s ==> %s\n", filename.c_str(), new_filename.c_str());
}

bool P12FileFactory::createRootPemFile(const std::string &p12PemString, bool overwrite) {
    static constexpr auto kMaxAuthnNameLen = 256;

    ossl_ptr<BIO> bio(BIO_new_mem_buf(p12PemString.data(), p12PemString.size()));

    // Create a stack for the certs
    STACK_OF(X509_INFO) *inf(PEM_X509_INFO_read_bio(bio.get(), NULL, NULL, NULL));
    if (!inf || sk_X509_INFO_num(inf) == 0) {
        throw std::runtime_error("No certificates found in PEM data");
    }

    // Get the root CA certificate (either the only one or the last in chain)
    X509_INFO *xi = nullptr;
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
    ossl_ptr<X509_NAME> name(X509_get_subject_name(xi->x509));
    if (!name) {
        throw std::runtime_error("Failed to get subject name from certificate");
    }

    char cn[kMaxAuthnNameLen];
    if (X509_NAME_get_text_by_NID(name.get(), NID_commonName, cn, sizeof(cn)) < 0) {
        throw std::runtime_error("Failed to get CN from certificate");
    }

    std::string fileName(cn);
    std::replace(fileName.begin(), fileName.end(), ' ', '_');
    fileName += ".pem";

    // Prepare file to write
    std::string certs_directory_string = CertFactory::getCertsDirectory();
    std::string certs_file = certs_directory_string + "/" + fileName;
    std::string hash_link;

    // Check if file already exists, if it does, do nothing and return

    // Check if file already exists
    bool exists = (access(certs_file.c_str(), F_OK) != -1);
    if (!overwrite && exists) {
        log_debug_printf(certs, "Root Certificate already installed: %s\n", certs_file.c_str());
        return true;
    }

    std::remove(certs_file.c_str());
    {
        file_ptr fp(fopen(certs_file.c_str(), "w"));
        if (!fp) {
            throw std::runtime_error(SB() << "Error opening root certificate file for writing: " << certs_file);
        }

        if (PEM_write_X509(fp.get(), xi->x509) != 1) {
            throw std::runtime_error("Failed to write certificate to file");
        }
    }

    // Verify the file was written correctly
    if (std::ifstream(certs_file).peek() == std::ifstream::traits_type::eof()) {
        throw std::runtime_error(SB() << "Certificate file is empty after writing: " << certs_file);
    }

    // Create appropriate symlink
    hash_link = CertFactory::createCertSymlink(certs_file);

    log_warn_printf(certs, "New Root CA certificate installed: %s\n", certs_file.c_str());

#if defined(__linux__)
    log_warn_printf(certs, "To trust this Root CA on Linux:%s", "\n");
    log_warn_printf(certs, "1. Debian/Ubuntu:%s", "\n");
    log_warn_printf(certs, "   sudo cp %s /usr/local/share/ca-certificates/\n", certs_file.c_str());
    log_warn_printf(certs, "   sudo update-ca-certificates%s", "\n");
    log_warn_printf(certs, "2. RHEL/CentOS:%s", "\n");
    log_warn_printf(certs, "   sudo cp %s /etc/pki/ca-trust/source/anchors/\n", certs_file.c_str());
    log_warn_printf(certs, "   sudo update-ca-trust%s", "\n");

#elif defined(__APPLE__)
    log_warn_printf(certs, "To trust this Root CA on macOS:%s", "\n");
    log_warn_printf(certs, "1. Add to System Keychain:%s", "\n");
    log_warn_printf(certs, "   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n",
                    certs_file.c_str());
    log_warn_printf(certs, "2. Create hash symlink:%s", "\n");
    log_warn_printf(certs, "   sudo ln -sf %s /etc/ssl/certs/%s\n",
                    certs_file.c_str(), hash_link.c_str());

#elif defined(_WIN32)
    log_warn_printf(certs, "To trust this Root CA on Windows:%s", "\n");
    log_warn_printf(certs, "1. Double-click %s\n", certs_file.c_str());
    log_warn_printf(certs, "2. Click 'Install Certificate'%s", "\n");
    log_warn_printf(certs, "3. Select 'Local Machine' and click 'Next'%s", "\n");
    log_warn_printf(certs, "4. Select 'Place all certificates in the following store'%s", "\n");
    log_warn_printf(certs, "5. Click 'Browse' and select 'Trusted Root Certification Authorities'%s", "\n");
    log_warn_printf(certs, "6. Click 'Next' and then 'Finish'%s", "\n");

#elif defined(__rtems__)
    log_warn_printf(certs, "For RTEMS systems:%s", "\n");
    log_warn_printf(certs, "Ensure %s is included in your SSL certificate directory\n", certs_file.c_str());
    log_warn_printf(certs, "Hash link: %s\n", hash_link.c_str());
#endif

    return false;
}

ossl_ptr<PKCS12> P12FileFactory::pemStringToP12(std::string password, EVP_PKEY *keys_ptr, std::string pem_string) {
    // Read PEM data into a new BIO
    ossl_ptr<BIO> bio(BIO_new_mem_buf(pem_string.c_str(), -1));
    if (!bio) {
        throw std::runtime_error("Unable to allocate BIO");
    }

    // Get first Cert as Certificate
    ossl_ptr<X509> cert(PEM_read_bio_X509_AUX(bio.get(), NULL, NULL, (void *)password.c_str()));
    if (!cert) {
        throw std::runtime_error("Unable to read certificate");
    }

    // Get the chain
    ossl_ptr<STACK_OF(X509)> certs(sk_X509_new_null());
    if (!certs) {
        throw std::runtime_error("Unable to allocate certificate stack");
    }

    // Get whole of certificate chain and push to certs
    ossl_ptr<X509> ca;
    while (X509 *ca_ptr = PEM_read_bio_X509(bio.get(), NULL, NULL, (void *)password.c_str())) {
        ca = ossl_ptr<X509>(ca_ptr);
        sk_X509_push(certs.get(), ca.release());
    }

    return toP12(password, keys_ptr, cert.get(), certs.get());
}

ossl_ptr<PKCS12> P12FileFactory::toP12(std::string password, EVP_PKEY *keys_ptr, X509 *cert_ptr, STACK_OF(X509) * cert_chain_ptr) {
    // Get the subject name of the certificate
    if (!cert_ptr && !keys_ptr) throw std::runtime_error("No certificate or key provided");

    ossl_ptr<PKCS12> p12;
    if (!cert_ptr) {
        p12.reset(PKCS12_create_ex2(password.c_str(), nullptr, keys_ptr, nullptr, nullptr, 0, 0, 0, 0, 0, nullptr, nullptr, nullptr, nullptr));
    } else {
        auto subject_name(X509_get_subject_name(cert_ptr));
        auto subject_string(X509_NAME_oneline(subject_name, nullptr, 0));
        ossl_ptr<char> subject(subject_string, false);
        if (!subject) {
            throw std::runtime_error("Unable to get the subject of the certificate");
        }

        // Create the p12 structure
        if (sk_X509_num(cert_chain_ptr) < 1) {
            // Use null cert and construct chain from cert
            chainFromRootCertPtr(cert_chain_ptr, cert_ptr);
            ERR_clear_error();
            p12.reset(
                PKCS12_create_ex2(password.c_str(), subject.get(), keys_ptr, nullptr, cert_chain_ptr, 0, 0, 0, 0, 0, nullptr, nullptr, &jdkTrust, nullptr));
        } else {
            ERR_clear_error();
            p12.reset(
                PKCS12_create_ex2(password.c_str(), subject.get(), keys_ptr, cert_ptr, cert_chain_ptr, 0, 0, 0, 0, 0, nullptr, nullptr, &jdkTrust, nullptr));
        }
    }

    if (!p12) {
        throw std::runtime_error(SB() << "Unable to create PKCS12: " << CertFactory::getError());
    }

    return p12;
}

/**
 * @brief Make a chain from a root certificate pointer
 *
 * Dont forget to cleanup after use with sk_X509_free()
 *
 * @param chain the chain pointer to set to the newly crested chain
 * @param root_cert_ptr the root pointer to make the chain from
 */
void P12FileFactory::chainFromRootCertPtr(STACK_OF(X509) * &chain, X509 *root_cert_ptr) {
    chain = sk_X509_new_null();

    if (!chain) {
        throw std::runtime_error("Unable to allocate space for certificate chain");
    }

    if (sk_X509_push(chain, root_cert_ptr) != 1) {
        throw std::runtime_error("Unable to add root certificate to chain");
    }
}

void P12FileFactory::writePKCS12File() {
    // If a pem string has been specified then convert to p12
    ossl_ptr<PKCS12> p12;
    if (!pem_string_.empty()) {
        p12 = pemStringToP12(password_, key_pair_->pkey.get(), pem_string_);
    } else if (cert_ptr_) {
        // If a cert and certs have been specified then convert to p12
        p12 = toP12(password_, key_pair_->pkey.get(), cert_ptr_, certs_ptr_);
    } else if (key_pair_->pkey.get()) {
        // If private key only
        p12 = toP12(password_, key_pair_->pkey.get(), nullptr, nullptr);
    }

    p12_ptr_ = p12.get();

    if (!p12_ptr_) throw std::runtime_error("Insufficient configuration to create certificate");

    // Make a backup of the existing P12 file if it exists
    backupFileIfExists(filename_);

    // Open file for writing.
    file_ptr file(fopen(filename_.c_str(), "wb"));
    if (!file) {
        throw std::runtime_error(SB() << "Error opening P12 file for writing" << filename_);
    }

    // Write PKCS12 object to file and check the result.
    if (i2d_PKCS12_fp(file.get(), p12_ptr_) != 1) throw std::runtime_error(SB() << "Error writing " << usage_ << " data to file: " << filename_);

    // flush the output to the file
    fflush(file.get());

    // close the file
    fclose(file.get());

    p12_ptr_ = nullptr;
    p12.release();   // Free up p12 object
    file.release();  // Close file and release pointer

    chmod(filename_.c_str(),
          S_IRUSR | S_IWUSR);  // Protect P12 file
    log_info_printf(certs, "%s file Created: %s\n", usage_.c_str(), filename_.c_str());
}

bool P12FileFactory::writeRootPemFile(const std::string &pem_string, const bool overwrite) { return createRootPemFile(pem_string, overwrite); }
}  // namespace certs
}  // namespace pvxs
