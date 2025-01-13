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
#include "openssl.h"
#include "osiFileName.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "security.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

/**
 * @brief Get a key pair from a P12 file
 *
 * @param filename the path to the P12 file
 * @param password the optional password for the file. If blank then the password is not used.
 * @return a shared pointer to the KeyPair object
 * @throw std::runtime_error if the file cannot be opened or parsed
 */
std::shared_ptr<KeyPair> P12FileFactory::getKeyFromFile() {
    file_ptr fp(fopen(filename_.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error getting private key from file: \"" << filename_ << "\": " << strerror(errno));
    }

    ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), nullptr), false);
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening private key file as a PKCS#12 object: " << filename_);
    }

    ossl_ptr<EVP_PKEY> pkey;
    if (!PKCS12_parse(p12.get(), password_.c_str(), pkey.acquire(), nullptr, nullptr)) {
        throw ossl::SSLError(SB() << "Error parsing private key file: " << filename_);
    }

    return std::make_shared<KeyPair>(std::move(pkey));
}

/**
 * @brief Get the certificate data from a P12 file
 *
 * The P12 file is parsed to extract the certificate and chain.
 * If it contains a private key too then it is read and returned in the CertData object.
 *
 * @return a CertData object
 * @throw std::runtime_error if the file cannot be opened or parsed
 */
CertData P12FileFactory::getCertDataFromFile() {
    ossl_ptr<X509> cert;
    STACK_OF(X509) *chain_ptr = nullptr;
    std::shared_ptr<KeyPair> key_pair;
    ossl_ptr<EVP_PKEY> pkey;

    // Get cert from configured file
    file_ptr fp(fopen(filename_.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening keychain file for reading binary contents: \"" << filename_ << "\"");
    }

    ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), nullptr), false);
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening keychain file as a PKCS#12 object: " << filename_);
    }

    // Try to get private key and certificates
    if (!PKCS12_parse(p12.get(), password_.c_str(), pkey.acquire(), cert.acquire(), &chain_ptr)) {
        throw std::runtime_error(SB() << "Error parsing keychain file: " << filename_);
    }

    ossl_shared_ptr<STACK_OF(X509)> chain;
    if (chain_ptr)
        chain = ossl_shared_ptr<STACK_OF(X509)>(chain_ptr);
    else
        chain = ossl_shared_ptr<STACK_OF(X509)>(sk_X509_new_null());

    return {cert, chain, std::make_shared<KeyPair>(std::move(pkey))};
}

/**
 * @brief Convert a PEM string to a P12 object
 *
 * @param password the optional password for the file. If blank then the password is not used.
 * @param keys_ptr the private key to include in the P12 file.  Note that this is required if there are any certificates in the PEM string.
 * @param pem_string the PEM string to convert.  May contain certificates, and certificate chains.  We will
 *                   read the first certificate and use is as the subject of the P12 file.  The remaining certificates
 *                   will be added to the chain of the P12 file.  As a convention the order of the certificates in the
 *                   PEM string is the entity certificate first, intermediate certificates next and then finally the CA certificate.
 * @return an owned pointer to the PKCS12 object
 * @throw std::runtime_error if the PEM string cannot be parsed
 */
ossl_ptr<PKCS12> P12FileFactory::pemStringToP12(const std::string &password, EVP_PKEY *keys_ptr, const std::string &pem_string) {
    // Read PEM data into a new BIO
    ossl_ptr<BIO> bio(BIO_new_mem_buf(pem_string.c_str(), -1), false);
    if (!bio) {
        throw std::runtime_error("Unable to allocate BIO");
    }

    // Get first Cert as Certificate
    ossl_ptr<X509> cert(PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, (void *)password.c_str()), false);
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
    while (X509 *ca_ptr = PEM_read_bio_X509(bio.get(), nullptr, nullptr, (void *)password.c_str())) {
        ca = ossl_ptr<X509>(ca_ptr);
        sk_X509_push(certs.get(), ca.release());
    }

    return toP12(password, keys_ptr, cert.get(), certs.get());
}

/**
 * @brief Convert an entity certificate and the certificate chain to a P12 object
 *
 * @param password the optional password for the p12 object. If blank then the password is not used.
 * @param keys_ptr the private key to include in the p12 object.  Note that this is required if there are any certificates in the PEM string.
 * @param cert_ptr the entity (subject) certificate of the p12 object
 * @param cert_chain_ptr the chain of certificates to include in the p12 object
 * @return a shared pointer to the PKCS12 object
 * @throw std::runtime_error if the certificate and key cannot be found or an error occurs
 */
ossl_ptr<PKCS12> P12FileFactory::toP12(const std::string &password, EVP_PKEY *keys_ptr, X509 *cert_ptr, STACK_OF(X509) * cert_chain_ptr) {
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
            // TODO find a way to write cert-only p12 files
            p12.reset(PKCS12_create_ex2(password.c_str(), subject.get(), keys_ptr, nullptr, cert_chain_ptr, 0, 0, 0, 0, 0, nullptr,
                                        nullptr, &jdkTrust, nullptr));
        } else {
            p12.reset(PKCS12_create_ex2(password.c_str(), subject.get(), keys_ptr, cert_ptr, cert_chain_ptr, 0, 0, 0, 0, 0, nullptr,
                                        nullptr, &jdkTrust, nullptr));
        }
    }

    if (!p12) {
        throw std::runtime_error(SB() << "Unable to create PKCS12: " << CertFactory::getError());
    }

    return p12;
}

/**
 * @brief Write the P12 object to a file
 *
 * If a pem string has been specified then it is converted to a p12 object.
 * If a cert has been specified then it is converted to a p12 object.
 * If the only thing specified is a key pair then it is converted to a p12 object.
 *
 * If the file already exists then it will be backed up.
 *
 * @throw std::runtime_error if the file cannot be written
 */
void P12FileFactory::writePKCS12File() {
    // If a pem string has been specified then convert to p12
    ossl_ptr<PKCS12> p12;
    if (!pem_string_.empty()) {
        p12 = pemStringToP12(password_, key_pair_->pkey.get(), pem_string_);
    } else if (cert_ptr_) {
        // If a cert has been specified then convert to p12
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
    file_ptr file(fopen(filename_.c_str(), "wb"), false);
    if (!file) {
        throw std::runtime_error(SB() << "Error opening P12 file for writing" << filename_);
    }

    // Write PKCS12 object to file
    if (i2d_PKCS12_fp(file.get(), p12_ptr_) != 1) throw std::runtime_error(SB() << "Error writing keychain data to file: " << filename_);

    // flush the output to the file
    fflush(file.get());

    p12_ptr_ = nullptr;

    chmod(filename_.c_str(),
          S_IRUSR | S_IWUSR);  // Protect P12 file
    std::cout << "Keychain file created   : " << filename_ << std::endl;
}
}  // namespace certs
}  // namespace pvxs
