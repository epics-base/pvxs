/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "idfilereader.h"

#include <fstream>

#include <pvxs/log.h>

namespace pvxs {
namespace certs {

DEFINE_LOGGER(filelogger, "pvxs.p12");

cert_factory_ptr IdFileReader::createReader(const std::string& filename, const std::string& password) {
    const std::string ext = getExtension(filename);
    if (ext == "p12" || ext == "pfx") {
        return make_factory_ptr<P12FileReader>(filename, password);
    }
    throw std::runtime_error(SB() << ": Unsupported keychain file extension (expected p12 or pfx): \"" << (ext.empty() ? "<none>" : ext) << "\"");
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
CertData P12FileReader::getCertDataFromFile() {
    ossl_ptr<X509> cert;
    ossl_ptr<STACK_OF(X509)> chain(sk_X509_new_null(), false);
    std::shared_ptr<KeyPair> key_pair;
    ossl_ptr<EVP_PKEY> pkey;

    // Get cert from configured file
    const file_ptr fp(fopen(filename_.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening keychain file for reading binary contents: \"" << filename_ << "\"");
    }

    const ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), nullptr), false);
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening keychain file as a PKCS#12 object: " << filename_);
    }

    // Try to get private key and certificates
    if (!PKCS12_parse(p12.get(), password_.c_str(), pkey.acquire(), cert.acquire(), chain.acquire())) {
        throw std::runtime_error(SB() << "Error parsing keychain file: " << filename_);
    }

    if (!!cert ^ !!pkey) {
        log_warn_printf(filelogger, "Inconsistency between certificate and key: %s\n", filename_.c_str());
        cert.reset();
        pkey.reset();
    }

    if (!chain) {
        chain.reset(sk_X509_new_null());
    }
    // If no certificate authority certificate chain was provided, then check if the entity cert is self-signed.
    // If it is, add it as a single-entry chain.
    if (!chain || sk_X509_num(chain.get()) == 0) {
        if (cert && X509_check_issued(cert.get(), cert.get()) == X509_V_OK) {
            if (!sk_X509_push(chain.get(), X509_dup(cert.get()))) {
                throw std::runtime_error("Error adding self-signed certificate to chain");
            }
        }
    }

    ossl_shared_ptr<STACK_OF(X509)> shared_chain(std::move(chain));

    return {cert, shared_chain, (pkey ? std::make_shared<KeyPair>(std::move(pkey)) : nullptr)};
}

}  // namespace certs
}  // namespace pvxs
