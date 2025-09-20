/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certfactory.h"

#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_set>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>

#include "openssl.h"
#include "opensslgbl.h"
#include "osiFileName.h"
#include "ownedptr.h"
#include "security.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(certs, "pvxs.certs.cms");

/**
 * Creates a new X.509 certificate from scratch.  It uses the provided public
 * key from the key pair and sets all the appropriate fields based on usage.
 * It then signs the certificate with the issuer's private key if it is
 * specified otherwise, it uses the provided private key (self-signed).
 *
 * @return a unique pointer to an X.509 certificate
 */
ossl_ptr<X509> CertFactory::create() {
    // 0. Make sure the custom certificate extensions have been registered
    ossl::osslInit();

    // 1. Create an empty certificate
    ossl_ptr<X509> certificate(X509_new());

    // 2. Determine issuer: If no issuer, then self-sign, or specify cert & key
    if (!issuer_certificate_ptr_) {
        // ReSharper disable once CppDFALocalValueEscapesFunction
        issuer_certificate_ptr_ = certificate.get();
        issuer_pkey_ptr_ = key_pair_->pkey.get();
        issuer_chain_ptr_ = nullptr;
    } else if (!issuer_pkey_ptr_) {
        throw std::runtime_error("Issuer' private key not provided for signing the certificate");
    }

    // 3. Set the certificate version to 2 (X.509 v3 - 0-based)
    constexpr auto cert_version = 2;
    if (X509_set_version(certificate.get(), cert_version) != 1) {
        throw std::runtime_error("Failed to set certificate version.");
    }
    log_debug_printf(certs, "Set Cert Version: %d\n", cert_version + 1);

    // 4. Set the public key of the certificate using the provided key pair
    if (X509_set_pubkey(certificate.get(), key_pair_->getPublicKey().get()) != 1) {
        throw std::runtime_error("Failed to set public key in certificate.");
    }
    log_debug_printf(certs, "Public Key: %s\n", "<set>");

    // 5. Add an entry in the certificate's subject name using the common name
    setSubject(certificate);

    // 6. Set the issuer symbolic name
    if (X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer_certificate_ptr_)) != 1) {
        throw std::runtime_error("Failed to set issuer name.");
    }
    log_debug_printf(certs, "Issuer Name: %s\n", "<set>");

    // 7. Set the validity period for the certificate using the not_before and
    // not_after times.
    setValidity(certificate);

    // 8. Set the serial number
    setSerialNumber(certificate);

    // 9. Add several extensions to the certificate
    addExtensions(certificate);

    // 10. Set the authority key identifier appropriately
    addExtension(certificate, NID_authority_key_identifier, "keyid:always,issuer:always");

    // 11. Add EPICS status, config subscription, and must-renew-by, extensions, if required and is not CMS itself
    if (!IS_USED_FOR_(usage_, ssl::kForCMS)) {
        const auto issuer_id = CertStatus::getSkId(issuer_certificate_ptr_);
        const auto skid = CertStatus::getSkId(certificate);

        // Check if status subscription should be added based on configuration and no_status flag
        bool add_status_subscription = false;
        if (cert_status_subscription_required_ == YES) {
            add_status_subscription = true;
        } else if (cert_status_subscription_required_ == NO) {
            add_status_subscription = false;
        } else { // DEFAULT
            add_status_subscription = !no_status_;
        }

        if (add_status_subscription) {
            addCustomExtensionByNid(certificate, ossl::NID_SPvaCertStatusURI, getCertStatusURI(cert_pv_prefix_, issuer_id, serial_));
        }

        if (!cert_config_uri_base_.empty()) {
            addCustomExtensionByNid(certificate, ossl::NID_SPvaCertConfigURI, getConfigURI(cert_pv_prefix_, issuer_id, skid));
        }
    }

    // 12. Create cert chain from issuer's chain and issuer's cert
    if (issuer_chain_ptr_) {
        const int num_certs = sk_X509_num(issuer_chain_ptr_);
        log_debug_printf(certs, "Creating Certificate Chain with %d entries\n", num_certs + 1);

        // Add the issuer's certificate too if not already added
        const auto root_cert = sk_X509_value(issuer_chain_ptr_, num_certs - 1);
        const bool already_added = root_cert && X509_cmp(root_cert, issuer_certificate_ptr_) == 0;
        if (!already_added && !sk_X509_push(certificate_chain_.get(), issuer_certificate_ptr_)) {
            throw std::runtime_error(SB() << "Failed to add issuer certificate to certificate chain");
        }

        // Fill with issuer chain certificates if supplied
        for (int i = 0; i < num_certs; ++i) {
            const auto chain_cert = sk_X509_value(issuer_chain_ptr_, i);
            if (!sk_X509_push(certificate_chain_.get(), chain_cert)) {
                throw std::runtime_error("Failed to create certificate chain for new certificate");
            }
        }
    } else
        log_debug_printf(certs, "Creating %s Certificate Chain\n", "*EMPTY*");

    // 13. Sign the certificate with the private key of the issuer
    if (!X509_sign(certificate.get(), issuer_pkey_ptr_, EVP_sha256())) {
        throw std::runtime_error("Failed to sign the certificate");
    }
    log_debug_printf(certs, "Certificate: %s\n", "<SIGNED>");

    // Set the subject key identifier field
    set_skid(certificate);

    return certificate;
}

std::string CertFactory::sign(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data) {
    const ossl_ptr<EVP_MD_CTX> message_digest_context(EVP_MD_CTX_new());
    assert(message_digest_context.get() != nullptr);

    const EVP_MD *message_digest = EVP_sha256();
    assert(message_digest != nullptr);

    assert(EVP_DigestSignInit(message_digest_context.get(), nullptr, message_digest, nullptr, pkey.get()) == 1);
    assert(EVP_DigestSignUpdate(message_digest_context.get(), data.c_str(), data.size()) == 1);

    size_t len = 0;
    assert(EVP_DigestSignFinal(message_digest_context.get(), nullptr, &len) == 1);

    std::string signature(len, '\0');
    assert(EVP_DigestSignFinal(message_digest_context.get(), reinterpret_cast<unsigned char *>(&signature[0]), &len) == 1);
    signature.resize(len);

    return signature;
}

bool CertFactory::verifySignature(const ossl_ptr<EVP_PKEY> &pkey, const std::string &data, const std::string &signature) {
    const ossl_ptr<EVP_MD_CTX> message_digest_context(EVP_MD_CTX_new());
    assert(message_digest_context.get() != nullptr);

    const EVP_MD *message_digest = EVP_sha256();
    assert(message_digest != nullptr);

    assert(EVP_DigestVerifyInit(message_digest_context.get(), nullptr, message_digest, nullptr, pkey.get()) == 1);
    assert(EVP_DigestVerifyUpdate(message_digest_context.get(), data.c_str(), data.size()) == 1);

    if (EVP_DigestVerifyFinal(message_digest_context.get(), reinterpret_cast<const unsigned char *>(&signature[0]), signature.size()) == 1) {
        return true;
    }
    return false;
}

/**
 * Set the subject of the provided certificate.
 *
 * @param certificate A pointer to a certificate
 */
void CertFactory::setSubject(const ossl_ptr<X509> &certificate) const {
    const auto subject_name(X509_get_subject_name(certificate.get()));
    if (subject_name) {
        if (X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(name_.c_str()), -1, -1, 0) != 1) {
            throw std::runtime_error(SB() << "Failed to set common name in certificate subject: " << name_);
        }
        log_debug_printf(certs, "SUBJECT CN: %s\n", name_.c_str());
        if (!country_.empty() &&
            X509_NAME_add_entry_by_txt(subject_name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(country_.c_str()), -1, -1, 0) != 1) {
            throw std::runtime_error(SB() << "Failed to set country in certificate subject: " << name_);
        }
        log_debug_printf(certs, "SUBJECT  C: %s\n", country_.c_str());
        if (!org_.empty() &&
            X509_NAME_add_entry_by_txt(subject_name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(org_.c_str()), -1, -1, 0) != 1) {
            throw std::runtime_error(SB() << "Failed to set org in certificate subject: " << name_);
        }
        log_debug_printf(certs, "SUBJECT  O: %s\n", org_.c_str());
        if (!org_unit_.empty() &&
            X509_NAME_add_entry_by_txt(subject_name, "OU", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(org_unit_.c_str()), -1, -1, 0) != 1) {
            throw std::runtime_error(SB() << "Failed to set country in certificate subject: " << name_);
        }
        log_debug_printf(certs, "SUBJECT OU: %s\n", org_unit_.c_str());
    }
}

/**
 * Set the validity of the given certificate. The validity is set by setting
 * the. not before and not after times using the provided parameters.
 *
 * @param certificate The certificate whose validity is to be set
 */
void CertFactory::setValidity(const ossl_ptr<X509> &certificate) const {
    const auto before = CertDate::toAsn1_Time(not_before_);
    const auto after = CertDate::toAsn1_Time(not_after_);

    if (X509_set1_notBefore(certificate.get(), before.get()) != 1) {
        throw std::runtime_error("Failed to set validity start time in certificate.");
    }
    log_debug_printf(certs, "Not before: %s", std::ctime(&not_before_));

    if (X509_set1_notAfter(certificate.get(), after.get()) != 1) {
        throw std::runtime_error("Failed to set validity end time in certificate.");
    }
    log_debug_printf(certs, "Not after: %s", std::ctime(&not_after_));
}

/**
 * Set the given certificate's serial number. The serial number should
 * be unique for each certificate authority.
 *
 * @param certificate The certificate whose serial number is to be
 */
void CertFactory::setSerialNumber(const ossl_ptr<X509> &certificate) const {
    const ossl_ptr<ASN1_INTEGER> serial_number(ASN1_INTEGER_new());
    if (ASN1_INTEGER_set_uint64(serial_number.get(), serial_) != 1) {
        throw std::runtime_error("Failed to create certificate serial number.");
    }
    if (X509_set_serialNumber(certificate.get(), serial_number.get()) != 1) {
        throw std::runtime_error("Failed to set certificate serial number.");
    }
    log_debug_printf(certs, "Serial Number: %llu\n", static_cast<unsigned long long>(serial_));
}

/**
 * To set all of the required extensions in this certificate.
 * For a certificate to be valid, many certificates are mandatory.
 * This function sets all of the mandatory extensions based on the
 * specified usage of the certificate.
 *
 * @param certificate The certificate whose extensions are to be set
 */
void CertFactory::addExtensions(const ossl_ptr<X509> &certificate) const {
    // Subject Key Identifier
    addExtension(certificate, NID_subject_key_identifier, "hash", certificate.get());

    // Basic Constraints
    auto basic_constraint(IS_USED_FOR_(usage_, ssl::kForCertAuth) ? "critical,CA:TRUE" : "CA:FALSE");
    addExtension(certificate, NID_basic_constraints, basic_constraint);

    // Key usage
    std::string usage;
    if (IS_USED_FOR_(usage_, ssl::kForIntermediateCertAuth)) {
        usage = "digitalSignature,cRLSign,keyCertSign";
    } else if (IS_USED_FOR_(usage_, ssl::kForCertAuth)) {
        usage = "cRLSign,keyCertSign";
    } else if (IS_FOR_A_SERVER_(usage_)) {
        usage = "digitalSignature,keyEncipherment";
    } else {
        usage = "digitalSignature";
    }
    if (!usage.empty()) {
        addExtension(certificate, NID_key_usage, usage.c_str());
    }

    // Extended Key Usage: conditionally set based on `usage_`
    std::string extended_usage;
    if (IS_USED_FOR_(usage_, ssl::kForClientAndServer)) {
        extended_usage = "clientAuth,serverAuth";
    } else if (IS_USED_FOR_(usage_, ssl::kForClient)) {
        extended_usage = "clientAuth";
    } else if (IS_USED_FOR_(usage_, ssl::kForServer)) {
        extended_usage = "serverAuth";
    } else if (IS_USED_FOR_(usage_, ssl::kForIntermediateCertAuth)) {
        extended_usage = "serverAuth,clientAuth,OCSPSigning";
    } else if (IS_USED_FOR_(usage_, ssl::kForCMS)) {
        extended_usage = "serverAuth,OCSPSigning";
    }
    if (!extended_usage.empty()) {
        addExtension(certificate, NID_ext_key_usage, extended_usage.c_str());
    }
}

/**
 * Add an extension to certificate.
 *
 * Each NID_* has a corresponding const X509V3_EXT_METHOD
 * in a crypto/x509/v3_*.c which defines the expected type of the void* value
 * arg.
 *
 * NID_subject_key_identifier   <-> ASN1_OCTET_STRING
 * NID_authority_key_identifier <-> AUTHORITY_KEYID
 * NID_basic_constraints        <-> BASIC_CONSTRAINTS
 * NID_key_usage                <-> ASN1_BIT_STRING
 * NID_ext_key_usage            <-> EXTENDED_KEY_USAGE
 *
 * Use X509V3_CTX automates building these values in the correct way,
 * and then calls low level X509_add1_ext_i2d()
 *
 * see also "man x509v3_config" for explanation of "expr" string.
 */
void CertFactory::addExtension(const ossl_ptr<X509> &certificate, const int nid, const char *value, const X509 *subject) const {
    if (!value) {
        throw std::invalid_argument("Value for the extension cannot be null.");
    }

    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuer_certificate_ptr_, const_cast<X509 *>(subject), nullptr, nullptr, 0);

    const ossl_ptr<X509_EXTENSION> extension(X509V3_EXT_conf_nid(nullptr, &context, nid, value), false);
    if (!extension) {
        const unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Failed to set certificate extension: " << err_msg);
    }

    if (X509_add_ext(certificate.get(), extension.get(), -1) != 1) {
        throw std::runtime_error("Failed to add certificate extension");
    }
    log_debug_printf(certs, "Extension [%*d]: %-*s = \"%s\"\n", 3, nid, 32, nid2String(nid), value);
}

/**
 * Add a time extension by NID to certificate.
 *
 */
/**
 * Add a time extension by NID to certificate.
 *
 */
void CertFactory::addCustomTimeExtensionByNid(const ossl_ptr<X509> &certificate, const int nid, const time_t value) {
    char err_msg[256];

    // Convert time_t to ASN1_TIME
    const auto time_data = CertDate::toAsn1_Time(value);

    // Determine the length of the DER encoding
    const int der_len = i2d_ASN1_TIME(time_data.get(), nullptr);
    if (der_len < 0) {
        const unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to determine DER length: " << err_msg);
    }

    // Allocate buffer for the DER encoding
    std::vector<unsigned char> der_buf(der_len);
    unsigned char* p = der_buf.data();

    // Encode the ASN1_TIME to DER format
    if (i2d_ASN1_TIME(time_data.get(), &p) < 0) {
        const unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to encode ASN1_TIME: " << err_msg);
    }

    // Create an ASN1_OCTET_STRING to hold the DER-encoded data
    const ossl_ptr<ASN1_OCTET_STRING> oct_str(ASN1_OCTET_STRING_new(), false);
    if (!oct_str) {
        const unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to create ASN1_OCTET_STRING: " << err_msg);
    }

    // Set the octet string data
    if (!ASN1_OCTET_STRING_set(oct_str.get(), der_buf.data(), der_len)) {
        const unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to set ASN1_OCTET_STRING data: " << err_msg);
    }

    // Create a new extension using the DER-encoded ASN1_TIME in the octet string
    const ossl_ptr<X509_EXTENSION> ext(X509_EXTENSION_create_by_NID(nullptr, nid, 0, oct_str.get()), false);
    if (!ext) {
        const unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to create X509_EXTENSION: " << err_msg);
    }

    // Add the extension to the certificate
    if (!X509_add_ext(certificate.get(), ext.get(), -1)) {
        const unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Failed to add X509_EXTENSION to certificate: " << err_msg);
    }

    // Get string representation of time for logging
    const CertDate cert_date(value);
    log_debug_printf(certs, "Extension [%*d]: %-*s = \"%s\"\n", 3, nid, 32, nid2String(nid), cert_date.s.c_str());
}

/**
 * Add a string extension by NID to certificate.
 *
 */
void CertFactory::addCustomExtensionByNid(const ossl_ptr<X509> &certificate, const int nid, const std::string &value) {
    char err_msg[256];

    // Construct the string value using ASN1_STRING with IA5String type
    const ossl_ptr<ASN1_IA5STRING> string_data(ASN1_IA5STRING_new(), false);
    if (!string_data) {
        throw std::runtime_error("Adding custom extension: Failed to create ASN1_IA5STRING object");
    }

    // Set the string data using ASN1_STRING_set
    if (!ASN1_STRING_set(string_data.get(), value.c_str(), value.size())) {
        const auto err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to set ASN1_STRING: " << err_msg);
    }

    // Create a new extension using the smart pointer
    const ossl_ptr<X509_EXTENSION> ext(X509_EXTENSION_create_by_NID(nullptr, nid, false, string_data.get()), false);
    if (!ext) {
        const auto err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Adding custom extension: Failed to create X509_EXTENSION: " << err_msg);
    }

    // Add the extension to the certificate
    if (!X509_add_ext(certificate.get(), ext.get(), -1)) {
        const auto err = ERR_get_error();
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        throw std::runtime_error(SB() << "Failed to add X509_EXTENSION to certificate: " << err_msg);
    }

    log_debug_printf(certs, "Extension [%*d]: %-*s = \"%s\"\n", 3, nid, 32, nid2String(nid), value.c_str());
}

/**
 * @brief HELPER FUNCTION: Create a new managed Basic Input Output
 * object that can be used to output in various forms, throw for errors
 *
 * @return new managed BIO object
 */
ossl_ptr<BIO> CertFactory::newBio() {
    ERR_clear_error();
    ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()), false);
    if (!bio) {
        throw std::runtime_error(SB() << "Error: Failed to create bio for output: " << getError());
    }
    return bio;
}

/**
 * @brief HELPER FUNCTION: Output the Basic Input Output object as a string
 *
 * return string representation of the BIO object
 */
std::string CertFactory::bioToString(const ossl_ptr<BIO> &bio) {
    BUF_MEM
    *bptr;                              // to hold pointer to data in the BIO object.
    BIO_get_mem_ptr(bio.get(), &bptr);  // set to point into BIO object

    // Create a std::string from the BIO
    std::string result(bptr->data, bptr->length);

    return result;
}

/**
 * HELPER FUNCTION: Add the given certificate to the given Basic Input Output
 * object
 *
 * @param bio the BIO to add the cert to
 * @param cert the certificate to add to the BIO stream
 */
void CertFactory::writeCertToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<X509> &cert) {
    ERR_clear_error();
    if (!PEM_write_bio_X509(bio.get(), cert.get())) {
        throw std::runtime_error(SB() << "Error writing certificate to BIO: " << getError());
    }
}

/**
 * HELPER FUNCTION: Add the given certificate stack to the given Basic Input
 * Output object
 *
 * @param bio the BIO to add the cert to
 * @param chain the certificate stack to add to the BIO stream
 */
void CertFactory::writeCertsToBio(const ossl_ptr<BIO> &bio, const STACK_OF(X509) * chain) {
    if (chain) {
        ERR_clear_error();
        // Get the number of certificates in the stack
        const int count = sk_X509_num(chain);

        for (int i = 0; i < count; i++) {
            if (!PEM_write_bio_X509(bio.get(), sk_X509_value(chain, i))) {
                log_err_printf(certs, "STACK ERROR: %s\n", getError().c_str());
                throw std::runtime_error(SB() << "Error writing certificate to BIO: " << getError());
            }
        }
    }
}

time_t CertFactory::getNotAfterTimeFromCert(const ossl_ptr<X509> &cert) {
    const ASN1_TIME *cert_not_after = X509_get_notAfter(cert.get());
    const time_t not_after = CertDate::asn1TimeToTimeT(cert_not_after);
    return not_after;
}

std::string CertFactory::certAndCasToPemString(const ossl_ptr<X509> &cert, const STACK_OF(X509) * cert_auth_chain_ptr) {
    const auto bio = newBio();

    writeCertToBio(bio, cert);
    writeCertsToBio(bio, cert_auth_chain_ptr);

    return bioToString(bio);
}

void CertFactory::set_skid(const ossl_ptr<X509> &certificate) {
    int pos = -1;
    std::stringstream skid_ss;

    pos = X509_get_ext_by_NID(certificate.get(), NID_subject_key_identifier, pos);
    X509_EXTENSION *ex = X509_get_ext(certificate.get(), pos);

    const ossl_ptr<ASN1_OCTET_STRING> skid(static_cast<ASN1_OCTET_STRING *>(X509V3_EXT_d2i(ex)), false);

    if (skid != nullptr) {
        // Convert to hexadecimal string
        for (int i = 0; i < skid->length; i++) {
            skid_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(skid->data[i]);
        }
    }

    skid_ = skid_ss.str();
}

}  // namespace certs
}  // namespace pvxs
