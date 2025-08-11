/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The OCSP helper functions.
 *
 */

#include "certstatusmanager.h"

#include <thread>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/sslinit.h>

#include "certstatus.h"
#include "certstatusfactory.h"
#include "configcms.h"
#include "evhelper.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(status, "pvxs.certs.status");

/**
 * @brief Retrieves the Online Certificate Status Protocol (OCSP) response from the given byte array.
 *
 * The getOCSPResponse function takes a shared_array of uint8_t bytes as input and returns the OCSP response.
 * The OCSP response is a data structure used to validate the status of an SSL certificate. It contains information
 * about the certificate, including its validity and revocation status.
 *
 * @param ocsp_bytes A shared_array of bytes representing the OCSP response.
 * @return The OCSP response as a data structure.
 */
ossl_ptr<OCSP_RESPONSE> CertStatusManager::getOCSPResponse(const shared_array<const uint8_t> &ocsp_bytes) {
    return getOCSPResponse(ocsp_bytes.data(), ocsp_bytes.size());
}

/**
 * @brief Retrieves the Online Certificate Status Protocol (OCSP) response from the given byte array.
 *
 * The getOCSPResponse function takes a shared_array of uint8_t bytes as input and returns the OCSP response.
 * The OCSP response is a data structure used to validate the status of an SSL certificate. It contains information
 * about the certificate, including its validity and revocation status.
 *
 * @param ocsp_bytes A pointer to a byte buffer representing the OCSP response.
 * @param ocsp_bytes_len the length of the buffer
 * @return The OCSP response as a data structure.
 */
ossl_ptr<OCSP_RESPONSE> CertStatusManager::getOCSPResponse(const uint8_t *ocsp_bytes, const size_t ocsp_bytes_len) {
    // Create a BIO for the OCSP response
    const ossl_ptr<BIO> bio(BIO_new_mem_buf(ocsp_bytes, static_cast<int>(ocsp_bytes_len)), false);
    if (!bio) {
        throw OCSPParseException("Failed to create BIO for OCSP response");
    }

    // Parse the BIO into an OCSP_RESPONSE
    ossl_ptr<OCSP_RESPONSE> ocsp_response(d2i_OCSP_RESPONSE_bio(bio.get(), nullptr), false);
    if (!ocsp_response) {
        throw OCSPParseException("Failed to parse OCSP response");
    }

    return ocsp_response;
}

/**
 * Parse OCSP responses from the provided ocsp_bytes response
 * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
 *
 * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_bytes The input byte buffer pointer containing the OCSP responses data.
 * @param ocsp_bytes_len the length of the byte buffer
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 */
PVXS_API ParsedOCSPStatus CertStatusManager::parse(const uint8_t *ocsp_bytes, const size_t ocsp_bytes_len, X509_STORE *trusted_store_ptr) {
    auto ocsp_response = getOCSPResponse(ocsp_bytes, ocsp_bytes_len);
    return parse(ocsp_response, trusted_store_ptr);
}

/**
 * Parse OCSP responses from the provided ocsp_bytes response
 * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
 *
 * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_bytes The input byte array containing the OCSP responses data.
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 */
PVXS_API ParsedOCSPStatus CertStatusManager::parse(const shared_array<const uint8_t> &ocsp_bytes, X509_STORE *trusted_store_ptr) {
    const auto ocsp_response = getOCSPResponse(ocsp_bytes);
    return parse(ocsp_response, trusted_store_ptr);
}

/**
 * Parse OCSP responses from the provided OCSP response object
 * and return the parsed out status of the certificate which is the subject of the OCSP response.
 *
 * First verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_response An OCSP response object.
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 */
PVXS_API ParsedOCSPStatus CertStatusManager::parse(const ossl_ptr<OCSP_RESPONSE> &ocsp_response, X509_STORE *trusted_store_ptr) {
    // Get the response status
    const int response_status = OCSP_response_status(ocsp_response.get());
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        throw OCSPParseException("OCSP response status not successful");
    }

    // Extract the basic OCSP response
    const ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(ocsp_response.get()), false);
    if (!basic_response) {
        throw OCSPParseException("Failed to get basic OCSP response");
    }

    // Verify OCSP response is signed by provided trusted root certificate authority
    verifyOCSPResponse(basic_response, trusted_store_ptr);

    OCSP_SINGLERESP *single_response = OCSP_resp_get0(basic_response.get(), 0);
    if (!single_response) {
        throw OCSPParseException("No entries found in OCSP response");
    }

    ASN1_GENERALIZEDTIME *this_update = nullptr, *next_update = nullptr, *revocation_time = nullptr;
    int reason = 0;

    // Get the OCSP_CERTID from the single response and extract the serial number
    const OCSP_CERTID *cert_id = OCSP_SINGLERESP_get0_id(single_response);
    ASN1_INTEGER *serial = nullptr;
    OCSP_id_get0_info(nullptr, nullptr, nullptr, &serial, const_cast<OCSP_CERTID *>(cert_id));

    const auto ocsp_status = static_cast<ocspcertstatus_t>(OCSP_single_get0_status(single_response, &reason, &revocation_time, &this_update, &next_update));
    // Check status validity: less than 5 seconds old
    OCSP_check_validity(this_update, next_update, 0, 5);

    if (ocsp_status == OCSP_CERTSTATUS_REVOKED && !revocation_time) {
        throw OCSPParseException("Revocation time not set when status is REVOKED");
    }

    return {CertStatusFactory::ASN1ToUint64(serial), OCSPCertStatus(ocsp_status), this_update, next_update, revocation_time};
}

/**
 * @brief Subscribe to status updates for the given certificate,
 * calling the given callback with a CertificateStatus if the status changes.
 * It also sets members with the pva certificate status, the status validity period, and a
 * revocation date if applicable.
 *
 * It will not call the callback unless the status update has been verified and
 * all errors are ignored.
 *
 * Important Note: This implementation relies on trusted_root being stored in the context and
 * so having a longer scope than the subscription in that same context or the peer status
 * subscriptions in the same context too.  The reference needs to remain valid until the subscription
 * is cancelled.
 *
 * @param ctx_cert the certificate to monitor
 * @param callback the callback to call
 * @param trusted_store_ptr the trusted store to verify the status response against
 * @return a manager of this subscription that you can use to `unsubscribe()`, `waitForValue()` and `getValue()`
 */
cert_status_ptr<CertStatusManager> CertStatusManager::subscribe(X509_STORE *trusted_store_ptr, const std::string &status_pv, StatusCallback &&callback) {
    // Construct the URI
    log_debug_printf(status, "Starting Status Subscription: %s\n", status_pv.c_str());

    // Create a shared_ptr to hold the callback
    auto fn = std::make_shared<StatusCallback>(std::move(callback));

    try {
        // Subscribe to the service using the constructed URI
        // with TLS disabled to avoid recursive loop
        auto client(std::make_shared<client::Context>(client::Context::fromEnv(true)));
        cert_status_ptr<CertStatusManager> cert_status_manager(new CertStatusManager(std::move(client)));
        cert_status_manager->callback_ref = std::move(fn);
        std::weak_ptr<CertStatusManager> weak_cert_status_manager(cert_status_manager);

        log_debug_printf(status, "Subscribing to peer status: %s", "");
        auto sub = cert_status_manager->client_->monitor(status_pv)
                       .maskConnected(true)
                       .maskDisconnected(true)
                       .event([trusted_store_ptr, weak_cert_status_manager](client::Subscription &s) {
                           try {
                               const auto csm = weak_cert_status_manager.lock();
                               if (!csm) return;
                               const auto update = s.pop();
                               if (update) {
                                   try {
                                       auto status_update{PVACertificateStatus(update, trusted_store_ptr)};
                                       log_debug_printf(status, "Status subscription received: %s\n", status_update.status.s.c_str());
                                       csm->status_ = std::make_shared<CertificateStatus>(status_update);
                                       (*csm->callback_ref)(status_update);
                                   } catch (OCSPParseException &e) {
                                       log_debug_printf(status, "Ignoring invalid status update: %s\n", e.what());
                                   } catch (std::invalid_argument &e) {
                                       log_debug_printf(status, "Ignoring invalid status update: %s\n", e.what());
                                   } catch (std::exception &e) {
                                       log_err_printf(status, "%s\n", e.what());
                                   }
                               }
                           } catch (client::Finished &conn) {
                               log_debug_printf(status, "Subscription Finished: %s\n", conn.what());
                           } catch (client::Connected &conn) {
                               log_debug_printf(status, "Connected Subscription: %s\n", conn.peerName.c_str());
                           } catch (client::Disconnect &conn) {
                               log_debug_printf(status, "Disconnected Subscription: %s\n", conn.what());
                           } catch (std::exception &e) {
                               log_err_printf(status, "Error Getting Subscription: %s\n", e.what());
                           }
                       })
                       .exec();
        cert_status_manager->subscribe(sub);
        log_debug_printf(status, "subscription address: %p\n", cert_status_manager.get());
        return cert_status_manager;
    } catch (std::exception &e) {
        log_debug_printf(status, "Error subscribing to certificate status: %s\n", e.what());
        throw CertStatusSubscriptionException(SB() << "Error subscribing to certificate status: " << e.what());
    }
}

/**
 * @brief Unsubscribe from the certificate status monitoring
 */
void CertStatusManager::unsubscribe() {
    if (sub_) sub_->cancel();
}

/**
 * Verifies an OCSP response comes from a trusted source.
 *
 * @param basic_response An OCSP basic response.
 *
 * @return Returns true if the OCSP response is valid, false otherwise.
 *
 * This function takes in an OCSP response and verifies that it was signed by a trusted source.
 * It verifies the validity of the OCSP response against the contained certificate authority certificate
 * and its chain, and returns a boolean result.
 *
 * Returns true if the OCSP response is valid, indicating that the certificate in question is from a trusted source.
 * Returns false if the OCSP response is invalid or if the certificate in question not to be trusted.
 */
bool CertStatusManager::verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP> &basic_response, X509_STORE *trusted_store_ptr) {
    // get cert_auth_cert_chain from the response (will be verified to see if it's ultimately signed by our trusted root certificate authority)
    const auto const_cert_auth_cert_chain_ptr = OCSP_resp_get0_certs(basic_response.get());
    ossl_ptr<STACK_OF(X509)> cert_auth_cert_chain(sk_X509_dup(const_cert_auth_cert_chain_ptr));  // remove const-ness

    // Verify the OCSP response.  Values greater than 0 mean verified
    const int verify_result = OCSP_basic_verify(basic_response.get(), cert_auth_cert_chain.get(), trusted_store_ptr, 0);
    if (verify_result <= 0) {
        // Get detailed error information
        const unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));

        throw OCSPParseException(SB() << std::string("OCSP_basic_verify failed: ") << err_buf);
    }

    return true;
}

/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 * This will return the PV name to monitor for status of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 * @param cert the certificate to examine
 * @return the PV name to call for status on that certificate
 */
std::string CertStatusManager::getStatusPvFromCert(const ossl_ptr<X509> &cert) { return getStatusPvFromCert(cert.get()); }

std::string CertStatusManager::getConfigPvFromCert(const ossl_ptr<X509> &cert) { return getConfigPvFromCert(cert.get()); }

time_t CertStatusManager::getExpirationDateFromCert(const ossl_ptr<X509> &cert) { return getExpirationDateFromCert(cert.get()); }
time_t CertStatusManager::getRenewByFromCert(const ossl_ptr<X509> &cert) { return getRenewByFromCert(cert.get()); }


/**
 * @brief Get the extension from the certificate.
 * This method retrieves the extension from the given certificate using the NID_PvaCertStatusURI.
 * If the extension is not found, it throws a CertStatusNoExtensionException.
 * @param certificate the certificate to retrieve the extension from
 * @return the X509_EXTENSION object, if found, otherwise throws an exception
 */
X509_EXTENSION *CertStatusManager::getStatusExtension(const X509 *certificate) {
    const int extension_index = X509_get_ext_by_NID(certificate, ossl::NID_SPvaCertStatusURI, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find Certificate-Status-PV extension in certificate.");

    // Get the extension object from the certificate
    X509_EXTENSION *extension = X509_get_ext(certificate, extension_index);
    if (!extension) {
        throw CertStatusNoExtensionException("Failed to get Certificate-Status-PV extension from the certificate.");
    }
    return extension;
}

/**
 * @brief Get the extension from the certificate.
 * This method retrieves the extension from the given certificate using the NID_PvaCertConfigURI.
 * If the extension is not found, it throws a CertConfigNoExtensionException.
 * @param certificate the certificate to retrieve the extension from
 * @return the X509_EXTENSION object, if found, otherwise throws an exception
 */
X509_EXTENSION *CertStatusManager::getConfigExtension(const X509 *certificate) {
    const int extension_index = X509_get_ext_by_NID(certificate, ossl::NID_SPvaCertConfigURI, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find Certificate-Config-PV extension in certificate.");

    // Get the extension object from the certificate
    X509_EXTENSION *extension = X509_get_ext(certificate, extension_index);
    if (!extension) {
        throw CertStatusNoExtensionException("Failed to get Certificate-Config-PV extension from the certificate.");
    }
    return extension;
}

/**
 * @brief Get the extension from the certificate.
 * This method retrieves the extension from the given certificate using the NID_PvaCertConfigURI.
 * If the extension is not found, it throws a CertConfigNoExtensionException.
 * @param certificate the certificate to retrieve the extension from
 * @return the X509_EXTENSION object, if found, otherwise throws an exception
 */
X509_EXTENSION *CertStatusManager::getRenewByDateExtension(const X509 *certificate) {
    const int extension_index = X509_get_ext_by_NID(certificate, ossl::NID_SPvaRenewByDate, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find Renew By Date extension in certificate.");

    // Get the extension object from the certificate
    X509_EXTENSION *extension = X509_get_ext(certificate, extension_index);
    if (!extension) throw CertStatusNoExtensionException("Failed to get Renew By Date extension from the certificate.");
    return extension;
}

std::string CertStatusManager::getIssuerIdFromCert(const X509* cert_ptr) {
    const ossl_ptr<AUTHORITY_KEYID> akid(static_cast<AUTHORITY_KEYID*>(X509_get_ext_d2i(cert_ptr, NID_authority_key_identifier, nullptr, nullptr)),
                                       false);
    if (!akid || !akid->keyid) throw CertStatusNoExtensionException("Failed to get Authority Key Identifier.");

    // Convert the first 8 chars to hex
    std::stringstream ss;
    for (int i = 0; i < akid->keyid->length && ss.tellp() < 8; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(akid->keyid->data[i]);
    }

    return ss.str();
}

std::string CertStatusManager::getSerialFromCert(const X509* cert_ptr) {
    const ASN1_INTEGER* serial = X509_get0_serialNumber(cert_ptr);
    if (!serial) {
        throw CertStatusNoExtensionException("Failed to get Serial Number from certificate.");
    }

    // Convert ASN1_INTEGER to BIGNUM
    const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr), false);
    if (!bn) {
        throw CertStatusNoExtensionException("Failed to convert Serial Number to BIGNUM.");
    }

    // Convert BIGNUM to decimal string
    char* decimal_str = BN_bn2dec(bn.get());
    if (!decimal_str) {
        throw CertStatusNoExtensionException("Failed to convert Serial Number to string.");
    }

    // Create a C++ string and free the C string
    std::string result(decimal_str);
    OPENSSL_free(decimal_str);

    return result;
}

std::string CertStatusManager::getCertIdFromCert(const X509 *cert) {
    const std::string issuer_id = getIssuerIdFromCert(cert);
    const std::string serial = getSerialFromCert(cert);

    return SB() << issuer_id << ":" << std::setw(20) << std::setfill('0') << serial;
}


/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 *
 * This will return the PV name to monitor for status of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 *
 * @param cert the certificate to examine
 * @return the PV name to call for status on that certificate
 */
std::string CertStatusManager::getStatusPvFromCert(const X509 *cert) {
    const auto extension = getStatusExtension(cert);

    // Retrieve the extension data which is an ASN1_OCTET_STRING object
    const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) throw CertStatusNoExtensionException("Failed to get data from the Certificate-Status-PV extension.");

    // Get the data as a string
    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    if (!data) throw CertStatusNoExtensionException("Failed to extract data from ASN1_STRING.");

    const int length = ASN1_STRING_length(ext_data);
    if (length < 0) throw CertStatusNoExtensionException("Invalid length of ASN1_STRING data.");

    // Return the data as a std::string
    return std::string(reinterpret_cast<const char *>(data), length);
}

/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 *
 * This will return the PV name to monitor for config of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 *
 * @param cert the certificate to examine
 * @return the PV name to call for config on that certificate
 */
std::string CertStatusManager::getConfigPvFromCert(const X509 *cert) {
    const auto extension = getConfigExtension(cert);

    // Retrieve the extension data, which is an ASN1_OCTET_STRING object
    const ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) throw CertStatusNoExtensionException("Failed to get data from the Certificate-Status-PV extension.");

    // Get the data as a string
    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    if (!data) throw CertStatusNoExtensionException("Failed to extract data from ASN1_STRING.");

    const int length = ASN1_STRING_length(ext_data);
    if (length < 0) throw CertStatusNoExtensionException("Invalid length of ASN1_STRING data.");

    // Return the data as a std::string
    return std::string(reinterpret_cast<const char *>(data), length);
}

time_t CertStatusManager::getRenewByFromCert(const X509 *cert) {
    X509_EXTENSION *extension = getRenewByDateExtension(cert);

    // Extract the ASN1_OCTET_STRING data from the extension
    const auto octet_string = X509_EXTENSION_get_data(extension);
    if (!octet_string) throw CertStatusNoExtensionException("Failed to get data from the Renew By Date extension.");

    // Create a pointer to the data for d2i_ASN1_TIME
    const auto *p = octet_string->data;

    // Parse the DER-encoded ASN1_TIME
    const ossl_ptr<ASN1_TIME> asn1_time(d2i_ASN1_TIME(nullptr, &p, octet_string->length), false);
    if (!asn1_time) {
        // Add debug information
        log_debug_printf(status, "Extension data length: %d", octet_string->length);
        for(auto i = 0; i < std::min(octet_string->length, 20); i++) {
            log_debug_printf(status, "Byte %d: 0x%02x", i, octet_string->data[i]);
        }
        throw CertStatusNoExtensionException("Failed to parse ASN1_TIME from the Renew By Date extension.");
    }

    return CertDate::asn1TimeToTimeT(asn1_time.get());
}

time_t CertStatusManager::getExpirationDateFromCert(const X509 *cert) {
    // Get the notAfter field directly from the certificate
    const auto *expiration = X509_get0_notAfter(cert);
    if (!expiration) {
        throw CertStatusNoExtensionException("Failed to get expiration date from certificate");
    }

    // Convert ASN1_TIME to time_t using the CertDate utility
    return CertDate::asn1TimeToTimeT(expiration);
}
}  // namespace certs
}  // namespace pvxs
