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
    // Create a BIO for the OCSP response
    ossl_ptr<BIO> bio(BIO_new_mem_buf(ocsp_bytes.data(), static_cast<int>(ocsp_bytes.size())), false);
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
 * Parse OCSP responses from the provided ocsp_bytes response and store the parsed times in the given vectors
 * and return the statuses of each certificate contained in the ocsp_bytes response.
 *
 * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
 *
 * Then parse it and read out the status and the status times
 *
 * @param ocsp_bytes The input byte array containing the OCSP responses data.
 * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
 */
PVXS_API ParsedOCSPStatus CertStatusManager::parse(const shared_array<const uint8_t> ocsp_bytes, X509_STORE *trusted_store_ptr) {
    auto ocsp_response = getOCSPResponse(ocsp_bytes);

    // Get the response status
    int response_status = OCSP_response_status(ocsp_response.get());
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        throw OCSPParseException("OCSP response status not successful");
    }

    // Extract the basic OCSP response
    ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(ocsp_response.get()), false);
    if (!basic_response) {
        throw OCSPParseException("Failed to get basic OCSP response");
    }

    // Verify OCSP response is signed by provided trusted root CA
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

    auto ocsp_status = static_cast<ocspcertstatus_t>(OCSP_single_get0_status(single_response, &reason, &revocation_time, &this_update, &next_update));
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
        auto sub = cert_status_manager->client_->monitor(status_pv).maskConnected(true).maskDisconnected(true).event(
          [trusted_store_ptr, weak_cert_status_manager](client::Subscription &sub) {
              try {
                  auto cert_status_manager = weak_cert_status_manager.lock();
                  if (!cert_status_manager) return;
                  auto update = sub.pop();
                  if (update) {
                      try {
                          auto status_update{PVACertificateStatus(update, trusted_store_ptr)};
                          log_debug_printf(status, "Status subscription received: %s\n", status_update.status.s.c_str());
                          cert_status_manager->status_ = std::make_shared<CertificateStatus>(status_update);
                          (*cert_status_manager->callback_ref)(status_update);
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
          }).exec();
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
 * It verifies the validity of the OCSP response against the contained CA certificate and its chain,
 * and returns a boolean result.
 *
 * Returns true if the OCSP response is valid, indicating that the certificate in question is from a trusted source.
 * Returns false if the OCSP response is invalid or if the certificate in question not to be trusted.
 *
 * Example usage:
 * @code
 *     shared_array<const uint8_t> ocsp_bytes = generateOCSPResponse(); // Generates an OCSP response
 *     ossl_ptr<X509> ca_cert = loadCACertificate(); // Loads a CA certificate
 *     bool isValid = verifyOCSPResponse(ocsp_bytes, ca_cert); // Verifies the OCSP response
 * @endcode
 */
bool CertStatusManager::verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP> &basic_response, X509_STORE *trusted_store_ptr) {
    // get ca_chain from the response (will be verified to see if it's ultimately signed by our trusted root ca)
    auto const_ca_chain_ptr = OCSP_resp_get0_certs(basic_response.get());
    ossl_ptr<STACK_OF(X509)> ca_chain(sk_X509_dup(const_ca_chain_ptr));  // remove const-ness

    // Verify the OCSP response.  Values greater than 0 mean verified
    int verify_result = OCSP_basic_verify(basic_response.get(), ca_chain.get(), trusted_store_ptr, 0);
    if (verify_result <= 0) {
        throw OCSPParseException("OCSP_basic_verify failed");
    }

    return true;
}

/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 * This will return the PV name to monitor for status of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 * @param certificate the certificate to examine
 * @return the PV name to call for status on that certificate
 */
std::string CertStatusManager::getStatusPvFromCert(const ossl_ptr<X509> &certificate) { return getStatusPvFromCert(certificate.get()); }

/**
 * @brief Get the extension from the certificate.
 * This method retrieves the extension from the given certificate using the NID_PvaCertStatusURI.
 * If the extension is not found, it throws a CertStatusNoExtensionException.
 * @param certificate the certificate to retrieve the extension from
 * @return the X509_EXTENSION object if found, otherwise throws an exception
 */
X509_EXTENSION *CertStatusManager::getExtension(const X509 *certificate) {
    int extension_index = X509_get_ext_by_NID(certificate, ossl::SSLContext::NID_PvaCertStatusURI, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find Certificate-Status-PV extension in certificate.");

    // Get the extension object from the certificate
    X509_EXTENSION *extension = X509_get_ext(certificate, extension_index);
    if (!extension) {
        throw CertStatusNoExtensionException("Failed to get Certificate-Status-PV extension from the certificate.");
    }
    return extension;
}

/**
 * @brief Get the string value of a custom extension by NID from a certificate.
 *
 * This will return the PV name to monitor for status of the given certificate.
 * It is stored in the certificate using a custom extension.
 * Exceptions are thrown if it is unable to retrieve the value of the extension
 * or it does not exist.
 *
 * @param certificate the certificate to examine
 * @return the PV name to call for status on that certificate
 */
std::string CertStatusManager::getStatusPvFromCert(const X509 *certificate) {
    auto extension = getExtension(certificate);

    // Retrieve the extension data which is an ASN1_OCTET_STRING object
    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) throw CertStatusNoExtensionException("Failed to get data from the Certificate-Status-PV extension.");

    // Get the data as a string
    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    if (!data) throw CertStatusNoExtensionException("Failed to extract data from ASN1_STRING.");

    int length = ASN1_STRING_length(ext_data);
    if (length < 0) throw CertStatusNoExtensionException("Invalid length of ASN1_STRING data.");

    // Return the data as a std::string
    return std::string(reinterpret_cast<const char *>(data), length);
}
}  // namespace certs
}  // namespace pvxs
