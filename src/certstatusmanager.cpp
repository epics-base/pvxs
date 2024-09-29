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
ossl_ptr<OCSP_RESPONSE> CertStatusManager::getOCSPResponse(const shared_array<const uint8_t>& ocsp_bytes) {
    // Create a BIO for the OCSP response
    ossl_ptr<BIO> bio(BIO_new_mem_buf(ocsp_bytes.data(), static_cast<int>(ocsp_bytes.size())), false);
    if (!bio) {
        throw OCSPParseException("Failed to create BIO for OCSP response");
    }

    // Parse the BIO into an OCSP_RESPONSE
    ossl_ptr<OCSP_RESPONSE> ocsp_response(d2i_OCSP_RESPONSE_bio(bio.get(), nullptr));
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
 */
PVXS_API ParsedOCSPStatus CertStatusManager::parse(const shared_array<const uint8_t> ocsp_bytes) {
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

    // Verify signature of OCSP response
    if (!verifyOCSPResponse(basic_response)) {
        throw OCSPParseException("The OCSP response is not from a trusted source");
    }

    OCSP_SINGLERESP* single_response = OCSP_resp_get0(basic_response.get(), 0);
    if (!single_response) {
        throw OCSPParseException("No entries found in OCSP response");
    }

    ASN1_GENERALIZEDTIME *this_update = nullptr, *next_update = nullptr, *revocation_time = nullptr;
    int reason = 0;

    // Get the OCSP_CERTID from the single response and extract the serial number
    const OCSP_CERTID* cert_id = OCSP_SINGLERESP_get0_id(single_response);
    ASN1_INTEGER* serial = nullptr;
    OCSP_id_get0_info(nullptr, nullptr, nullptr, &serial, const_cast<OCSP_CERTID*>(cert_id));


    auto ocsp_status = static_cast<ocspcertstatus_t>(OCSP_single_get0_status(single_response, &reason, &revocation_time, &this_update, &next_update));
    // Check status validity: less than 5 seconds old
    OCSP_check_validity(this_update, next_update, 0, 5);

    if ( ocsp_status == OCSP_CERTSTATUS_REVOKED && !revocation_time) {
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
 * It will not call the callback unless the status udpdate has been verified and
 * all errors are ignored.
 *
 * @param ctx_cert the certificate to monitor
 * @param callback the callback to call
 * @return a manager of this subscription that you can use to `unsubscribe()`, `waitForValue()` and `getValue()`
 */
cert_status_ptr<CertStatusManager> CertStatusManager::subscribe(ossl_ptr<X509> &&ctx_cert, StatusCallback&& callback) {
    // Construct the URI
    auto uri = CertStatusManager::getStatusPvFromCert(ctx_cert);
    log_debug_printf(status, "Starting Status Subscription: %s\n", uri.c_str());

    // Create a shared_ptr to hold the callback
    auto callback_ptr = std::make_shared<StatusCallback>(std::move(callback));

    // Subscribe to the service using the constructed URI
    // with TLS disabled to avoid recursive loop
    auto client(std::make_shared<client::Context>(client::Context::fromEnv(true)));
    try {
        auto cert_status_manager = cert_status_ptr<CertStatusManager>(new CertStatusManager(std::move(ctx_cert), client));
        log_debug_printf(status, "Subscribing to status: %p\n", cert_status_manager.get());
        auto sub = client->monitor(uri)
                       .maskConnected(true)
                       .maskDisconnected(true)
                       .event([callback_ptr, cert_status_manager](client::Subscription& sub) {
                           try {
                               auto update = sub.pop();
                               if (update) {
                                   auto status_update((PVACertificateStatus)update);
                                   log_debug_printf(status, "Status subscription received: %s\n", status_update.status.s.c_str());
                                   cert_status_manager->status_ = (certstatus_t)status_update.status.i;
                                   cert_status_manager->status_valid_until_date_ = status_update.status_valid_until_date.t + 100;
                                   cert_status_manager->revocation_date_ = status_update.revocation_date.t;
                                   (*callback_ptr)(status_update);
                               }
                           } catch (client::Finished& conn) {
                               log_debug_printf(status, "Subscription Finished: %s\n", conn.what());
                           } catch (client::Connected& conn) {
                               log_debug_printf(status, "Connected Subscription: %s\n", conn.peerName.c_str());
                           } catch (client::Disconnect& conn) {
                               log_debug_printf(status, "Disconnected Subscription: %s\n", conn.what());
                           } catch (std::exception& e) {
                               log_err_printf(status, "Error Getting Subscription: %s\n", e.what());
                           }
                       })
                       .exec();
        cert_status_manager->subscribe(sub);
        log_debug_printf(status, "subscription address: %p\n", cert_status_manager.get());
        return cert_status_manager;
    } catch (std::exception& e) {
        log_err_printf(status, "Error subscribing to certificate status: %s\n", e.what());
        throw CertStatusSubscriptionException(SB() << "Error subscribing to certificate status: " << e.what());
    }
}

/**
 * @brief Unsubscribe from the certificate status monitoring
 */
void CertStatusManager::unsubscribe() {
    client_->hurryUp();
    if (sub_) sub_->cancel();
    if (client_) client_->close();
}

/**
 * @brief Get status from the manager.
 *
 * If status has already been retrieved and it is still valid then use that otherwise go get new status
 *
 * @return the simplified status - does not have ocsp bytes but has been verified and certified
 * @see waitForStatus
 */
PVACertificateStatus CertStatusManager::getStatus() {
    auto status_so_far = PVACertificateStatus(status_, status_valid_until_date_, revocation_date_);
    return isValid() ? status_so_far : getStatus(cert_);
}

PVACertificateStatus CertStatusManager::getStatus(const ossl_ptr<X509>& cert) {
    try {
        auto uri = getStatusPvFromCert(cert);

        // Build and start network operation
        // use an unsecure socket that doesn't monitor files or status
        auto client(client::Context::fromEnvUnsecured());
        auto operation = client.get(uri).exec();

        // wait for it to complete, for up to 2 second.  Very short wait for status
        Value result = operation->wait(2.0);
        client.close();

        return PVACertificateStatus(result);
    } catch (...) {
        return {};
    }
}

/**
 * @brief After we have started a subscription for status we may sometimes want to
 * wait until the status is available.
 * This method waits until the status is returned for up to 3 seconds.  If the status has
 * already been updated by the subscription then it is returned immediately.
 *
 * If not it will start a light weight loop to wait for the status to arrive.
 *
 * @note as long as the status is not UNKNOWN then Certificate status returned will be
 * certified and verified.  However we don't include the byte array in this light weight
 * CertificateStatus that we return.
 *
 * @param loop the event loop to use to wait
 * @return the certificate status at the end of the time - either UNKNOWN still or
 * some new value.
 */
PVACertificateStatus CertStatusManager::waitForStatus(const evbase& loop) {
    auto start(time(nullptr));
    // Timeout 3 seconds
    while ((status_ == UNKNOWN) && time(nullptr) < start + 3) {
        loop.dispatch([]() {});
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return PVACertificateStatus(status_, status_valid_until_date_, revocation_date_);
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
bool CertStatusManager::verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP>& basic_response) {
    // Get the ca_cert from the response
    pvxs::ossl_ptr<X509> ca_cert;
    OCSP_resp_get0_signer(basic_response.get(), ca_cert.acquire(), nullptr);

    // get ca_chain
    auto const_ca_chain_ptr = OCSP_resp_get0_certs(basic_response.get());
    ossl_ptr<STACK_OF(X509)> ca_chain(sk_X509_dup(const_ca_chain_ptr));  // remove const-ness

    // Create a new X509_STORE and add the issuer certificate
    ossl_ptr<X509_STORE> store(X509_STORE_new());
    if (!store) {
        throw OCSPParseException("Failed to create X509_STORE to verify OCSP response");
    }

    if (X509_STORE_set_default_paths(store.get()) != 1) {
        throw OCSPParseException("Failed to load system default CA certificates to verify OCSP response");
    }

    // Set up the store context for verification
    ossl_ptr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
    if (!ctx) {
        throw OCSPParseException("Failed to create X509_STORE_CTX to verify OCSP response");
    }

    if (X509_STORE_CTX_init(ctx.get(), store.get(), ca_cert.get(), nullptr) != 1) {
        throw OCSPParseException("Failed to initialize X509_STORE_CTX to verify OCSP response");
    }

    // Set the custom verification callback
    X509_STORE_CTX_set_verify_cb(ctx.get(), pvxs::ossl::ossl_verify);

    // TODO Remove this DEV option
    // Set the verification flag to accept self-signed certificates
    X509_STORE_CTX_set_flags(ctx.get(), X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_CHECK_SS_SIGNATURE | X509_V_FLAG_TRUSTED_FIRST);

    if (X509_verify_cert(ctx.get()) != 1) {
        throw OCSPParseException("Issuer certificate in OCSP response is not trusted by this host");
    }

    // Add the now trusted ca certificate from the response to the store
    if (X509_STORE_add_cert(store.get(), ca_cert.get()) != 1) {
        throw OCSPParseException("Failed to add issuer certificate to X509_STORE to verify OCSP response");
    }

    // Set the custom verification callback on the store
    X509_STORE_set_verify_cb(store.get(), pvxs::ossl::ossl_verify);

    // Verify the OCSP response.  Values greater than 0 mean verified
    return OCSP_basic_verify(basic_response.get(), ca_chain.get(), store.get(), 0) > 0;
}

/**
 * @brief Call this method to see if we should monitor the given certificate
 * This will return true if there is our custom extension in the certificate.
 * It will produce various exceptions to tell you if it failed to look.
 * Otherwise the boolean returned indicates whether the certificate status is
 * valid only when monitored.
 *
 * @param certificate certificate to check
 * @return true if we should monitor the given certificate
 */
bool CertStatusManager::shouldMonitor(const ossl_ptr<X509>& certificate) {
    return (X509_get_ext_by_NID(certificate.get(), ossl::SSLContext::NID_PvaCertStatusURI, -1) >= 0);
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
std::string CertStatusManager::getStatusPvFromCert(const ossl_ptr<X509>& certificate) {
    int extension_index = X509_get_ext_by_NID(certificate.get(), ossl::SSLContext::NID_PvaCertStatusURI, -1);
    if (extension_index < 0) throw CertStatusNoExtensionException("Failed to find extension index");

    // Get the extension object from the certificate
    X509_EXTENSION* extension = X509_get_ext(certificate.get(), extension_index);
    if (!extension) {
        throw CertStatusNoExtensionException("Failed to get extension from the certificate.");
    }

    // Retrieve the extension data which is an ASN1_OCTET_STRING object
    ASN1_OCTET_STRING* ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) {
        throw CertStatusNoExtensionException("Failed to get data from the extension.");
    }

    // Get the data as a string
    const unsigned char* data = ASN1_STRING_get0_data(ext_data);
    if (!data) {
        throw CertStatusNoExtensionException("Failed to extract data from ASN1_STRING.");
    }

    int length = ASN1_STRING_length(ext_data);
    if (length < 0) {
        throw CertStatusNoExtensionException("Invalid length of ASN1_STRING data.");
    }

    // Return the data as a std::string
    return std::string(reinterpret_cast<const char*>(data), length);
}
}  // namespace certs
}  // namespace pvxs
