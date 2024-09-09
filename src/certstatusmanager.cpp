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

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>
#include <pvxs/log.h>

#include "certstatus.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(status, "pvxs.certs.status");

/**
 * @brief Retrieves the Online Certificate Status Protocol (OCSP) response from the given byte array.
 *
 * The getOSCPResponse function takes a shared_array of uint8_t bytes as input and returns the OCSP response.
 * The OCSP response is a data structure used to validate the status of an SSL certificate. It contains information
 * about the certificate, including its validity and revocation status.
 *
 * @param ocsp_bytes A shared_array of bytes representing the OCSP response.
 * @return The OCSP response as a data structure.
 */
ossl_ptr<OCSP_RESPONSE> CertStatusManager::getOSCPResponse(const shared_array<const uint8_t>& ocsp_bytes) {
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
 * @param config The Configuration to use.
 * @param ocsp_bytes The input byte array containing the OCSP responses data.
 * @param trusted_issuer_cert the certificate of a trusted CA to use to verify the signature of the response.
 */
PVXS_API ParsedOCSPStatus CertStatusManager::parse(shared_array<const uint8_t> ocsp_bytes) {
    auto&& ocsp_response = getOSCPResponse(ocsp_bytes);

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

    auto ocsp_status = static_cast<ocspcertstatus_t>(OCSP_single_get0_status(single_response, &reason, &revocation_time, &this_update, &next_update));

    // Check status validity: less than 1 second old
    OCSP_check_validity(this_update, next_update, 0, 1);

    return {OCSPCertStatus(ocsp_status), this_update, next_update, revocation_time};
}

// Convert ASN1_INTEGER to a 64-bit unsigned integer
uint64_t CertStatusManager::ASN1ToUint64(ASN1_INTEGER* asn1_number) {
    uint64_t uint64_number = 0;
    for (int i = 0; i < asn1_number->length; ++i) {
        uint64_number = (uint64_number << 8) | asn1_number->data[i];
    }
    return uint64_number;
}

uint64_t CertStatusManager::getSerialNumber(const ossl_ptr<X509>& cert) { return getSerialNumber(cert.get()); }

uint64_t CertStatusManager::getSerialNumber(X509* cert) {
    if (!cert) {
        throw std::runtime_error("Can't get serial number: Null certificate");
    }

    // Extract the serial number from the certificate
    ASN1_INTEGER* serial_number_asn1 = X509_get_serialNumber(cert);
    if (!serial_number_asn1) {
        throw std::runtime_error("Failed to retrieve serial number from certificate");
    }

    // Convert ASN1_INTEGER to a 64-bit unsigned integer
    return ASN1ToUint64(serial_number_asn1);
}

cert_status_ptr<CertStatusManager> CertStatusManager::subscribe(const ossl_ptr<X509>&& cert, std::atomic<bool>& stop_flag, StatusCallback&& callback) {
    // Construct the URI
    auto uri = CertStatusManager::getStatusPvFromCert(cert);

    // Create a shared_ptr to hold the callback
    auto callback_ptr = std::make_shared<StatusCallback>(std::move(callback));

    // Subscribe to the service using the constructed URI
    // with TLS disabled to avoid recursive loop
    auto client(std::make_shared<client::Context>(client::Context::fromEnv(true)));
    std::shared_ptr<client::Subscription> sub;
    try {
        sub = client->monitor(uri)
                  .maskConnected(true)
                  .maskDisconnected(true)
                  .event([callback_ptr, &stop_flag](client::Subscription& sub) {
                      try {
                          auto update = sub.pop();
                          if (update) {
                              //                              std::cout <<  update  << std::endl;
                              (*callback_ptr)((CertificateStatus)update);
                          }
                      } catch (client::Finished& conn) {
                          log_debug_printf(status, "Subscription Finished: %s\n", conn.what());
                          stop_flag = true;
                      } catch (client::Connected& conn) {
                          log_debug_printf(status, "Connected Subscription: %s\n", conn.peerName.c_str());
                          stop_flag = true;
                      } catch (client::Disconnect& conn) {
                          log_debug_printf(status, "Disconnected Subscription: %s\n", conn.what());
                          stop_flag = true;
                      } catch (std::exception& e) {
                          log_err_printf(status, "Error Getting Subscription: %s\n", e.what());
                      }
                  })
                  .exec();
        return cert_status_ptr<CertStatusManager>(new CertStatusManager(cert, client, sub));
    } catch (std::exception& e) {
        log_err_printf(status, "Error subscribing to certificate status: %s\n", e.what());
        throw std::runtime_error(SB() << "Error subscribing to certificate status: " << e.what());
    }
}

void CertStatusManager::unsubscribe() {
    client_->hurryUp();
    if (sub_) sub_->cancel();
    if (client_) client_->close();
}

CertificateStatus CertStatusManager::getStatus() { return getStatus(cert_); }

CertificateStatus CertStatusManager::getStatus(const ossl_ptr<X509>& cert) {
    auto uri = getStatusPvFromCert(cert);

    // Build and start network operation
    // use an unsecure socket that doesn't monitor files or status
    auto client(client::Context::fromEnvUnsecured());
    auto operation = client.get(uri).exec();

    // wait for it to complete, for up to 5 seconds.
    Value result = operation->wait(3.0);

    return CertificateStatus(result);
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
 *     shared_array<uint8_t> ocsp_bytes = generateOCSPResponse(); // Generates an OCSP response
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

bool CertStatusManager::shouldMonitor(const ossl_ptr<X509>& certificate) {
    return (X509_get_ext_by_NID(certificate.get(), ossl::SSLContext::NID_PvaCertStatusURI, -1) >= 0);
}

/**
 * Get the string value of a custom extension by NID from a certificate.
 *
 */
std::string CertStatusManager::getStatusPvFromCert(const ossl_ptr<X509>& certificate) {
    int extension_index = X509_get_ext_by_NID(certificate.get(), ossl::SSLContext::NID_PvaCertStatusURI, -1);
    if (extension_index < 0) return "";

    // Get the extension object from the certificate
    X509_EXTENSION* extension = X509_get_ext(certificate.get(), extension_index);
    if (!extension) {
        throw std::runtime_error("Failed to get extension from the certificate.");
    }

    // Retrieve the extension data which is an ASN1_OCTET_STRING object
    ASN1_OCTET_STRING* ext_data = X509_EXTENSION_get_data(extension);
    if (!ext_data) {
        throw std::runtime_error("Failed to get data from the extension.");
    }

    // Get the data as a string
    const unsigned char* data = ASN1_STRING_get0_data(ext_data);
    if (!data) {
        throw std::runtime_error("Failed to extract data from ASN1_STRING.");
    }

    int length = ASN1_STRING_length(ext_data);
    if (length < 0) {
        throw std::runtime_error("Invalid length of ASN1_STRING data.");
    }

    // Return the data as a std::string
    return std::string(reinterpret_cast<const char*>(data), length);
}
}  // namespace certs
}  // namespace pvxs
