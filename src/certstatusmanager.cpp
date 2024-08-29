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

DEFINE_LOGGER(status, "pvxs.cert.status");

// Must be set up with correct values after OpenSSL initialisation to retrieve status PV from certs
int CertStatusManager::NID_PvaCertStatusURI = NID_undef;

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
ParsedOCSPStatus CertStatusManager::parse(shared_array<const uint8_t> ocsp_bytes) {
    auto&& ocsp_response = getOSCPResponse(ocsp_bytes);

    // Get the response status
    int response_status = OCSP_response_status(ocsp_response.get());
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        throw OCSPParseException("OCSP response status not successful");
    }

    // Extract the basic OCSP response
    ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(ocsp_response.get()));
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

    ASN1_GENERALIZEDTIME *this_update = nullptr, *next_update = nullptr, *revoked_time = nullptr;
    int reason = 0;

    auto ocsp_status = static_cast<ocspcertstatus_t>(OCSP_single_get0_status(single_response, &reason, &revoked_time, &this_update, &next_update));

    // Check status validity: less than 1 second old
    OCSP_check_validity(this_update, next_update, 0, 1);

    return {OCSPCertStatus(ocsp_status), StatusDate(this_update), StatusDate(next_update), StatusDate(revoked_time)};
}

// Convert ASN1_INTEGER to a 64-bit unsigned integer
uint64_t CertStatusManager::ASN1ToUint64(ASN1_INTEGER* asn1_number) {
    uint64_t uint64_number = 0;
    for (int i = 0; i < asn1_number->length; ++i) {
        uint64_number = (uint64_number << 8) | asn1_number->data[i];
    }
    return uint64_number;
}

uint64_t CertStatusManager::getSerialNumber(const ossl_ptr<X509>& cert) {
    // Extract the serial number from the certificate
    ASN1_INTEGER* serial_number_asn1 = X509_get_serialNumber(cert.get());
    if (!serial_number_asn1) {
        throw std::runtime_error("Failed to retrieve serial number from certificate");
    }

    // Convert ASN1_INTEGER to a 64-bit unsigned integer
    return ASN1ToUint64(serial_number_asn1);
}

cert_status_ptr<CertStatusManager> CertStatusManager::subscribe(const ossl_ptr<X509>& cert, StatusCallback&& callback) {
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
                  .event([callback_ptr](client::Subscription& sub) {
                      try {
                          auto value = sub.pop();
                          if (!value)
                              (*callback_ptr)({});
                          (*callback_ptr)((CertificateStatus)value);
                      } catch (std::exception& e) {
                          log_warn_printf(status, "Error parsing certificate status: %s\n", e.what());
                          (*callback_ptr)({});
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
    sub_->cancel();
    client_->close();
}

CertificateStatus CertStatusManager::getStatus() { return getStatus(cert_); }

CertificateStatus CertStatusManager::getStatus(const ossl_ptr<X509>& cert) {
    // Extract the issuer's SKID from the certificate
    auto issuer_id = CertStatus::getIssuerId(cert.get());
    auto serial = getSerialNumber(cert);

    // Construct the URI
    auto uri = CertStatus::makeStatusURI(issuer_id, serial);

    // Build and start network operation
    // Disable TLS for get status as the OCSP payload is signed
    // and, we'll enter a recursive loop!!
    auto client(client::Context::fromEnv(true));
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
bool CertStatusManager::verifyOCSPResponse(ossl_ptr<OCSP_BASICRESP>& basic_response) {
    // Get the ca_cert from the response
    pvxs::ossl_ptr<X509> ca_cert;
    OCSP_resp_get0_signer(basic_response.get(), ca_cert.acquire(), nullptr);

    // Initialize the ca_chain
    const pvxs::ossl_shared_ptr<STACK_OF(X509)> ca_chain = pvxs::make_ossl_shared_ptr(OCSP_resp_get0_certs(basic_response.get()));

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

    if (X509_verify_cert(ctx.get()) != 1) {
        throw OCSPParseException("Issuer certificate in OCSP response is not trusted by this host");
    }

    // Add the now trusted ca certificate from the response to the store
    if (X509_STORE_add_cert(store.get(), ca_cert.get()) != 1) {
        throw OCSPParseException("Failed to add issuer certificate to X509_STORE to verify OCSP response");
    }

    // Verify the OCSP response.  Values greater than 0 mean verified
    return OCSP_basic_verify(basic_response.get(), ca_chain.get(), store.get(), 0) > 0;
}

bool CertStatusManager::shouldMonitor(const ossl_ptr<X509>& certificate) {
    // Register the custom NID if it has not yet been registered
    CertStatus::registerCustomNids();
    return (X509_get_ext_by_NID(certificate.get(), CertStatusManager::NID_PvaCertStatusURI, -1) >= 0);
}

/**
 * Get the string value of a custom extension by NID from a certificate.
 *
 */
std::string CertStatusManager::getStatusPvFromCert(const ossl_ptr<X509>& certificate) {
    // Register the custom NID if it has not yet been registered
    // TODO protect from race conditions
    CertStatus::registerCustomNids();

    int extension_index = X509_get_ext_by_NID(certificate.get(), CertStatusManager::NID_PvaCertStatusURI, -1);
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
