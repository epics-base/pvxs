/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The OCSP helper functions.
 *
 */

#include "certstatus.h"

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>

#include "certmgmtservice.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

// For accurate time calculation the start da in a year of each month
const int kMonthStartDays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

// The prefix for Certificate Status PVs in PVA
const std::string kCertStatusPrefix(GET_MONITOR_CERT_STATUS_ROOT);

// The prototype for the PVA certificate status response
Value kStatusPrototype(getStatusPrototype());

/**
 * @brief The prototype of the data returned for a certificate status request
 * Essentially an enum, a serial number and the ocsp response
 *
 * @return The prototype of the data returned for a certificate status request
 */
Value getStatusPrototype() {
    using namespace members;
    nt::NTEnum enum_value;
    nt::NTEnum enum_ocspvalue;

    auto value = TypeDef(TypeCode::Struct,
                         {
                             enum_value.build().as("status"),
                             Member(TypeCode::UInt64, "serial"),
                             Member(TypeCode::String, "state"),
                             enum_ocspvalue.build().as("ocsp_status"),
                             Member(TypeCode::String, "ocsp_state"),
                             Member(TypeCode::String, "ocsp_status_date"),
                             Member(TypeCode::String, "ocsp_certified_until"),
                             Member(TypeCode::String, "ocsp_revocation_date"),
                             Member(TypeCode::UInt8A, "ocsp_response"),
                         })
                     .create();
    shared_array<const std::string> choices(CERT_STATES);
    value["status.value.choices"] = choices.freeze();
    shared_array<const std::string> ocsp_choices(OCSP_CERT_STATES);
    value["ocsp_status.value.choices"] = ocsp_choices.freeze();
    return value;
}

/**
 * @brief Creates and signs an OCSP response for a given certificate.
 *
 * This function takes in a serial number, certificate status, revocation time, CA certificate,
 * CA private key, and CA chain as input parameters. It creates an OCSP_CERTID using the CA
 * certificate and serial number. Then it creates an OCSP request using the OCSP_CERTID.
 * Next, it creates an OCSP basic response using the OCSP request, CA certificate, CA private key,
 * CA chain, and certificate status. The function adds the status times to the OCSP basic response
 * and serializes the response into a byte array. The byte array is then returned.
 *
 * @param serial The serial number of the certificate.
 * @param status The status of the certificate (PENDING_VALIDATION, VALID, EXPIRED, or REVOKED).
 * @param revocation_time The time of revocation for the certificate (0 if not revoked).
 *
 * @see createOCSPCertId
 * @see ocspResponseToBytes
 */
CertificateStatus CertStatusCreator::createOCSPStatus(uint64_t serial, certstatus_t status, StatusDate status_date, StatusDate revocation_time) {
    // Create OCSP response
    pvxs::ossl_ptr<OCSP_BASICRESP> basic_resp(OCSP_BASICRESP_new());

    // Set ASN1_TIME objects for revocationTime, thisUpdate, and nextUpdate using pvxs::ossl_ptr
    auto status_valid_until_time = StatusDate(status_date.t + cert_status_validity_mins_ * 60);

    pvxs::ossl_ptr<ASN1_TIME> thisUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> nextUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> revocationTime(nullptr, false);

    // Set the status date
    ASN1_TIME_set(thisUpdate.get(), status_date.t);

    // Set status validity time
    ASN1_TIME_set(nextUpdate.get(), status_valid_until_time.t);

    // Determine the OCSP status and revocation time
    uint32_t ocsp_status;
    switch (status) {
        case VALID:
            ocsp_status = V_OCSP_CERTSTATUS_GOOD;
            break;
        case REVOKED:
            ocsp_status = V_OCSP_CERTSTATUS_REVOKED;
            revocationTime.reset(ASN1_TIME_new());
            ASN1_TIME_set(revocationTime.get(), revocation_time.t);
            break;
        default:
            ocsp_status = V_OCSP_CERTSTATUS_UNKNOWN;
            break;
    }

    // Create OCSP_CERTID
    auto cert_id = createOCSPCertId(serial);

    // Add the status to the OCSP response
    if (!OCSP_basic_add1_status(basic_resp.get(), cert_id.get(), ocsp_status, 0, revocationTime.get(), thisUpdate.get(), nextUpdate.get())) {
        throw std::runtime_error("Failed to add status to OCSP response");
    }

    // Adding the CA chain to the response
    if (ca_chain_) {
        for (int i = 0; i < sk_X509_num(ca_chain_.get()); i++) {
            X509* cert = sk_X509_value(ca_chain_.get(), i);
            OCSP_basic_add1_cert(basic_resp.get(), cert);
        }
    }

    // Sign the OCSP response
    if (!OCSP_basic_sign(basic_resp.get(), ca_cert_.get(), ca_pkey_.get(), EVP_sha256(), ca_chain_.get(), 0)) {
        throw std::runtime_error("Failed to sign the OCSP response");
    }

    // Serialize OCSP response
    auto ocsp_response = ocspResponseToBytes(basic_resp);
    auto ocsp_bytes = shared_array<const uint8_t>(ocsp_response.begin(), ocsp_response.end());

    return CertificateStatus(status, ocsp_status, ocsp_bytes, status_date, status_valid_until_time, revocation_time);
}

/**
 * @brief Converts a 64-bit unsigned integer (serial number) to an ASN.1 representation.
 *
 * This function converts the serial number
 * to an ASN.1 representation. ASN.1 (Abstract Syntax Notation One) is a standard
 * notation and set of rules for defining the structure of data.
 *
 * @return The ASN.1 representation of the serial number.
 *
 * @see uint64FromASN1()
 */
// Function to convert uint64_t serial number to ASN1_INTEGER
pvxs::ossl_ptr<ASN1_INTEGER> CertStatusCreator::uint64ToASN1(const uint64_t& serial) {
    pvxs::ossl_ptr<ASN1_INTEGER> asn1_serial(ASN1_INTEGER_new());
    if (!asn1_serial) {
        throw std::runtime_error(SB() << "Error converting serial number: " << serial);
    }

    // Convert uint64_t to a byte array
    unsigned char serial_bytes[sizeof(uint64_t)];
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        serial_bytes[i] = (serial >> (8 * (sizeof(uint64_t) - 1 - i))) & 0xff;
    }

    // Convert byte array to ASN1_INTEGER
    ASN1_STRING_set(asn1_serial.get(), serial_bytes, sizeof(serial_bytes));
    return asn1_serial;
}

/**
 * @brief Creates an OCSP certificate ID using the given digest algorithm.
 *
 * This function creates an OCSP (Online Certificate Status Protocol) certificate ID using
 * the provided digest algorithm.  The digest algorithm defaults to `EVP_sha1` if not specified.
 *
 * @param serial serial number of certificate
 * @param digest The digest algorithm used to compute the OCSP ID.  Defaults to EVP_sha1
 *
 * @return The OCSP certificate ID.
 */
pvxs::ossl_ptr<OCSP_CERTID> CertStatusCreator::createOCSPCertId(const uint64_t& serial, const EVP_MD* digest) {
    unsigned char issuer_name_hash[EVP_MAX_MD_SIZE];
    unsigned char issuer_key_hash[EVP_MAX_MD_SIZE];

    // Compute issuer_name_hash
    unsigned int issuer_name_hash_len = 0;
    X509_NAME* issuer_name = X509_get_subject_name(ca_cert_.get());
    X509_NAME_digest(issuer_name, digest, issuer_name_hash, &issuer_name_hash_len);

    // Compute issuer_key_hash
    unsigned int issuer_key_hash_len = 0;
    ASN1_BIT_STRING* pub_key_bit_string = X509_get0_pubkey_bitstr(ca_cert_.get());
    pvxs::ossl_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(mdctx.get(), digest, nullptr);
    EVP_DigestUpdate(mdctx.get(), pub_key_bit_string->data, pub_key_bit_string->length);
    EVP_DigestFinal_ex(mdctx.get(), issuer_key_hash, &issuer_key_hash_len);

    // Convert uint64_t serial number to ASN1_INTEGER
    pvxs::ossl_ptr<ASN1_INTEGER> asn1_serial = uint64ToASN1(serial);

    // Create OCSP_CERTID
    return pvxs::ossl_ptr<OCSP_CERTID>(OCSP_cert_id_new(digest, issuer_name, pub_key_bit_string, asn1_serial.get()));
}

/**
 * @brief Converts the OCSP response to bytes.
 *
 * This function takes the OCSP response as input and converts it into a sequence of bytes.
 *
 * @param basic_resp The OCSP response to be converted.
 * @return The sequence of bytes representing the OCSP response object.
 */
std::vector<uint8_t> CertStatusCreator::ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp) {
    ossl_ptr<unsigned char> resp_der(nullptr, false);
    pvxs::ossl_ptr<OCSP_RESPONSE> ocsp_resp(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp.get()));
    int resp_len = i2d_OCSP_RESPONSE(ocsp_resp.get(), resp_der.acquire());

    std::vector<uint8_t> resp_bytes(resp_der.get(), resp_der.get() + resp_len);

    return resp_bytes;
}

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
    ossl_ptr<BIO> bio(BIO_new_mem_buf(ocsp_bytes.data(), static_cast<int>(ocsp_bytes.size())));
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
OCSPStatus CertStatusManager::parse(shared_array<const uint8_t> ocsp_bytes) {
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

    auto ocsp_status = OCSP_single_get0_status(single_response, &reason, &revoked_time, &this_update, &next_update);

    // Check status validity: less than 1 second old
    OCSP_check_validity(this_update, next_update, 0, 1);

    return OCSPStatus(ocsp_status, ocsp_bytes, this_update, next_update, revoked_time);
}

// Convert ASN1_INTEGER to a 64-bit unsigned integer
uint64_t CertStatusManager::ASN1ToUint64(ASN1_INTEGER* asn1_number) {
    uint64_t uint64_number = 0;
    for (int i = 0; i < asn1_number->length; ++i) {
        uint64_number = (uint64_number << 8) | asn1_number->data[i];
    }
    return uint64_number;
}

/**
 * @brief Converts a value off the wire to a CertificateStatus object
 * @param val value off the wire
 * @return CertificateStatus object
 */
CertificateStatus CertStatusManager::valToStatus(const Value& val) {
    auto status = val["status.value.index"].as<certstatus_t>();
    auto ocsp_status = val["ocsp_status.value.index"].as<uint32_t>();
    auto const ocsp_response = val["ocsp_response"].template as<shared_array<const uint8_t>>();
    auto ocsp_status_detail = CertStatusManager::parse(ocsp_response);
    return CertificateStatus(status, ocsp_status, ocsp_response, ocsp_status_detail.status_date, ocsp_status_detail.status_valid_until_date,
                             ocsp_status_detail.revocation_date);
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

cert_status_ptr<CertStatusManager> CertStatusManager::subscribe(const ossl_ptr<X509>& cert, StatusCallback& callback) {
    // Extract the serial number from the certificate
    ASN1_INTEGER* serial_number_asn1 = X509_get_serialNumber(cert.get());
    if (!serial_number_asn1) {
        throw std::runtime_error("Failed to retrieve serial number from certificate");
    }

    // Convert ASN1_INTEGER to a 64-bit unsigned integer
    uint64_t serial = ASN1ToUint64(serial_number_asn1);

    // Extract the issuer's SKID from the certificate
    std::string issuer_id = getIssuerId(cert.get());

    // Construct the URI
    std::string uri = makeStatusURI(issuer_id, serial);

    // Subscribe to the service using the constructed URI
    auto client(client::Context::fromEnv());
    auto sub = client.monitor(uri)
                   .maskConnected(false)
                   .maskDisconnected(false)
                   .event([&callback](client::Subscription& sub) { callback(valToStatus(sub.pop())); })
                   .exec();

    return cert_status_ptr<CertStatusManager>(new CertStatusManager(cert, sub));
}

void CertStatusManager::unsubscribe() { sub_.get()->cancel(); }

CertificateStatus CertStatusManager::getStatus() { return getStatus(cert_); }

CertificateStatus CertStatusManager::getStatus(const ossl_ptr<X509>& cert) {
    // Extract the issuer's SKID from the certificate
    auto issuer_id = getIssuerId(cert.get());
    auto serial = getSerialNumber(cert);

    // Construct the URI
    auto uri = makeStatusURI(issuer_id, serial);

    // Build and start network operation
    auto client(client::Context::fromEnv());
    auto operation = client.get(uri).exec();

    // wait for it to complete, for up to 5 seconds.
    Value result = operation->wait(3.0);

    return valToStatus(result);
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

std::string getIssuerId(X509* ca_cert_ptr) {
    ossl_ptr<ASN1_OCTET_STRING> skid(reinterpret_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(ca_cert_ptr, NID_subject_key_identifier, nullptr, nullptr)));
    if (!skid.get()) {
        throw std::runtime_error("Failed to get Subject Key Identifier.");
    }

    // Convert first 8 chars to hex
    auto buf = const_cast<unsigned char*>(skid->data);
    std::stringstream ss;
    for (int i = 0; i < skid->length && ss.tellp() < 8; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
    }

    return ss.str();
}

std::string makeStatusURI(std::string& issuer_id, uint64_t& serial) {
    return SB() << GET_MONITOR_CERT_STATUS_ROOT << ":" << issuer_id << ":" << std::setw(16) << std::setfill('0') << serial;
}

}  // namespace certs
}  // namespace pvxs
