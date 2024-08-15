/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The OCSP helper functions.
 *
 */

#include "ocsphelper.h"

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "certmgmtservice.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

const int OCSPHelper::kMonthStartDays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

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
void OCSPHelper::makeOCSPResponse(uint64_t serial, CertStatus status, time_t status_date, time_t revocation_time) {
    if (process_mode_) throw std::runtime_error("OCSP Helper not configured to create an OCSP response");

    serial_ = serial;

    // Create OCSP response
    pvxs::ossl_ptr<OCSP_BASICRESP> basic_resp(OCSP_BASICRESP_new());

    status_ = status;

    // Set ASN1_TIME objects for revocationTime, thisUpdate, and nextUpdate using pvxs::ossl_ptr
    status_date_ = StatusDate(status_date);
    status_valid_until_time_ = StatusDate(status_date + config_.cert_status_validity_mins * 60);

    pvxs::ossl_ptr<ASN1_TIME> thisUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> nextUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> revocationTime(nullptr, false);

    // Set the status date
    ASN1_TIME_set(thisUpdate.get(), status_date_.t);

    // Set status validity time
    ASN1_TIME_set(nextUpdate.get(), status_valid_until_time_.t);

    // Determine the OCSP status and revocation time
    switch (status) {
        case VALID:
            ocsp_status_ = V_OCSP_CERTSTATUS_GOOD;
            break;
        case REVOKED:
            ocsp_status_ = V_OCSP_CERTSTATUS_REVOKED;
            revocation_time_ = StatusDate(revocation_time);
            revocationTime.reset(ASN1_TIME_new());
            ASN1_TIME_set(revocationTime.get(), revocation_time_.t);
            break;
        default:
            ocsp_status_ = V_OCSP_CERTSTATUS_UNKNOWN;
            break;
    }

    // Create OCSP_CERTID
    auto cert_id = createOCSPCertId();

    // Add the status to the OCSP response
    if (!OCSP_basic_add1_status(basic_resp.get(), cert_id.get(), ocsp_status_, 0, revocationTime.get(), thisUpdate.get(), nextUpdate.get())) {
        throw std::runtime_error("Failed to add status to OCSP response");
    }

    // Adding the CA chain to the response
    for (int i = 0; i < sk_X509_num(ca_chain_.get()); i++) {
        X509* cert = sk_X509_value(ca_chain_.get(), i);
        OCSP_basic_add1_cert(basic_resp.get(), cert);
    }

    // Sign the OCSP response
    if (!OCSP_basic_sign(basic_resp.get(), ca_cert_.get(), ca_pkey_.get(), EVP_sha256(), ca_chain_.get(), 0)) {
        throw std::runtime_error("Failed to sign the OCSP response");
    }

    // Serialize OCSP response and return
    ocsp_response_ = ocspResponseToBytes(basic_resp);
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
// Function to convert a uint64_t serial number to ASN1_INTEGER
pvxs::ossl_ptr<ASN1_INTEGER> OCSPHelper::uint64ToASN1() {
    pvxs::ossl_ptr<ASN1_INTEGER> asn1_serial(ASN1_INTEGER_new());
    if (!asn1_serial) {
        throw std::runtime_error(SB() << "Error converting serial number: " << serial_);
    }

    // Convert uint64_t to a byte array
    unsigned char serial_bytes[sizeof(uint64_t)];
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        serial_bytes[i] = (serial_ >> (8 * (sizeof(uint64_t) - 1 - i))) & 0xff;
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
 * @param digest The digest algorithm used to compute the OCSP ID.  Defaults to EVP_sha1
 *
 * @return The OCSP certificate ID.
 */
pvxs::ossl_ptr<OCSP_CERTID> OCSPHelper::createOCSPCertId(const EVP_MD* digest) {
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
    pvxs::ossl_ptr<ASN1_INTEGER> asn1_serial = uint64ToASN1();

    // Create OCSP_CERTID
    pvxs::ossl_ptr<OCSP_CERTID> id(OCSP_cert_id_new(digest, issuer_name, pub_key_bit_string, asn1_serial.get()));

    return id;
}

/**
 * @brief Converts the OCSP response to bytes.
 *
 * This function takes the OCSP response as input and converts it into a sequence of bytes.
 *
 * @param basic_resp The OCSP response to be converted.
 * @return The sequence of bytes representing the OCSP response object.
 */
std::vector<uint8_t> OCSPHelper::ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp) {
    ossl_ptr<unsigned char> resp_der(nullptr, false);
    pvxs::ossl_ptr<OCSP_RESPONSE> ocsp_resp(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp.get()));
    int resp_len = i2d_OCSP_RESPONSE(ocsp_resp.get(), resp_der.acquire());

    std::vector<uint8_t> resp_bytes(resp_der.get(), resp_der.get() + resp_len);

    return resp_bytes;
}

/**
 * @brief  Manual calculation of time since epoch
 *
 * Gets round problematic timezone issues by relying on tm being in UTC beforehand
 *
 * @param tm tm struct in UTC
 * @return time_t seconds since epoch
 */
time_t OCSPHelper::tmToTimeTUTC(std::tm& tm) {
    int year = 1900 + tm.tm_year;

    // Calculate days up to start of the current year
    time_t days = (year - 1970) * 365 + (year - 1969) / 4  // Leap years
                  - (year - 1901) / 100                    // Excluding non-leap centuries
                  + (year - 1601) / 400;                   // Including leap centuries

    // Calculate days up to the start of the current month within the current year
    days += kMonthStartDays[tm.tm_mon];
    if (tm.tm_mon > 1 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) {
        days += 1;  // Add one day for leap years after February
    }

    // Adjust with the current day in the month (tm_mday starts from 1)
    days += tm.tm_mday - 1;

    // Incorporate hours, minutes, and seconds
    return ((days * 24 + tm.tm_hour) * 60 + tm.tm_min) * 60 + tm.tm_sec;
}

/**
 * @brief Convert from ASN1_TIME found in certificates to time_t format
 * @param time the ASN1_TIME to convert
 *
 * @return the time_t representation of the given ASN1_TIME value
 */
time_t OCSPHelper::asn1TimeToTimeT(ASN1_TIME* time) {
    std::tm t{};
    if (ASN1_TIME_to_tm(time, &t) != 1) {
        throw std::runtime_error("Failed to convert ASN1_TIME to tm structure");
    }
    return tmToTimeTUTC(t);
}

// Utility function to convert ASN1_TIME to string (simplified)
std::string OCSPHelper::asn1TimeToString(ASN1_GENERALIZEDTIME* time) {
    ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()), false);
    if (!bio) {
        throw OCSPParseException("Failed to create BIO for time conversion");
    }
    if (ASN1_GENERALIZEDTIME_print(bio.get(), time) == 0) {
        throw OCSPParseException("Failed to format ASN1_GENERALIZEDTIME");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio.get(), &bptr);
    return std::string(bptr->data, bptr->length);
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
ossl_ptr<OCSP_RESPONSE> OCSPHelper::getOSCPResponse(const shared_array<uint8_t>& ocsp_bytes) {
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
 * @tparam T The data type of the status and revocation date vector elements.
 * @param ocsp_bytes The input byte array containing the OCSP responses data.
 * @param status_date The vector to store the parsed status dates.
 * @param status_certified_until The vector to store the parsed status certified until dates.
 * @param revocation_date The vector to store the parsed revocation dates.
 * @param date_convert_fn The conversion function to convert ASN1_GENERALIZEDTIME to the desired time format.
 *        Defaults to `asn1TimeToString` but can also be `asn1TimeToTimeT`.
 *
 * @return the vector containing OCSP response status codes for each certificate status in the ocsp_bytes response
 */
// Existing implementation of parseOCSPResponses can go here
OCSPHelper::OCSPHelper(const ConfigCms& config, const shared_array<uint8_t>& ocsp_bytes, const pvxs::ossl_ptr<X509>& ca_cert, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain)
    : config_(config),
      ca_cert_(ca_cert),
      ca_pkey_(ossl_ptr_ref<EVP_PKEY>()),
      ca_chain_(ca_chain),
      process_mode_(true),
      serial_(0) {

    // Verify signature of OCSP response
    if (!verifyOCSPResponse(ocsp_bytes)) {
        throw OCSPParseException("The OCSP response is not from a trusted source");
    }

    auto&& ocsp_response = getOSCPResponse(ocsp_bytes);

    int response_status = OCSP_response_status(ocsp_response.get());
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        throw OCSPParseException("OCSP response status not successful");
    }

    // Extract the basic OCSP response
    ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(ocsp_response.get()));
    if (!basic_response) {
        throw OCSPParseException("Failed to get basic OCSP response");
    }

    OCSP_SINGLERESP* single_response = OCSP_resp_get0(basic_response.get(), 0);
    if (!single_response) {
        throw OCSPParseException("No entries found in OCSP response");
    }

    ASN1_GENERALIZEDTIME *this_update = nullptr, *next_update = nullptr, *revoked_time = nullptr;
    int reason = 0;

    ocsp_status_ = OCSP_single_get0_status(single_response, &reason, &revoked_time, &this_update, &next_update);

    // Convert and store dates into strings or tm
    if (this_update) {
        status_date_ = StatusDate(asn1TimeToTimeT(this_update));
    }

    if (next_update) {
        status_valid_until_time_ = StatusDate(asn1TimeToTimeT(next_update));
    }

    if (revoked_time) {
        revocation_time_ = StatusDate(asn1TimeToTimeT(revoked_time));
    }
}

/**
 * Verifies an OCSP response against a given CA certificate.
 *
 * @param ocsp_bytes A shared array of bytes representing the OCSP response.
 * @param ca_cert The CA certificate used for verification.
 *
 * @return Returns true if the OCSP response is valid, false otherwise.
 *
 * This function takes in an OCSP response represented as a shared array of bytes and a CA certificate.
 * It verifies the validity of the OCSP response against the given CA certificate and returns a boolean result.
 * Returns true if the OCSP response is valid, indicating that the certificate in question is valid and not revoked.
 * Returns false if the OCSP response is invalid or if the certificate in question is revoked.
 *
 * Example usage:
 * @code
 *     shared_array<uint8_t> ocsp_bytes = generateOCSPResponse(); // Generates an OCSP response
 *     ossl_ptr<X509> ca_cert = loadCACertificate(); // Loads a CA certificate
 *     bool isValid = verifyOCSPResponse(ocsp_bytes, ca_cert); // Verifies the OCSP response
 * @endcode
 */
bool OCSPHelper::verifyOCSPResponse(const shared_array<uint8_t>& ocsp_bytes) {
    auto response(getOSCPResponse(ocsp_bytes));

    // Create OCSP basic response structure
    ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_response_get1_basic(response.get()));
    if (!basic_response) {
        throw OCSPParseException("Could not retrieve basic OCSP response");
    }

    // Create a new X509_STORE and add the issuer certificate
    ossl_ptr<X509_STORE> store(X509_STORE_new());
    if (!store) {
        throw OCSPParseException("Failed to create X509_STORE");
    }

    // Add the issuer certificate to the store
    if (X509_STORE_add_cert(store.get(), ca_cert_.get()) != 1) {
        throw OCSPParseException("Failed to add issuer certificate to X509_STORE");
    }

    // Verify the OCSP response.  Values greater than 0 mean verified
    return OCSP_basic_verify(basic_response.get(), ca_chain_.get(), store.get(), 0) > 0;
}

}  // namespace certs
}  // namespace pvxs
