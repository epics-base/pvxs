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

static const int kMonthStartDays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

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
 * @param ca_cert The CA certificate used for signing the OCSP response.
 * @param ca_pkey The private key of the CA certificate.
 * @param ca_chain The chain of CA certificates.
 * @return The serialized OCSP response as a vector of uint8_t.
 *
 * @see createOCSPCertId
 * @see ocspResponseToBytes
 */
std::vector<uint8_t> createAndSignOCSPResponse(ConfigCms &config, uint64_t serial, CertStatus status, const pvxs::ossl_ptr<X509>& ca_cert,
                                               const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain,
                                               time_t status_date, time_t revocation_time) {
    // Create OCSP response
    pvxs::ossl_ptr<OCSP_BASICRESP> basic_resp(OCSP_BASICRESP_new());

    // Set ASN1_TIME objects for revocationTime, thisUpdate, and nextUpdate using pvxs::ossl_ptr
    pvxs::ossl_ptr<ASN1_TIME> thisUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> nextUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> revocationTime(nullptr, false);

    // Set the status date
    ASN1_TIME_set(thisUpdate.get(), status_date);

    // Set nextUpdate time to cert_status_validity_mins minutes ahead
    ASN1_TIME_adj(nextUpdate.get(), status_date, 0, config.cert_status_validity_mins * 60);

    // Determine the OCSP status and revocation time
    int ocsp_status;
    switch (status) {
        case VALID:
            ocsp_status = V_OCSP_CERTSTATUS_GOOD;
            break;
        case REVOKED:
            ocsp_status = V_OCSP_CERTSTATUS_REVOKED;
            revocationTime.reset(ASN1_TIME_new());
            ASN1_TIME_set(revocationTime.get(), revocation_time);
            break;
        default:
            ocsp_status = V_OCSP_CERTSTATUS_UNKNOWN;
            break;
    }

    // Create OCSP_CERTID
    auto cert_id = createOCSPCertId(serial, ca_cert);

    // Add the status to the OCSP response
    if (!OCSP_basic_add1_status(basic_resp.get(), cert_id.get(), ocsp_status, 0, revocationTime.get(), thisUpdate.get(), nextUpdate.get())) {
        throw std::runtime_error("Failed to add status to OCSP response");
    }

    // Adding the CA chain to the response
    for (int i = 0; i < sk_X509_num(ca_chain.get()); i++) {
        X509* cert = sk_X509_value(ca_chain.get(), i);
        OCSP_basic_add1_cert(basic_resp.get(), cert);
    }

    // Sign the OCSP response
    if (!OCSP_basic_sign(basic_resp.get(), ca_cert.get(), ca_pkey.get(), EVP_sha256(), ca_chain.get(), 0)) {
        throw std::runtime_error("Failed to sign the OCSP response");
    }

    // Serialize OCSP response and return
    return ocspResponseToBytes(basic_resp);
}

/**
 * @brief Converts a 64-bit unsigned integer (serial number) to an ASN.1 representation.
 *
 * This function takes a 64-bit unsigned integer (a serial number) and converts it
 * to an ASN.1 representation. ASN.1 (Abstract Syntax Notation One) is a standard
 * notation and set of rules for defining the structure of data.
 *
 * @param serial The 64-bit unsigned integer (serial number) to be converted.
 *
 * @return The ASN.1 representation of the given unsigned integer.
 *
 * @see uint64FromASN1()
 */
// Function to convert a uint64_t serial number to ASN1_INTEGER
pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1(uint64_t serial) {
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
 * @brief Creates an OCSP certificate ID using the given parameters.
 *
 * This function creates an OCSP (Online Certificate Status Protocol) certificate ID using the provided
 * serial number, CA (Certification Authority) certificate, and digest algorithm.  The digest
 * algorithm defaults to `EVP_sha1` if not specified.
 *
 * @param serial The serial number of the certificate for which the OCSP ID needs to be created.
 * @param ca_cert The CA certificate used to sign the certificate.
 * @param digest The digest algorithm used to compute the OCSP ID.  Defaults to EVP_sha1
 *
 * @return The OCSP certificate ID.
 */
pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(uint64_t serial, const pvxs::ossl_ptr<X509>& ca_cert, const EVP_MD* digest) {
    if (!ca_cert) {
        throw std::runtime_error("No CA certificate provided");
    }

    unsigned char issuer_name_hash[EVP_MAX_MD_SIZE];
    unsigned char issuer_key_hash[EVP_MAX_MD_SIZE];

    // Compute issuer_name_hash
    unsigned int issuer_name_hash_len = 0;
    X509_NAME* issuer_name = X509_get_subject_name(ca_cert.get());
    X509_NAME_digest(issuer_name, digest, issuer_name_hash, &issuer_name_hash_len);

    // Compute issuer_key_hash
    unsigned int issuer_key_hash_len = 0;
    ASN1_BIT_STRING* pub_key_bit_string = X509_get0_pubkey_bitstr(ca_cert.get());
    pvxs::ossl_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(mdctx.get(), digest, nullptr);
    EVP_DigestUpdate(mdctx.get(), pub_key_bit_string->data, pub_key_bit_string->length);
    EVP_DigestFinal_ex(mdctx.get(), issuer_key_hash, &issuer_key_hash_len);

    // Convert uint64_t serial number to ASN1_INTEGER
    pvxs::ossl_ptr<ASN1_INTEGER> asn1_serial = uint64ToASN1(serial);

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
std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp) {
    unsigned char* resp_der = nullptr;
    int resp_len;

    pvxs::ossl_ptr<OCSP_RESPONSE> ocsp_resp(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp.get()));
    resp_len = i2d_OCSP_RESPONSE(ocsp_resp.get(), &resp_der);

    std::vector<uint8_t> resp_bytes(resp_der, resp_der + resp_len);
    OPENSSL_free(resp_der);

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
time_t tmToTimeTUTC(std::tm& tm) {
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
time_t asn1TimeToTimeT(ASN1_TIME* time) {
    std::tm t{};
    if (ASN1_TIME_to_tm(time, &t) != 1) {
        throw std::runtime_error("Failed to convert ASN1_TIME to tm structure");
    }
    return tmToTimeTUTC(t);
}

// Utility function to convert ASN1_TIME to string (simplified)
std::string asn1TimeToString(ASN1_GENERALIZEDTIME* time) {
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

ossl_ptr<OCSP_RESPONSE> getOSCPResponse(const shared_array<uint8_t>& ocsp_bytes) {
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

bool verifyOCSPResponse(const shared_array<uint8_t>& ocsp_bytes, ossl_ptr<X509> &ca_cert) {
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
    if (X509_STORE_add_cert(store.get(), ca_cert.get()) != 1) {
        throw OCSPParseException("Failed to add issuer certificate to X509_STORE");
    }

    // Verify the OCSP response.  Values greater than 0 mean verified
    return OCSP_basic_verify(basic_response.get(), nullptr, store.get(), 0) > 0;
}

}  // namespace certs
}  // namespace pvxs
