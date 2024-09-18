/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The Certificate status Factory.
 *
 */

#include "certstatusfactory.h"

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include <pvxs/client.h>

#include "certstatus.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

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
 * @param status_date The status date of this status certification, normally now.
 * @param predicated_revocation_time The time of revocation for the certificate if revoked.
 *
 * @see createOCSPCertId
 * @see ocspResponseToBytes
 */
CertificateStatus CertStatusFactory::createOCSPStatus(uint64_t serial, certstatus_t status, StatusDate status_date,
                                                      StatusDate predicated_revocation_time) const {
    // Create OCSP response
    ossl_ptr<OCSP_BASICRESP> basic_resp(OCSP_BASICRESP_new());

    // Set ASN1_TIME objects
    auto status_valid_until_time = StatusDate(status_date.t + cert_status_validity_mins_ * 60);

    auto this_update = status_date.toAsn1_Time();
    auto next_update = status_valid_until_time.toAsn1_Time();
    StatusDate revocation_time_to_use = (time_t)0;  // Default to 0

    // Determine the OCSP status and revocation time
    ocspcertstatus_t ocsp_status;
    switch (status) {
        case VALID:
            ocsp_status = OCSP_CERTSTATUS_GOOD;
            break;
        case REVOKED:
            ocsp_status = OCSP_CERTSTATUS_REVOKED;
            revocation_time_to_use = predicated_revocation_time;
            break;
        default:
            ocsp_status = OCSP_CERTSTATUS_UNKNOWN;
            break;
    }
    auto revocation_asn1_time = revocation_time_to_use.toAsn1_Time();

    // Create OCSP_CERTID
    auto cert_id = createOCSPCertId(serial);

    // Add the status to the OCSP response
    if (!OCSP_basic_add1_status(basic_resp.get(), cert_id.get(), ocsp_status, 0, revocation_asn1_time.get(), this_update.get(), next_update.get())) {
        throw std::runtime_error(SB() << "Failed to add status to OCSP response: " << getError());
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
    const auto ocsp_bytes = shared_array<const uint8_t>(ocsp_response.begin(), ocsp_response.end());

    return CertificateStatus(status, ocsp_status, ocsp_bytes, status_date, status_valid_until_time, revocation_time_to_use);
}

/**
 * @brief Converts a 64-bit unsigned integer (serial number) to an ASN.1 representation.
 *
 * This function converts the serial number
 * to an ASN.1 representation. ASN.1 (Abstract Syntax Notation One) is a standard
 * notation and set of rules for defining the structure of data.
 *
 * @param serial the serial number to convert to ASN1 format
 * @return The ASN.1 representation of the serial number.
 *
 * @see uint64FromASN1()
 */
ossl_ptr<ASN1_INTEGER> CertStatusFactory::uint64ToASN1(const uint64_t& serial) {
    ossl_ptr<ASN1_INTEGER> asn1_serial(ASN1_INTEGER_new(), false);
    if (!asn1_serial) throw std::runtime_error(SB() << "Error converting serial number: " << serial);

    // Convert byte array to ASN1_INTEGER
    ASN1_INTEGER_set_uint64(asn1_serial.get(), serial);
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
ossl_ptr<OCSP_CERTID> CertStatusFactory::createOCSPCertId(const uint64_t& serial, const EVP_MD* digest) const {
    if (!ca_cert_) throw std::runtime_error(SB() << "Can't create OCSP Cert ID: Null Certificate");

    unsigned char issuer_name_hash[EVP_MAX_MD_SIZE];
    unsigned char issuer_key_hash[EVP_MAX_MD_SIZE];

    // Compute issuer_name_hash
    unsigned int issuer_name_hash_len = 0;
    X509_NAME* issuer_name = X509_get_subject_name(ca_cert_.get());
    X509_NAME_digest(issuer_name, digest, issuer_name_hash, &issuer_name_hash_len);

    // Compute issuer_key_hash
    unsigned int issuer_key_hash_len = 0;
    ASN1_BIT_STRING* issuer_key = X509_get0_pubkey_bitstr(ca_cert_.get());
    pvxs::ossl_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(mdctx.get(), digest, nullptr);
    EVP_DigestUpdate(mdctx.get(), issuer_key->data, issuer_key->length);
    EVP_DigestFinal_ex(mdctx.get(), issuer_key_hash, &issuer_key_hash_len);

    // Convert uint64_t serial number to ASN1_INTEGER
    ossl_ptr<ASN1_INTEGER> asn1_serial = uint64ToASN1(serial);

    // Create OCSP_CERTID
    auto cert_id = ossl_ptr<OCSP_CERTID>(OCSP_cert_id_new(digest, issuer_name, issuer_key, asn1_serial.get()), false);
    if (!cert_id) throw std::runtime_error(SB() << "Failed to create cert_id: " << getError());

    return cert_id;
}

/**
 * @brief Converts the given OCSP basic response to bytes.
 *
 * This function takes the OCSP response as input and converts it into a sequence of bytes.
 *
 * @param basic_resp The OCSP response to be converted.
 * @return The sequence of bytes representing the OCSP response object.
 */
std::vector<uint8_t> CertStatusFactory::ocspResponseToBytes(const ossl_ptr<OCSP_BASICRESP>& basic_resp) {
    ossl_ptr<unsigned char> resp_der(nullptr, false);
    ossl_ptr<OCSP_RESPONSE> ocsp_resp(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp.get()));
    int resp_len = i2d_OCSP_RESPONSE(ocsp_resp.get(), resp_der.acquire());

    std::vector<uint8_t> resp_bytes(resp_der.get(), resp_der.get() + resp_len);

    return resp_bytes;
}

}  // namespace certs
}  // namespace pvxs
