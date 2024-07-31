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
#include "ownedptr.h"

namespace pvxs {
namespace certs {


std::vector<uint8_t> createAndSignOCSPResponse(uint64_t serial, CertificateStatus status, time_t revocation_time, const pvxs::ossl_ptr<X509>& ca_cert, const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain) {
    // Create OCSP_CERTID
    auto cert_id = createOCSPCertId(ca_cert, serial);

    // Create OCSP request
    auto req = createOCSPRequest(cert_id);

    // Create OCSP response
    auto basic_resp =
      createOCSPBasicResponse(req, ca_cert, ca_pkey, ca_chain, status);

    // Add status times to the OCSP response
    addStatusToBasicResp(basic_resp, cert_id, status, revocation_time);
    cert_id.release();

    // Serialize OCSP response and return
    return ocspResponseToBytes(basic_resp);
}

// Function to convert a uint64_t serial number to ASN1_INTEGER
pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1(uint64_t serial) {
    pvxs::ossl_ptr<ASN1_INTEGER> asn1_serial(ASN1_INTEGER_new());
    if (!asn1_serial) {
        throw std::runtime_error(SB() << "Error converting serial number: " << serial );
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

// Create an OCSP_CERTID using certificate information
pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(const pvxs::ossl_ptr<X509>& ca_cert, uint64_t serial_number, const EVP_MD* digest) {
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
    pvxs::ossl_ptr<ASN1_INTEGER> serial = uint64ToASN1(serial_number);

    // Create OCSP_CERTID
    pvxs::ossl_ptr<OCSP_CERTID> id(OCSP_cert_id_new(digest, issuer_name, pub_key_bit_string, serial.get()));

    return id;
}


// Create and set up an OCSP request using certificate information
pvxs::ossl_ptr<OCSP_REQUEST> createOCSPRequest(const pvxs::ossl_ptr<OCSP_CERTID>& cert_id) {
    pvxs::ossl_ptr<OCSP_REQUEST> req(OCSP_REQUEST_new());
    OCSP_request_add0_id(req.get(), cert_id.get());
    return req;
}

// Create and set up an OCSP response for a single certificate
pvxs::ossl_ptr<OCSP_BASICRESP> createOCSPBasicResponse(const pvxs::ossl_ptr<OCSP_REQUEST>& req, const pvxs::ossl_ptr<X509>& ca_cert, const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain, CertificateStatus status) {
    pvxs::ossl_ptr<OCSP_BASICRESP> basic_resp(OCSP_BASICRESP_new());

    // There should be only one request in the OCSP request for a single certificate
    OCSP_ONEREQ* one_req = OCSP_request_onereq_get0(req.get(), 0);
    OCSP_CERTID* cert_id = OCSP_onereq_get0_id(one_req);

    // Map CertificateStatus to OCSP status
    int ocsp_status;
    switch (status) {
        case VALID:
            ocsp_status = V_OCSP_CERTSTATUS_GOOD;
            break;
        case EXPIRED:
            ocsp_status = V_OCSP_CERTSTATUS_REVOKED;
            break;
        case REVOKED:
            ocsp_status = V_OCSP_CERTSTATUS_REVOKED;
            break;
        case PENDING_VALIDATION:
        default:
            ocsp_status = V_OCSP_CERTSTATUS_UNKNOWN;
            break;
    }

    // Adding OCSP response for provided certificate ID
    OCSP_basic_add1_status(basic_resp.get(), cert_id, ocsp_status, 0, 0, 0, 0);

    // Adding the CA chain to the response
    for (int i = 0; i < sk_X509_num(ca_chain.get()); i++) {
        X509* cert = sk_X509_value(ca_chain.get(), i);
        OCSP_basic_add1_cert(basic_resp.get(), cert);
    }

    // Signing the response
    OCSP_basic_sign(basic_resp.get(), ca_cert.get(), ca_pkey.get(), EVP_sha256(), ca_chain.get(), 0);
    return basic_resp;
}

// Serialize an OCSP response to a byte array
std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp) {
    unsigned char* resp_der = nullptr;
    int resp_len;

    pvxs::ossl_ptr<OCSP_RESPONSE> ocsp_resp(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp.get()));
    resp_len = i2d_OCSP_RESPONSE(ocsp_resp.get(), &resp_der);

    std::vector<uint8_t> resp_bytes(resp_der, resp_der + resp_len);
    OPENSSL_free(resp_der);

    return resp_bytes;
}

// Function to set OCSP response details
void addStatusToBasicResp(pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp, pvxs::ossl_ptr<OCSP_CERTID>& cert_id, CertificateStatus cert_status, time_t revocation_time) {
    // Set ASN1_TIME objects for revocationTime, thisUpdate, and nextUpdate using pvxs::ossl_ptr
    pvxs::ossl_ptr<ASN1_TIME> revocationTime(nullptr);
    pvxs::ossl_ptr<ASN1_TIME> thisUpdate(ASN1_TIME_new());
    pvxs::ossl_ptr<ASN1_TIME> nextUpdate(ASN1_TIME_new());

    // Set the current time as thisUpdate (i.e., time at which the status was verified)
    ASN1_TIME_set(thisUpdate.get(), time(nullptr));

    // Set nextUpdate time 1 day ahead
    ASN1_TIME_adj(nextUpdate.get(), time(nullptr), 1, 0);

    // Determine the OCSP status and revocation time
    int ocsp_status;
    switch (cert_status) {
        case VALID:
            ocsp_status = V_OCSP_CERTSTATUS_GOOD;
            break;
        case REVOKED:
            ocsp_status = V_OCSP_CERTSTATUS_REVOKED;
            revocationTime.reset(ASN1_TIME_new());
            ASN1_TIME_set(revocationTime.get(), revocation_time);
            break;
        case EXPIRED:
        case PENDING_VALIDATION:
        default:
            ocsp_status = V_OCSP_CERTSTATUS_UNKNOWN;
            break;
    }

    // Add the status to the OCSP response
    if (!OCSP_basic_add1_status(basic_resp.get(), cert_id.get(), ocsp_status, 0, revocationTime.get(), thisUpdate.get(), nextUpdate.get())) {
        throw std::runtime_error("Failed to add status to OCSP response");
    }
}

}  // namespace certs
}  // namespace pvxs
