/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate status factory class
 *
 *   certstatusfactory.h
 *
 */
#ifndef PVXS_CERTSTATUSFACTORY_H_
#define PVXS_CERTSTATUSFACTORY_H_

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include "certstatus.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

/**
 * @brief Class used to create OCSP certificate status responses
 *
 * You can create a cert_status_creator and reuse it to make response statuses for
 * certificates providing their serial number and the desired status by calling
 * `createPVACertificateStatus()`.
 *
 * When using the getters (e.g. status()) be aware that they are references into
 * the class and so each time you call createPVACertificateStatus() these reference values
 * change.
 *
 * @code
 *      static auto cert_status_creator(CertStatusFactory(config, ca_cert, ca_pkey, ca_chain));
 *      auto cert_status = cert_status_creator.createPVACertificateStatus(serial, new_state);
 * @endcode
 */
class CertStatusFactory {
   public:
    /**
     * @brief Used to make OCSP responses for given statuses
     * You need the private key of the CA in order to do this.
     * Subsequently call createPVACertificateStatus() to make responses for certificates
     *
     * @param ca_cert the CA certificate to use to sign the OCSP response
     * @param ca_pkey the CA's private key to use to sign the response
     * @param ca_chain the CA's certificate change used to sign any response
     * @param cert_status_validity_mins_ the number of minutes the status is valid for
     *
     * @see createPVACertificateStatus()
     */
    CertStatusFactory(const ossl_ptr<X509>& ca_cert, const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain,
                      uint32_t cert_status_validity_mins = 30, uint32_t cert_status_validity_secs = 0)
        : ca_cert_(ca_cert),
          ca_pkey_(ca_pkey),
          ca_chain_(ca_chain),
          cert_status_validity_mins_(cert_status_validity_mins),
          cert_status_validity_secs_(cert_status_validity_secs) {};

    /**
     * @brief Create OCSP status for certificate identified by serial number
     * The configured ca_cert and ca_chain is encoded into the response so that consumers of the response can determine the issuer
     * and the chain of trust.  The issuer will have to have previously trusted the root certificate as this will
     * be verified.  The response will be signed with the configured private key so that authenticity of the response can be verified.
     *
     * The result contains the signed OCSP response as well as unencrypted OCSP status, status date , status validity date and
     * revocation date if applicable.
     * The PVA status is also included for completeness
     *
     * @param serial the serial number of the certificate to create an OCSP response for
     * @param status the PVA certificate status to create an OCSP response with
     * @param status_date the status date to set in the OCSP response
     * @param predicated_revocation_time the revocation date to set in the OCSP response if applicable
     *
     * @return the Certificate Status containing the signed OCSP response and other OCSP response data.
     */
    PVACertificateStatus createPVACertificateStatus(const ossl_ptr<X509>& cert, certstatus_t status, StatusDate status_date = std::time(nullptr),
                                                    StatusDate predicated_revocation_time = std::time(nullptr)) const;
    PVACertificateStatus createPVACertificateStatus(uint64_t serial, certstatus_t status, StatusDate status_date = std::time(nullptr),
                                                    StatusDate predicated_revocation_time = std::time(nullptr)) const;

    /**
     * @brief Convert ASN1_INTEGER to a 64-bit unsigned integer
     * @param asn1_number
     * @return
     */
    static inline uint64_t ASN1ToUint64(ASN1_INTEGER* asn1_number) {
        uint64_t uint64_number = 0;
        for (int i = 0; i < asn1_number->length; ++i) {
            uint64_number = (uint64_number << 8) | asn1_number->data[i];
        }
        return uint64_number;
    }

    static uint64_t getSerialNumber(const ossl_ptr<X509>& cert);
    static uint64_t getSerialNumber(X509* cert);

   private:
    const ossl_ptr<X509>& ca_cert_;                          // CA Certificate to encode in the OCSP responses
    const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey_;                // CA Certificate's private key to sign the OCSP responses
    const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain_;  // CA Certificate chain to encode in the OCSP responses
    const uint32_t cert_status_validity_mins_;               // The status validity period in minutes to encode in the OCSP responses
    const uint32_t cert_status_validity_secs_;               // The status validity period additional seconds to encode in the OCSP responses

    /**
     * @brief Internal function to create an OCSP CERTID.  Uses CertStatusFactory configuration
     * @param digest the method to use to create the CERTID
     * @return an OCSP CERTID
     */
    pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(const uint64_t& serial, const EVP_MD* digest = EVP_sha1()) const;
    /**
     * @brief Internal function to convert an OCSP_BASICRESP into a byte array
     * @param basic_resp the OCSP_BASICRESP to convert
     * @return a byte array
     */
    static std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);

    /**
     * @brief Internal function to convert a PVA serial number into an ASN1_INTEGER
     * @param serial the serial number to convert
     * @return ASN1_INTEGER
     */
    static pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1(const uint64_t& serial);

    static inline std::string getError() {
        unsigned long err;
        std::string error_string;
        std::string sep;
        while ((err = ERR_get_error()))  // get all error codes from the error queue
        {
            char buffer[256];
            ERR_error_string_n(err, buffer, sizeof(buffer));
            error_string += sep + buffer;
            sep = ", ";
        }
        return error_string;
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUSFACTORY_H_
