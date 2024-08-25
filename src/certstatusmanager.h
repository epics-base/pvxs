/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate status manager class
 *
 *   certstatusmanager.h
 *
 */
#ifndef PVXS_CERTSTATUSMANAGER_H_
#define PVXS_CERTSTATUSMANAGER_H_

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>

#include "certstatus.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = OwnedPtr<T, cert_status_delete<T>>;

/**
 * @brief This class is used to parse OCSP responses and to get/subscribe to certificate status
 *
 * Parsing OCSP responses is carried out by providing the OCSP response buffer
 * to the static `parse()` function. This function will verify the response comes
 * from a trusted source, is well formed, and then will return the `OCSPStatus`
 * it indicates.
 * @code
 *  auto ocsp_status(CertStatusManager::parse(ocsp_response);
 * @endcode
 *
 * To get certificate status call the status `getStatus()` method with the
 * the certificate you want to get status for.  It will make a request
 * to the PVACMS to get certificate status for the certificate. After verifying the
 * authenticity of the response and checking that it is from a trusted
 * source it will return `CertificateStatus`.
 * @code
 *  auto cert_status(CertStatusManager::getStatus(cert);
 * @endcode
 *
 * To subscribe, call the subscribe method with the certificate you want to
 * subscribe to status for and provide a callback that takes a `CertificateStatus`
 * to be notified of status changes.  It will subscribe to PVACMS to monitor changes to
 * to the certificate status for the given certificate. After verifying the
 * authenticity of each status update and checking that it is from a trusted
 * source it will call the callback with a `CertificateStatus` representing the
 * updated status.
 * @code
 *  auto csm = CertStatusManager::subscribe(cert, [] (CertificateStatus &&cert_status) {
 *      std::cout << "STATUS DATE: " << cert_status.status_date.s << std::endl;
 *  });
 *  ...
 *  csm.unsubscribe();
 *  // unsubscribe() automatically called when csm goes out of scope
 * @endcode
 */
class CertStatusManager {
   public:
    using StatusCallback = std::function<void(const CertificateStatus&)>;

    /**
     * @brief Get the status PV from a Cert.
     * This function gets the PVA extension that stores the status PV in the certificate
     * if the certificate must be used in conjunction with a status monitor to check for
     * revoked status.
     * @param cert the certificate to check for the status PV extension
     * @return a blank string if no extension exists, otherwise contains the status PV
     *         e.g. CERT:STATUS:0293823f:098294739483904875
     */
    static std::string getStatusPvFromCert(const ossl_ptr<X509>& cert);

    /**
     * @brief To parse OCSP responses
     *
     * Parsing OCSP responses is carried out by providing the OCSP response buffer.
     * This function will verify the response comes from a trusted source,
     * is well formed, and then will return the `OCSPStatus` it indicates.
     *
     * @param ocsp_bytes the ocsp response
     * @return the OCSP response status
     */
    static OCSPStatus parse(shared_array<const uint8_t> ocsp_bytes);

    /**
     * @brief Used to create a helper that you can use to subscribe to certificate status with
     * Subsequently call subscribe() to subscribe
     *
     * @param config the config to use
     * @param cert the certificate for which you want to subscribe to status
     *
     * @see unsubscribe()
     */
    static cert_status_ptr<CertStatusManager> subscribe(const ossl_ptr<X509>& cert, StatusCallback&& callback);

    /**
     * @brief Get status for a given certificate
     * @param cert the certificate for which you want to get status
     * @return CertificateStatus
     */
    static CertificateStatus getStatus(const ossl_ptr<X509>& cert);

    /**
     * @brief Unsubscribe from listening to certificate status
     *
     * This function idempotent unsubscribe from the certificate status updates
     */
    void unsubscribe();

    /**
     * @brief Get status for a currently subscribed certificate
     * @return CertificateStatus
     */
    CertificateStatus getStatus();
    static uint64_t getSerialNumber(const ossl_ptr<X509>& cert);

    static CertificateStatus valToStatus(const Value& val);

  private:
    CertStatusManager(const ossl_ptr<X509>& cert, std::shared_ptr<client::Subscription> sub) : cert_(cert), sub_(sub) {};
    const ossl_ptr<X509>& cert_;
    const std::shared_ptr<client::Subscription> sub_;

    static ossl_ptr<OCSP_RESPONSE> getOSCPResponse(const shared_array<const uint8_t>& ocsp_bytes);
    static bool verifyOCSPResponse(ossl_ptr<OCSP_BASICRESP>& basic_response);
    static uint64_t ASN1ToUint64(ASN1_INTEGER* asn1_number);

    std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);

    static int NID_PvaCertStatusURI;
};

template <>
struct cert_status_delete<CertStatusManager> {
    inline void operator()(CertStatusManager* base_pointer) {
        if (base_pointer) {
            base_pointer->unsubscribe();  // Idempotent unsubscribe
            delete base_pointer;
        }
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUSMANAGER_H_
