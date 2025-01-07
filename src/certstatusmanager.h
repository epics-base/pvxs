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

#include <functional>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// #include <pvxs/client.h>
#include <pvxs/sharedArray.h>

#include "certstatus.h"
#include "evhelper.h"
#include "ownedptr.h"

namespace pvxs {

// Forward def
namespace client {
class Context;
struct Subscription;
}  // namespace client

namespace certs {

template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = ossl_shared_ptr<T, cert_status_delete<T>>;

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
    friend struct OCSPStatus;
    CertStatusManager() = delete;

    virtual ~CertStatusManager() = default;

    using StatusCallback = std::function<void(const PVACertificateStatus&)>;

    static bool shouldMonitor(const ossl_ptr<X509>& certificate);
    static bool shouldMonitor(const X509* certificate);
    std::shared_ptr<StatusCallback> callback_ref{}; // Option placeholder for ref to callback if used

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
     * @brief Get the custom status extension from the given certificate
     * @param certificate the certificate to retrieve the status extension from
     * @return the extension
     * @throws CertStatusNoExtensionException if no extension is present in the certificate
     */
    static X509_EXTENSION* getExtension(const X509* certificate);

    /**
     * @brief Determine if status monitoring is required for the given certificate
     * @param certificate the certificate to check
     * @return true if certificate monitoring is required
     */
    static bool statusMonitoringRequired(const X509* certificate);

    /**
     * @brief Get the status PV from a Cert.
     * This function gets the PVA extension that stores the status PV in the certificate
     * if the certificate must be used in conjunction with a status monitor to check for
     * revoked status.
     * @param cert the certificate to check for the status PV extension
     * @return a blank string if no extension exists, otherwise contains the status PV
     *         e.g. CERT:STATUS:0293823f:098294739483904875
     */
    static std::string getStatusPvFromCert(const X509* cert);

    /**
     * @brief Used to create a helper that you can use to subscribe to certificate status with
     * Subsequently call subscribe() to subscribe
     *
     * @param ctx_cert certificate you want to subscribe to
     * @param callback the callback to call when a status change has appeared
     *
     * @see unsubscribe()
     */
    static cert_status_ptr<CertStatusManager> subscribe(ossl_ptr<X509>&& ctx_cert, StatusCallback&& callback);

    /**
     * @brief Unsubscribe from listening to certificate status
     *
     * This function idempotent unsubscribe from the certificate status updates
     */
    void unsubscribe();

    inline bool available(double timeout = 5.0) noexcept { return isValid() || waitedTooLong(timeout); }

    inline bool waitedTooLong(double timeout = 5.0) const noexcept { return (manager_start_time_ + (time_t)timeout) < std::time(nullptr); }

    inline bool isValid() noexcept { return status_ && status_->isValid(); }

   private:
    CertStatusManager(ossl_ptr<X509>&& cert, std::shared_ptr<client::Context>& client, std::shared_ptr<client::Subscription>& sub)
        : cert_(std::move(cert)), client_(client), sub_(sub) {};
    CertStatusManager(ossl_ptr<X509>&& cert, std::shared_ptr<client::Context>& client) : cert_(std::move(cert)), client_(client) {};
    inline void subscribe(std::shared_ptr<client::Subscription>& sub) { sub_ = sub; }
    inline bool isGood() noexcept { return status_ && status_->isGood(); }

    const ossl_ptr<X509> cert_;
    std::shared_ptr<client::Context> client_;
    std::shared_ptr<client::Subscription> sub_;
    std::shared_ptr<CertificateStatus> status_;
    std::shared_ptr<PVACertificateStatus> pva_status_;
    time_t manager_start_time_{time(nullptr)};
    static ossl_ptr<OCSP_RESPONSE> getOCSPResponse(const shared_array<const uint8_t>& ocsp_bytes);

    static bool verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP>& basic_response);

    /**
     * @brief To parse OCSP responses
     *
     * Parsing OCSP responses is carried out by providing the OCSP response buffer.
     * This function will verify the response comes from a trusted source,
     * is well formed, and then will return the `ParsedOCSPStatus` it indicates.
     *
     * @param ocsp_bytes the ocsp response
     * @return the Parsed OCSP response status
     */
   public:
    static ParsedOCSPStatus parse(shared_array<const uint8_t> ocsp_bytes);
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
