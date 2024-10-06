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

#define DO_CERT_STATUS_VALIDITY_EVENT_HANDLER(TYPE, STATUS_CALL)                            \
    void TYPE::doCertStatusValidityEventhandler(evutil_socket_t fd, short evt, void* raw) { \
        auto pvt = static_cast<TYPE*>(raw);                                                 \
        if (pvt->current_status && pvt->current_status->isValid()) return;                  \
        if (!pvt->cert_status_manager)                                                      \
            pvt->disableTls();                                                              \
        else {                                                                              \
            try {                                                                           \
                try {                                                                       \
                    pvt->current_status = pvt->cert_status_manager->STATUS_CALL();          \
                    if (pvt->current_status && pvt->current_status->isGood())               \
                        pvt->startStatusValidityTimer();                                    \
                    else                                                                    \
                        pvt->disableTls();                                                  \
                } catch (certs::CertStatusNoExtensionException & e) {                       \
                }                                                                           \
            } catch (...) {                                                                 \
                pvt->disableTls();                                                          \
            }                                                                               \
        }                                                                                   \
    }

#define CUSTOM_FILE_EVENT_CALL                \
    if (pvt->custom_cert_event_callback) {    \
        pvt->custom_cert_event_callback(evt); \
    }

#define _FILE_EVENT_CALL

#define DO_CERT_EVENT_HANDLER(TYPE, LOG, ...)                                                                                              \
    void TYPE::doCertEventHandler(evutil_socket_t fd, short evt, void* raw) {                                                              \
        try {                                                                                                                              \
            auto pvt = static_cast<TYPE*>(raw);                                                                                            \
            __VA_ARGS__##_FILE_EVENT_CALL pvt->fileEventCallback(evt);                                                                     \
            if (pvt->first_cert_event) pvt->first_cert_event = false;                                                                      \
            timeval interval(statusIntervalShort);                                                                                         \
            if (event_add(pvt->cert_event_timer.get(), &interval)) log_err_printf(LOG, "Error re-enabling cert file event timer\n%s", ""); \
        } catch (std::exception & e) {                                                                                                     \
            log_exc_printf(LOG, "Unhandled error in cert file event timer callback: %s\n", e.what());                                      \
        }                                                                                                                                  \
    }

#define FILE_EVENT_CALLBACK(TYPE)                              \
    void TYPE::fileEventCallback(short evt) {                  \
        if (!first_cert_event) file_watcher.checkFileStatus(); \
    }

#define GET_CERT(TYPE)                                                      \
    X509* TYPE::getCert(ossl::SSLContext* context_ptr) {                    \
        auto context = context_ptr == nullptr ? &tls_context : context_ptr; \
        if (!context->ctx) return nullptr;                                  \
        return SSL_CTX_get0_certificate(context->ctx);                      \
    }

#define START_STATUS_VALIDITY_TIMER(TYPE, LOOP)                                                                                                           \
    void TYPE::startStatusValidityTimer() {                                                                                                               \
        (LOOP).dispatch([this]() {                                                                                                                        \
            auto now = time(nullptr);                                                                                                                     \
            timeval validity_end = {current_status->status_valid_until_date.t - now, 0};                                                                  \
            if (event_add(cert_validity_timer.get(), &validity_end)) log_err_printf(watcher, "Error starting certificate status validity timer\n%s", ""); \
        });                                                                                                                                               \
    }

#define SUBSCRIBE_TO_CERT_STATUS(TYPE, STATUS_TYPE, LOOP)                                                                                   \
    void TYPE::subscribeToCertStatus() {                                                                                                    \
        if (auto cert_ptr = getCert()) {                                                                                                    \
            try {                                                                                                                           \
                if (cert_status_manager) return;                                                                                            \
                auto ctx_cert = ossl_ptr<X509>(X509_dup(cert_ptr));                                                                         \
                cert_status_manager = certs::CertStatusManager::subscribe(std::move(ctx_cert), [this](certs::PVACertificateStatus status) { \
                    Guard G(tls_context.lock);                                                                                              \
                    auto was_good = current_status && current_status->isGood();                                                             \
                    current_status = std::make_shared<certs::STATUS_TYPE>(status);                                                          \
                    if (current_status && current_status->isGood()) {                                                                       \
                        if (!was_good) (LOOP).dispatch([this]() mutable { enableTls(); });                                                  \
                    } else if (was_good) {                                                                                                  \
                        (LOOP).dispatch([this]() mutable { disableTls(); });                                                                \
                    }                                                                                                                       \
                });                                                                                                                         \
            } catch (certs::CertStatusSubscriptionException & e) {                                                                          \
                log_warn_printf(watcher, "TLS Disabled: %s\n", e.what());                                                                   \
            } catch (certs::CertStatusNoExtensionException & e) {                                                                           \
                log_debug_printf(watcher, "Status monitoring not configured correctly: %s\n", e.what());                                    \
            }                                                                                                                               \
        }                                                                                                                                   \
    }

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
     * @brief Get status for a given certificate.  Does not contain OCSP signed
     * status data so use for client status.
     *
     * @param cert the certificate for which you want to get status
     * @return std::shared_ptr<CertificateStatus>
     */
    static std::shared_ptr<CertificateStatus> getStatus(const ossl_ptr<X509>& cert);

    /**
     * @brief Get status for a given certificate.  This status contains the OCSP signed
     * status data so can be used for stapling.  Use this for server status.
     *
     * @param cert the certificate for which you want to get status
     * @return ::shared_ptr<PVACertificateStatus>
     */
    static std::shared_ptr<PVACertificateStatus> getPVAStatus(const ossl_ptr<X509>& cert);

    /**
     * @brief Wait for status to become available or return the current status if it is still valid
     * @param loop the event loop base to use to wait
     * @return the status
     */
    std::shared_ptr<CertificateStatus> waitForStatus(const evbase& loop);

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
    std::shared_ptr<CertificateStatus> getStatus();

    /**
     * @brief Get status for a currently subscribed certificate
     * @return CertificateStatus
     */
    std::shared_ptr<PVACertificateStatus> getPVAStatus();

    inline bool available() noexcept { return isValid() || (manager_start_time_ + 3) < std::time(nullptr); }

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
    static ParsedOCSPStatus parse(const shared_array<const uint8_t> ocsp_bytes);

   private:
    std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);
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
