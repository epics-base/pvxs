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
    using StatusCallback = std::function<void(const PVACertificateStatus &)>;

    CertStatusManager() = delete;

    ~CertStatusManager() = default;

    /**
     * Parse OCSP responses from the provided ocsp_bytes response
     * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
     *
     * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
     *
     * Then parse it and read out the status and the status times
     *
     * @param ocsp_bytes The input byte array containing the OCSP responses data.
     * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
     */
    static ParsedOCSPStatus parse(const shared_array<const uint8_t> &ocsp_bytes, X509_STORE *trusted_store_ptr);

    /**
     * Parse OCSP responses from the provided ocsp_bytes response
     * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
     *
     * First Verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
     *
     * Then parse it and read out the status and the status times
     *
     * @param ocsp_bytes The input byte buffer pointer containing the OCSP responses data.
     * @ocsp_bytes_len the length of the byte buffer
     * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
     */
    static ParsedOCSPStatus parse(const uint8_t *ocsp_bytes, size_t ocsp_bytes_len, X509_STORE *trusted_store_ptr);

    /**
     * Parse OCSP responses from the provided OCSP response object
     * and return the parsed out status of the certificate which is the subject of the OCSP response.
     *
     * First verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well formed.
     *
     * Then parse it and read out the status and the status times
     *
     * @param ocsp_response An OCSP response object.
     * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
     */
    static ParsedOCSPStatus parse(const ossl_ptr<OCSP_RESPONSE> &ocsp_response, X509_STORE *trusted_store_ptr);

    /**
     * @brief Get the status PV from a Cert.
     * This function gets the PVA extension that stores the status PV in the certificate
     * if the certificate must be used in conjunction with a status monitor to check for
     * revoked status.
     * @param cert the certificate to check for the status PV extension
     * @return a blank string if no extension exists, otherwise contains the status PV
     *         e.g. CERT:STATUS:0293823f:098294739483904875
     */
    static std::string getStatusPvFromCert(const ossl_ptr<X509> &cert);

    /**
     * @brief Get the config PV from a Cert.
     * This function gets the PVA extension that stores the config PV in the certificate
     * if the certificate can be used in conjunction with a config monitor to check for
     * expired status.
     * @param cert the certificate to check for the config PV extension
     * @return a blank string if no extension exists, otherwise contains the config PV
     *         e.g. CERT:CONFIG:0293823f:098294739483904875
     */
    static std::string getConfigPvFromCert(const ossl_ptr<X509> &cert);


    /**
     * @brief Get the status PV from a Cert.
     * This function gets the PVA extension that stores the status PV in the certificate
     * if the certificate must be used in conjunction with a status monitor to check for
     * revoked status.
     * @param cert the certificate to check for the status PV extension
     * @return a blank string if no extension exists, otherwise contains the status PV
     *         e.g. CERT:STATUS:0293823f:098294739483904875
     */
    static std::string getIssuerIdFromCert(const X509* cert_ptr);
    static std::string getSerialFromCert(const X509* cert_ptr);
    static std::string getCertIdFromCert(const X509 *cert);
    static std::string getStatusPvFromCert(const X509 *cert);
    static std::string getConfigPvFromCert(const X509 *cert);

    static time_t getExpirationDateFromCert(const ossl_ptr<X509> &cert);
    static time_t getRenewByFromCert(const ossl_ptr<X509> &cert);

    static time_t getExpirationDateFromCert(const X509 *cert);
    static time_t getRenewByFromCert(const X509 *cert);

    /**
     * @brief Used to create a helper that you can use to subscribe to certificate status with
     * Subsequently call subscribe() to subscribe
     *
     * @param trusted_store_ptr the trusted store that we'll use to verify the OCSP responses received
     * @param ctx_cert certificate you want to subscribe to
     * @param callback the callback to call when a status change has appeared
     *
     * @see unsubscribe()
     */
    static cert_status_ptr<CertStatusManager> subscribe(X509_STORE *trusted_store_ptr, const std::string &status_pv, StatusCallback &&callback);

    /**
     * @brief Unsubscribe from listening to certificate status
     *
     * This function idempotent unsubscribe from the certificate status updates
     */
    void unsubscribe();

    bool available(double timeout = 5.0) const noexcept { return isValid() || waitedTooLong(timeout); }
    bool waitedTooLong(double timeout = 5.0) const noexcept { return (manager_start_time_ + (time_t)timeout) < std::time(nullptr); }
    bool isValid() const noexcept { return status_ && status_->isValid(); }

   private:
    CertStatusManager(std::shared_ptr<client::Context> &&client, std::shared_ptr<client::Subscription> sub) : client_(std::move(client)), sub_(sub) {};
    explicit CertStatusManager(std::shared_ptr<client::Context> &&client) : client_(std::move(client)), sub_{} {};

    void subscribe(std::shared_ptr<client::Subscription> &sub) { sub_ = sub; }

    std::shared_ptr<StatusCallback> callback_ref{};  // Option placeholder for ref to callback if used
    std::shared_ptr<client::Context> client_;
    std::shared_ptr<client::Subscription> sub_;
    std::shared_ptr<CertificateStatus> status_;
    std::shared_ptr<PVACertificateStatus> pva_status_;
    time_t manager_start_time_{time(nullptr)};

    /**
     * @brief Get the custom status extension from the given certificate
     * @param certificate the certificate to retrieve the status extension from
     * @return the extension
     * @throws CertStatusNoExtensionException if no extension is present in the certificate
     */
    static X509_EXTENSION *getStatusExtension(const X509 *certificate);
    static X509_EXTENSION *getConfigExtension(const X509 *certificate);
    static X509_EXTENSION *getRenewByDateExtension(const X509 *certificate);
    static ossl_ptr<OCSP_RESPONSE> getOCSPResponse(const shared_array<const uint8_t> &ocsp_bytes);
    static ossl_ptr<OCSP_RESPONSE> getOCSPResponse(const uint8_t *ocsp_bytes, const size_t ocsp_bytes_len);
    static bool verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP> &basic_response, X509_STORE *trusted_store_ptr);
};

template <>
struct cert_status_delete<CertStatusManager> {
    void operator()(CertStatusManager *base_pointer) {
        if (base_pointer) {
            base_pointer->unsubscribe();  // Idempotent unsubscribe
            delete base_pointer;
        }
    }
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUSMANAGER_H_
