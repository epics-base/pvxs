/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_OPENSSL_H
#define PVXS_OPENSSL_H

#include <list>
#include <memory>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <epicsAssert.h>
#include <epicsMutex.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/server.h>

#include "certstatus.h"
#include "conn.h"
#include "evhelper.h"
#include "ownedptr.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;
typedef uint64_t serial_number_t;

namespace pvxs {

namespace client {
struct Config;
}
namespace server {
struct Config;
}
namespace certs {
struct PVACertificateStatus;
struct CertificateStatus;
class CertStatusManager;
struct CertData;
template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = ossl_shared_ptr<T, cert_status_delete<T>>;
}  // namespace certs

namespace ssl {
constexpr uint16_t kForClient = 0x01;
constexpr uint16_t kForServer = 0x02;
constexpr uint16_t kForIntermediateCertAuth = 0x04;
constexpr uint16_t kForCMS = 0x08;
constexpr uint16_t kForCertAuth = 0x10;

constexpr uint16_t kForClientAndServer = kForClient | kForServer;
constexpr uint16_t kAnyServer = kForCMS | kForServer;

#define IS_USED_FOR_(USED, USAGE) (((USED) & (USAGE)) == USAGE)
#define IS_FOR_A_SERVER_(USED) (((USED) & (pvxs::ssl::kAnyServer)) != 0x00)
}  // namespace ssl

struct PeerCredentials;
namespace ossl {

PVXS_API int ossl_verify(int preverify_ok, X509_STORE_CTX* x509_ctx);

struct PVXS_API SSLError : public std::runtime_error {
    explicit SSLError(const std::string& msg);
    virtual ~SSLError();
};

/**
 * @brief A peer status monitor: containing a monitor and function to call when the peer status changes, the current status, and a status validity timer
 *
 * This is used to store the peer status, the cert status manager, the validity timer and the function to call when the peer status changes.
 *
 * The validity timer is used to create a timer for the status validity countdown.
 *
 * The function to call when the peer status changes is used to notify the caller when the peer status changes from good to bad or vice versa.
 * This function should disconnect the TLS connection if status goes from good to bad and should disconnect
 * a TCP connection so that it can be reconnected as a TLS connection when status goes from bad to good.
 *
 * Peer statuses are established when a connection is made and peer status monitoring is enabled.
 *
 * Peer statuses are updated when the peer certificate is approved, becomes valid, is revoked, or expires.
 *
 * Peer statuses have a validity and when statuses are updated the validity timer is set and will go off when the status becomes invalid so that
 * we can fetch the status and update the peer status - resetting the timer.
 */
struct CertStatusExData;

struct SSLPeerStatusAndMonitor {
    // To lock changes to peer statuses
    epicsMutex lock;
    // The cert status manager
    certs::cert_status_ptr<certs::CertStatusManager> cert_status_manager;
    bool subscribed{false};

    // The function to call when the peer status changes
    const std::function<void(bool)> fn;

    // The serial number of the certificate being monitored.  We get the status PV from the cert, so we know that it is from the right certificate authority
    const serial_number_t serial_number;

    // Peer status and monitor map holder: Cert Status Ex data where Map where status and monitors are mapped to status pv
    CertStatusExData* ex_data_ptr;

    certs::CertificateStatus status;

    /**
     * @brief Constructor when monitoring is needed
     * @param serial_number the serial number of the certificate that we're monitoring
     * @param ex_data_ptr the ex_data structure that the list of peer status and monitors is stored, for cleanup
     * @param fn function to call when the status changes
     */
    SSLPeerStatusAndMonitor(const serial_number_t serial_number, CertStatusExData* ex_data_ptr, const std::function<void(bool)>& fn)
        : fn(fn), serial_number{serial_number}, ex_data_ptr{ex_data_ptr} {}

    /**
     * @brief Constructor when no monitoring is needed
     * @param serial_number the serial number of the certificate that we're monitoring
     * @param ex_data_ptr the ex_data structure that the list of peer status and monitors is stored, for cleanup
     * @param status permanent status to set
     */
    SSLPeerStatusAndMonitor(const serial_number_t serial_number, CertStatusExData* ex_data_ptr, const certs::CertificateStatus& status)
        : serial_number{serial_number}, ex_data_ptr{ex_data_ptr}, status{status} {}

    void updateStatus(const certs::CertificateStatus& status);

    // Clean up peer status and monitor
    // Also remove from peer cert status map
    ~SSLPeerStatusAndMonitor();

    bool isSubscribed() const { return subscribed; }
};

struct StatusValidityExpirationHandlerParam;

/**
 * @brief The custom cert status related data stored in the SSL_CTX
 *
 * This is used to store the entity certificate and the certificate statuses for all peers of this context.
 * It also contains the event loop and the mutex to lock changes to the peer statuses.
 * The event loop is used to create timers for the status validity countdown.
 *
 * The peer statuses are stored in a map with the serial number of the peer's certificate as the key.
 * The SSLPeerStatus struct contains the certificate status, the cert status manager,
 * the validity timer and the function to call when the status changes.
 *
 * The status validity expiration handler parameters are stored in a map with the serial number of the peer's certificate as the key.
 * The status validity expiration handler is fed a pointer to data it needs to update the peer status but this
 * data needs to be kept from going stale.  So we store the parameters in a map and use the serial number as the key.
 */
struct CertStatusExData {
    // To lock changes to ex data
    epicsMutex lock;
    // The event loop to create timers for the status validity countdown
    const evbase& loop;
    // The entity certificate
    ossl_ptr<X509> cert{};
    // The Trusted Root Certificate Authority
    X509_STORE* trusted_store_ptr;
    // Whether status checking is enabled for this context.
    // If not then a permanent status is set and monitoring is not configured
    const bool status_check_enabled;

    // The map of Peer Statuses and Monitors, keyed by the serial number of each peer's certificate
    // We use weak pointers here.  The real shared pointers are in the Connections (client/server)
    //
    // Note that if peer cert does not have the status monitoring extension then we just use the
    // serial number as ID for the cert status that will not change and
    // if it does then we still use the serial number but we error out with a clash if there is a clash
    // of serial numbers across different CAs when creating the second subscription
    std::map<serial_number_t, std::weak_ptr<SSLPeerStatusAndMonitor>> peer_statuses{};
    // map to keep status validity expiration handler parameters from going stale
    std::map<serial_number_t, StatusValidityExpirationHandlerParam> sveh_params{};

    /**
     * @brief Constructor
     * @param loop - The event loop
     * @param status_check_enabled - Whether status checking is enabled for this context.  If not then a permanent status is set and monitoring is not
     * configured
     */
    CertStatusExData(const evbase& loop, bool status_check_enabled) : loop(loop), status_check_enabled(status_check_enabled) {}

    /**
     * @brief Returns the CertStatusExData from the SSL_CTX
     * @param ssl - The SSL_CTX
     * @return The CertStatusExData
     */
    static CertStatusExData* fromSSL_CTX(SSL_CTX* ssl);

    /**
     * @brief Returns the CertStatusExData from the SSL
     * @param ssl - The SSL
     * @return The CertStatusExData
     */
    static CertStatusExData* fromSSL(SSL* ssl);

    void removePeerStatusAndMonitor(serial_number_t serial_number) {
        Guard G(lock);
        peer_statuses.erase(serial_number);
    }

    /**
     * @brief Returns the serial number for the given certificate
     * @param cert_ptr - Certificate
     * @return The serial number
     */
    static serial_number_t getSerialNumber(X509* cert_ptr) {
        const ASN1_INTEGER* serial = X509_get_serialNumber(cert_ptr);
        const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr), false);
        if (!bn) {
            return 0;
        }

        if (static_cast<size_t>(BN_num_bytes(bn.get())) > sizeof(uint64_t)) {
            return 0;
        }

        return BN_get_word(bn.get());
    }

    std::shared_ptr<SSLPeerStatusAndMonitor> createPeerStatus(serial_number_t serial_number, const std::function<void(bool)> &fn);

    /**
     * @brief Sets the peer status for the given certificate
     * @param peer_cert - Peer Certificate
     * @param new_status - New Certificate status
     * @param fn - the function to call
     * @return The peer status that was set
     */
    std::shared_ptr<SSLPeerStatusAndMonitor> setPeerStatus(const ossl_ptr<X509>& peer_cert, const certs::CertificateStatus& new_status,
                                                           const std::function<void(bool)>& fn = nullptr) {
        return setPeerStatus(peer_cert.get(), new_status, fn);
    }

    std::shared_ptr<SSLPeerStatusAndMonitor> setPeerStatus(const ossl_ptr<X509>& peer_cert, const std::function<void(bool)>& fn = nullptr) {
        return setPeerStatus(peer_cert.get(), {}, fn);
    }

    std::shared_ptr<SSLPeerStatusAndMonitor> setPeerStatus(X509* peer_cert_ptr, const std::function<void(bool)>& fn = nullptr) {
        return setPeerStatus(peer_cert_ptr, {}, fn);
    }

    std::shared_ptr<SSLPeerStatusAndMonitor> setPeerStatus(X509* peer_cert_ptr, const certs::CertificateStatus& new_status, const std::function<void(bool)> &fn = nullptr);

    /**
     * @brief Returns the currently cached peer status and monitor if any.  Null if none cached
     * @param serial_number - Serial number
     * @return The cached peer status
     */
    std::shared_ptr<SSLPeerStatusAndMonitor> getCachedPeerStatus(const serial_number_t serial_number) const {
        const auto it = peer_statuses.find(serial_number);
        if (it != peer_statuses.end()) {
            auto peer_status = it->second.lock();
            if (peer_status) return peer_status;
        }
        return {};
    }

    /**
     * @brief Subscribes to peer status if required and not already monitoring
     * @param cert_ptr - peer certificate status to subscribe to
     * @param fn - Function to call when the peer status changes from good to bad or vice versa
     * @return a shared pointer to the peer status and optional monitor
     */
    std::shared_ptr<SSLPeerStatusAndMonitor> subscribeToPeerCertStatus(X509* cert_ptr, std::function<void(bool)> fn) noexcept;

   private:
    /**
     * @brief Creates a peer status if it does not already exist or returns the existing peer status
     *
     * This will initialise the peer status as Unknown and set up a time capable of being used as a status validity timer.  It also
     * sets up the function to call when the peer status changes. If the peer status already exists then it is returned.
     *
     * @param status_pv - status pv
     * @param fn - Function to call when the peer status changes
     * @return The peer status that was created or found
     */
    std::shared_ptr<SSLPeerStatusAndMonitor> getOrCreatePeerStatus(serial_number_t serial_number, const std::string& status_pv = {}, const std::function<void(bool)> &fn = nullptr);
};

/**
 * @brief The parameters for the status validity expiration handler
 *
 * This is used to pass the CertStatusExData and the serial number to the status validity expiration handler.
 * The CertStatusExData contains the peer statuses and the status validity expiration handler is used to update the peer status
 * when the status validity expires and the validity timer goes off.
 */
struct StatusValidityExpirationHandlerParam {
    CertStatusExData& cert_status_ex_data;
    serial_number_t serial_number;
};

struct ShowX509 {
    const X509* cert;
};

PVXS_API std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);

/**
 * @brief SSL context for TLS communication
 *
 * This struct encapsulates the OpenSSL SSL_CTX and related state for managing
 * TLS connections. It includes flags for certificate validity, status checking,
 * and stapling. The context can be used for both client and server connections,
 * and maintains a map of peer statuses for multiple connections.
 *
 * Key components:
 * - SSL_CTX* ctx: The OpenSSL SSL context
 * - Flags for certificate and status checking states
 * - A map of socket file descriptors to SSLPeerStatus for managing multiple connections
 * - Static methods for creating client and server contexts
 *
 * This struct is central to PVXS's TLS implementation, handling context creation,
 * certificate management, and peer status tracking.
 */
struct SSLContext {
    // To lock changes to context state that happen as a result of changes to certificate status
    epicsMutex lock;
    // The event loop.  Used to create timers for the status validity countdown
    const impl::evbase loop;

    ossl_shared_ptr<SSL_CTX> ctx;

    /**
     * @brief The state of the TLS context
     *
     * This is used to track the state of the context.
     * For TLS both entity and peer cert must be valid so there is Nearly Ready status to show when
     * only one side is ready
     *
     * `Init`           - The context has not been initialised (default)
     * `DegradedMode`   - The context is in Degraded mode.  Only TCP communications are permitted.
     * `TcpReady`       - The context is ready to establish TCP communications. TCP connections can be completely
     *                    configured, but TLS connections are deferred until the state is TlsReady.
     * `TlsPartial`     - The context is partially ready to establish TLS communications (entity or peer is fully ready).
     * `TlsReady`       - The context is fully ready to establish TLS communications.
     */
    enum state_t {
        Init,
        DegradedMode,
        TcpReady,
        TlsReady,
    } state = Init;

    // Whether status checking is disabled.  Copied from the config
    bool status_check_disabled{false};
    // Whether stapling is disabled.  Copied from the config
    bool stapling_disabled{false};

    /**
     * @brief Monitors the entity certificate status and sets the state of the TLS context when the status changes
     * @param cert the entity certificate
     * @param trusted_store_ptr the trusted root to verify OCSP status with
     */
    void monitorStatusAndSetState(const ossl_ptr<X509>& cert, X509_STORE* trusted_store_ptr);
    void setDegradedMode(bool clear = false);
    void setTlsOrTcpMode();
    void setTlsOrTcpMode(bool is_good);

    /**
     * @brief Creates a client TLS context
     * @param conf - The client configuration
     * @param loop - The event loop
     * @return The client TLS context
     */
    static std::shared_ptr<SSLContext> for_client(const ConfigCommon& conf, const evbase &loop);

    /**
     * @brief Creates a server TLS context
     * @param conf - The server configuration
     * @param loop - The event loop
     * @return The server TLS context
     */
    static std::shared_ptr<SSLContext> for_server(const ConfigCommon& conf, const evbase &loop);

    /**
     * @brief Get the CertStatusExData from the PVXS SSL context
     *
     * This function retrieves the CertStatusExData from the SSL context associated with the PVXS SSL context.
     * This is the custom data that is added to the SSL context during tls context creation.
     *
     * @return the CertStatusExData
     */
    CertStatusExData* getCertStatusExData() const;

    explicit SSLContext(evbase loop);
    SSLContext(const SSLContext& o);
    SSLContext(SSLContext& o) noexcept;
    ~SSLContext();

    explicit operator bool() const { return ctx.get(); }

    const X509* getEntityCertificate() const;
    bool hasExpired() const;

    static bool getPeerCredentials(PeerCredentials& cred, const SSL* ctx);
    static std::shared_ptr<SSLPeerStatusAndMonitor>  subscribeToPeerCertStatus(const SSL* ssl, const std::function<void(bool)> &fn);
    const certs::PVACertificateStatus& get_cert_status() { return cert_status; }

   private:
    // The entity certificate status monitor
    certs::cert_status_ptr<certs::CertStatusManager> cert_monitor;
    // The entity certificate status - note that this is a PVA certificate status because we will need the OCSP stapling data if this is a server
    certs::PVACertificateStatus cert_status{};
    // Timer for entity certificate status validity expiration
    evevent status_validity_timer;

    static void statusValidityTimerCallback(evutil_socket_t fd, short evt, void* raw);
    void restartStatusValidityTimerFromCertStatus() const;
};

PVXS_API void configureServerOCSPCallback(void* server, SSL* ssl);

struct OCSPStapleData {
    size_t size;
    uint8_t ocsp_response[];
};

}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_OPENSSL_H
