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

// EPICS OID for "validTillRevoked" extension:
// TODO Register this unassigned OID for EPICS
// "1.3.6.1.4.1" OID prefix for custom OIDs
// "37427" DTMF for "EPICS"
#define NID_PvaCertStatusURIID "1.3.6.1.4.1.37427.1"
#define SN_PvaCertStatusURI "ASN.1 - PvaCertStatusURI"
#define LN_PvaCertStatusURI "EPICS PVA Certificate Status URI"

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
constexpr uint16_t kForIntermediateCa = 0x04;
constexpr uint16_t kForCMS = 0x08;
constexpr uint16_t kForCa = 0x10;

constexpr uint16_t kForClientAndServer = kForClient | kForServer;
constexpr uint16_t kAnyServer = kForCMS | kForServer;

#define IS_USED_FOR_(USED, USAGE) (((USED) & (USAGE)) == USAGE)
#define IS_FOR_A_SERVER_(USED) (((USED) & (ssl::kAnyServer)) != 0x00)
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
struct SSLPeerStatusMonitor {
    // The certificate status
    std::shared_ptr<const certs::CertificateStatus> status;
    // The cert status manager
    certs::cert_status_ptr<certs::CertStatusManager> cert_status_manager;
    // The validity timer
    evevent validity_timer;
    // The function to call when the peer status changes
    std::function<void(bool)> fn;

    /**
     * @brief Constructor
     * @param status - The certificate status
     * @param validity_timer - The validity timer
     * @param fn - The function to call when the status changes
     */
    SSLPeerStatusMonitor(const std::shared_ptr<const certs::CertificateStatus>& status, evevent&& validity_timer, const std::function<void(bool)>& fn)
        : status(status), validity_timer(std::move(validity_timer)), fn(fn) {}
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
    // To lock changes to peer statuses
    epicsMutex lock;
    // The event loop to create timers for the status validity countdown
    const impl::evbase& loop;
    // The entity certificate
    ossl_ptr<X509> cert{};
    // The Trusted Root CA
    X509_STORE* trusted_store_ptr;
    // Whether status checking is enabled for this context.  If not then a permanent status is set and monitoring is not configured
    const bool status_check_enabled;
    // The map of Peer Status Monitors, keyed by the serial number of each peer's certificate
    std::map<serial_number_t, std::shared_ptr<SSLPeerStatusMonitor>> peer_status_monitors{};
    // map to keep status validity expiration handler parameters from going stale
    std::map<serial_number_t, StatusValidityExpirationHandlerParam> sveh_params{};

    /**
     * @brief Constructor
     * @param loop - The event loop
     * @param status_check_enabled - Whether status checking is enabled for this context.  If not then a permanent status is set and monitoring is not
     * configured
     */
    CertStatusExData(const impl::evbase& loop, bool status_check_enabled)
        : loop(loop), status_check_enabled(status_check_enabled) {}

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

    /**
     * @brief Returns the serial number for the given certificate
     * @param cert_ptr - Certificate
     * @return The serial number
     */
    static inline serial_number_t getSerialNumber(X509* cert_ptr) {
        ASN1_INTEGER* serial = X509_get_serialNumber(cert_ptr);
        ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr), false);
        if (!bn) {
            return 0;
        }

        if (BN_num_bytes(bn.get()) > sizeof(uint64_t)) {
            return 0;
        }

        return (serial_number_t)BN_get_word(bn.get());
    }

    /**
     * @brief Sets the peer status for the certificate for the given certificate
     * @param cert_ptr - Certificate
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(X509* cert_ptr, const certs::CertificateStatus& status) {
        return setCachedPeerStatus(getSerialNumber(cert_ptr), status);
    }

    /**
     * @brief Sets the peer status for the given serial number
     * @param serial_number - Serial number
     * @param status - Certificate status
     * @return The peer status that was set
     */
    std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(serial_number_t serial_number, const certs::CertificateStatus& status,
                                                                        std::function<void(bool)> fn = nullptr);

    /**
     * @brief Sets the peer status for the given certificate
     * @param cert_ptr - Certificate
     * @param status - Certificate status
     * @param fn - the function to call
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(X509* cert_ptr, std::shared_ptr<const certs::CertificateStatus> status,
                                                                               std::function<void(bool)> fn = nullptr) {
        return setCachedPeerStatus(getSerialNumber(cert_ptr), status, fn);
    }

    /**
     * @brief Sets the peer status for the given serial number
     * @param serial_number - Serial number
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(serial_number_t serial_number,
                                                                               const std::shared_ptr<const certs::CertificateStatus> status,
                                                                               std::function<void(bool)> fn = nullptr) {
        Guard G(lock);
        auto peer_status = getOrCreatePeerStatus(serial_number, fn);
        if (!peer_status) return nullptr;
        peer_status->status = status;
        return peer_status->status;
    }

    /**
     * @brief Creates a peer status if it does not already exist or returns the existing peer status
     *
     * This will initialise the peer status as Unknown and set up a time capable of being used as a status validity timer.  It also
     * sets up the function to call when the peer status changes. If the peer status already exists then it is returned.
     *
     * @param serial_number - Serial number
     * @param fn - Function to call when the peer status changes
     * @return The peer status that was created or found
     */
    std::shared_ptr<SSLPeerStatusMonitor> getOrCreatePeerStatus(serial_number_t serial_number, std::function<void(bool)> fn);

    /**
     * @brief Returns the currently cached peer status if any.  Null if none cached
     * @param cert_ptr - Certificate
     * @return The the cached peer status
     */
    inline std::shared_ptr<const certs::CertificateStatus> getCachedPeerStatus(X509* cert_ptr) const { return getCachedPeerStatus(getSerialNumber(cert_ptr)); }

    /**
     * @brief Returns the currently cached peer status if any.  Null if none cached
     * @param serial_number - Serial number
     * @return The cached peer status
     */
    inline std::shared_ptr<const certs::CertificateStatus> getCachedPeerStatus(const serial_number_t serial_number) const {
        auto it = peer_status_monitors.find(serial_number);
        if (it != peer_status_monitors.end()) {
            return it->second->status;
        }
        return nullptr;
    }

    /**
     * @brief Subscribes to peer status if required and not already monitoring
     * @param cert_ptr - peer certificate status to subscribe to
     * @param fn - Function to call when the peer status changes from good to bad or vice versa
     */
    void subscribeToPeerCertStatus(X509* cert_ptr, std::function<void(bool)> fn) noexcept;

    void setStatusValidityCountdown(std::weak_ptr<SSLPeerStatusMonitor> peer_status);
    static void statusValidityExpirationHandler(evutil_socket_t fd, short evt, void* raw);
    void statusValidityExpirationHandler(serial_number_t serial_number);
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

std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);

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

    static PVXS_API int NID_PvaCertStatusURI;

    ossl_shared_ptr<SSL_CTX> ctx;

    /**
     * @brief The state of the TLS context
     *
     * This is used to track the state of the context.
     *
     * Init - The context has not been initialised (default)
     * DegradedMode - The context is in degraded mode.  Only TCP connections are allowed.
     * TcpReady - The context is ready to accept TCP connections. Only TCP connections are accepted, but TLS connections are deferred until the state is
     * TlsReady. TlsReady - The context is ready to accept TLS connections.  All connections are accepted.
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

    // The entity certificate status validity timer (peer statuses are stored in the CertStatusExData tied to the SSL_CTX (ctx) created for this context)
    impl::evevent status_validity_timer{__FILE__, __LINE__, event_new(loop.base, -1, EV_TIMEOUT, statusValidityExpirationHandler, this)};

    /**
     * @brief Monitors the entity certificate status and sets the state of the TLS context when the status changes
     * @param cert the entity certificate
     * @param trusted_root_ca the trusted root to verify OCSP status with
     */
    void monitorStatusAndSetState(const ossl_ptr<X509>&cert, X509_STORE *trusted_store_ptr);
    void setDegradedMode(bool clear = false);
    void setTlsOrTcpMode();

    /**
     * @brief Creates a client TLS context
     * @param conf - The client configuration
     * @param loop - The event loop
     * @return The client TLS context
     */
    static std::shared_ptr<SSLContext> for_client(const impl::ConfigCommon& conf, const impl::evbase loop);

    /**
     * @brief Creates a server TLS context
     * @param conf - The server configuration
     * @param loop - The event loop
     * @return The server TLS context
     */
    static std::shared_ptr<SSLContext> for_server(const impl::ConfigCommon& conf, impl::evbase loop);

    /**
     * @brief Get the CertStatusExData from the PVXS SSL context
     *
     * This function retrieves the CertStatusExData from the SSL context associated with the PVXS SSL context.
     * This is the custom data that is added to the SSL context during tls context creation.
     *
     * @return the CertStatusExData
     */
    CertStatusExData* getCertStatusExData() const;

    explicit SSLContext(impl::evbase loop);
    SSLContext(const SSLContext& o);
    SSLContext(SSLContext& o) noexcept;

    static void statusValidityExpirationHandler(evutil_socket_t fd, short evt, void* raw);
    void setStatusValidityCountdown();

    /**
     * @brief Initializes the SSL library and sets up the custom certificate status URI OID
     * Uses the singleton pattern to ensure that the SSL library is initialized only once,
     * keyed off NID_PvaCertStatusURI being undefined.
     *
     * This is idempotent.  It can be called multiple times, but will not re-initialize the SSL library.
     *
     * It will do all the one time SSL library initialization that is required, inluding
     * SSL_library_init(), OpenSSL_add_all_algorithms(), ERR_load_crypto_strings(),
     * OpenSSL_add_all_ciphers(), and OpenSSL_add_all_digests().
     *
     * It will also create and register the custom certificate status URI OID.
     */
    static inline void sslInit() {
        // Initialize SSL
        if (NID_PvaCertStatusURI == NID_undef) {
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
            OpenSSL_add_all_ciphers();
            OpenSSL_add_all_digests();
            NID_PvaCertStatusURI = OBJ_create(NID_PvaCertStatusURIID, SN_PvaCertStatusURI, LN_PvaCertStatusURI);
            if (NID_PvaCertStatusURI == NID_undef) {
                throw std::runtime_error("Failed to create NID for " SN_PvaCertStatusURI ": " LN_PvaCertStatusURI);
            }
        }
    }

    explicit operator bool() const { return ctx.get(); }

    const X509* getEntityCertificate() const;

    static bool getPeerCredentials(PeerCredentials& cred, const SSL* ctx);
    static bool subscribeToPeerCertStatus(const SSL* ctx, std::function<void(bool)> fn);
    inline const certs::PVACertificateStatus& get_status() { return cert_status; }

   private:
    // The entity certificate status monitor
    certs::cert_status_ptr<certs::CertStatusManager> cert_monitor;
    // The entity certificate status - note that this is a PVA certificate status because we will need the OCSP stapling data if this is a server
    certs::PVACertificateStatus cert_status{};
};

PVXS_API void configureServerOCSPCallback(void* server, SSL* ssl);

struct OCSPStapleData {
    size_t size;
    uint8_t ocsp_response[];
};

}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_OPENSSL_H
