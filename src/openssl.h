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
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <epicsAssert.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/server.h>

#include "ownedptr.h"
#include "p12filewatcher.h"

#ifdef _WIN32
typedef SOCKET fd_t;
#else
typedef int fd_t;
#endif

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

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
struct CertificateStatus;
class CertStatusManager;
template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = ossl_shared_ptr<T, cert_status_delete<T>>;
}

namespace ssl {
constexpr uint16_t kForClient = 0x01;
constexpr uint16_t kForServer = 0x02;
constexpr uint16_t kForIntermediateCa = 0x04;
constexpr uint16_t kForCMS = 0x08;
constexpr uint16_t kForCa = 0x10;

constexpr uint16_t kForClientAndServer = kForClient | kForServer;
constexpr uint16_t kAnyServer = kForCMS | kForServer;

#define IS_USED_FOR_(USED, USAGE) ((USED & (USAGE)) == USAGE)
#define IS_FOR_A_SERVER_(USED) ((USED & (ssl::kAnyServer)) != 0x00)
}  // namespace ssl

struct PeerCredentials;
namespace ossl {

PVXS_API int ossl_verify(int preverify_ok, X509_STORE_CTX* x509_ctx);

struct SSLError : public std::runtime_error {
    explicit SSLError(const std::string& msg);
    virtual ~SSLError();
};

struct SSL_CTX_sidecar {
    ossl_ptr<X509> cert;
};

struct ShowX509 {
    const X509* cert;
};
std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);

/**
 * @brief Contains peer status and peer status monitor
 *
 * Created whenever a connection to an SSLContext is made.  There is a map in the
 * `SSLContext` from `fd` (socket file descriptor) to the related `SSLPeerStatus`
 * Use `int fd = SSL_get_fd(ssl)` to retrieve the file descriptor from the `SSL*`.
 * The fd is available during TLS handshake and in any callbacks that are set up.
 *
 * Use: A connection will be prevented from being finalised unless a valid (`isValid()`)
 * and good (`isGood()`) status exists for that `fd` identified connection.
 *
 * FOR CLIENTS
 * Client's peers are servers.  They can only have one.
 *
 * If `status_check_disabled` then an entry must be added to
 * made to `peer_status` containing an `certs::UnCertifiedCertificateStatus` and
 * no cert_status_manager (nullptr)
 *
 * If stapling is enabled in the client `SSLContext` then this is filled by the stapling callback.
 *
 * FOR SERVERS
 * Server's peers are clients.  There can be many peers to a single context
 *
 */
struct SSLPeerStatus {
    std::shared_ptr<const certs::CertificateStatus> status;
    certs::cert_status_ptr<certs::CertStatusManager> cert_status_manager;
};

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
    epicsMutex lock;  // To lock changes to context state that happen as a result of changes to certificate status
    static PVXS_API int NID_PvaCertStatusURI;
    SSL_CTX* ctx = nullptr;
    bool has_cert{false};       // set when a certificate has been established
    bool cert_is_valid{false};  // To signal that cert is valid when we have received the status for the certificate
    bool status_check_disabled{false};
    bool stapling_disabled{false};

    // A context can have multiple peers
    std::map<fd_t, SSLPeerStatus> peer_status;

    PVXS_API
    static SSLContext for_client(const impl::ConfigCommon& conf);
    PVXS_API
    static SSLContext for_server(const impl::ConfigCommon& conf);

    SSLContext() = default;
    inline SSLContext(const SSLContext& o)
        : ctx(o.ctx),
          has_cert(o.has_cert),
          cert_is_valid(o.cert_is_valid),
          status_check_disabled(o.status_check_disabled),
          stapling_disabled(o.stapling_disabled) {
        if (ctx) {
            auto ret(SSL_CTX_up_ref(ctx));
            assert(ret == 1);  // can up_ref actually fail?
        }
    }
    inline SSLContext(SSLContext& o) noexcept
        : ctx(o.ctx),
          has_cert(o.has_cert),
          cert_is_valid(o.cert_is_valid),
          status_check_disabled(o.status_check_disabled),
          stapling_disabled(o.stapling_disabled) {
        o.ctx = nullptr;
    }
    inline ~SSLContext() {
        SSL_CTX_free(ctx);  // If ctx is NULL nothing is done.
    }
    inline SSLContext& operator=(const SSLContext& o) {
        if (o.ctx) {
            auto ret(SSL_CTX_up_ref(o.ctx));
            assert(ret == 1);  // can up_ref actually fail?
        }
        SSL_CTX_free(ctx);
        ctx = o.ctx;
        has_cert = o.has_cert;
        cert_is_valid = o.cert_is_valid;
        status_check_disabled = o.status_check_disabled;
        stapling_disabled = o.stapling_disabled;
        return *this;
    }
    inline SSLContext& operator=(SSLContext&& o) {
        SSL_CTX_free(ctx);
        ctx = o.ctx;
        has_cert = o.has_cert;
        cert_is_valid = o.cert_is_valid;
        status_check_disabled = o.status_check_disabled;
        stapling_disabled = o.stapling_disabled;
        o.ctx = nullptr;
        return *this;
    }

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

    /**
     * @brief Returns the socket file descriptor for the given SSL object
     * @param ssl - SSL object
     * @return The socket file descriptor
     */
    static inline fd_t getFd(const SSL *ssl) {
        return (fd_t)SSL_get_fd(ssl);
    }

    /**
     * @brief Sets the peer status for the certificate for the given SSL object
     * @param ssl - SSL object
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(const SSL *ssl, const certs::CertificateStatus &status) {
        return setCachedPeerStatus(getFd(ssl), status);
    }

    /**
     * @brief Sets the peer status for the certificate on the other end of a given socket file descriptor
     * @param fd - Socket file descriptor
     * @param status - Certificate status
     * @return The peer status that was set
     */
    std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(fd_t fd, const certs::CertificateStatus &status);

    /**
     * @brief Sets the peer status for the certificate for the given SSL object
     * @param ssl - SSL object
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(const SSL *ssl, std::shared_ptr<const certs::CertificateStatus> status) {
        return setCachedPeerStatus(getFd(ssl), status);
    }

    /**
     * @brief Sets the peer status for the certificate on the other end of a given socket file descriptor
     * @param fd - Socket file descriptor
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(fd_t fd, const std::shared_ptr<const certs::CertificateStatus> status) {
        Guard G(lock);
        peer_status[fd].status = status;
        return peer_status[fd].status;
    }

    /**
     * @brief Returns the currently cached peer status if any.  Null if none cached
     * @param ssl - SSL object
     * @return The the cached peer status
     */
    inline std::shared_ptr<const certs::CertificateStatus> getCachedPeerStatus(const SSL *ssl) const {
        return getCachedPeerStatus(getFd(ssl));
    }

    /**
     * @brief Returns the currently cached peer status if any.  Null if none cached
     * @param fd - Socket file descriptor
     * @return The cached peer status
     */
    inline std::shared_ptr<const certs::CertificateStatus> getCachedPeerStatus(const fd_t fd) const {
        auto it = peer_status.find(fd);
        if (it != peer_status.end()) {
            return it->second.status;
        }
        return nullptr;
    }

    /**
     * @brief Subscribes to peer status if required and not already monitoring
     * @param ssl - SSL pointer at the other end of which is the certificate to subscribe to
     * @param fn - Function to call when the peer status changes from good to bad or vice versa
     */
    void subscribeToPeerStatus(const SSL *ssl, std::function<void(SSLContext*, bool)> fn);

    explicit operator bool() const { return ctx; }

    bool have_certificate() const;
    const X509* certificate0() const;

    static bool fill_credentials(PeerCredentials& cred, const SSL* ctx);
};

PVXS_API void stapleOcspResponse(void* server, SSL* ssl);

struct OCSPStapleData {
    size_t size;
    uint8_t ocsp_response[];
};

}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_OPENSSL_H
