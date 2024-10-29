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

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/server.h>

#include "ownedptr.h"
#include "p12filewatcher.h"

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

/**
 * @brief Contains peer status and peer status monitor
 *
 */
struct SSLPeerStatus {
    std::shared_ptr<const certs::CertificateStatus> status;
    certs::cert_status_ptr<certs::CertStatusManager> cert_status_manager;
};

struct CertStatusExData {
    epicsMutex lock;  // To lock changes to peer statuses
    ossl_ptr<X509> cert;
    const bool status_check_enabled;
    CertStatusExData(bool status_check_enabled) : status_check_enabled(status_check_enabled) {}

    std::map<serial_number_t, SSLPeerStatus> peer_statuses;

    static CertStatusExData* fromSSL_X509_STORE_CTX(X509_STORE_CTX* x509_ctx);
    static CertStatusExData* fromSSL_CTX(SSL_CTX* ssl);
    static CertStatusExData* fromSSL(SSL* ssl);

    /**
     * @brief Returns the serial number for the given certificate
     * @param cert_ptr - Certificate
     * @return The serial number
     */
    static inline serial_number_t getSerialNumber(X509 *cert_ptr) {
        ASN1_INTEGER *serial = X509_get_serialNumber(cert_ptr);
        ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr));
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
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(X509 *cert_ptr, const certs::CertificateStatus &status) {
        return setCachedPeerStatus(getSerialNumber(cert_ptr), status);
    }

    /**
     * @brief Sets the peer status for the given serial number
     * @param serial_number - Serial number
     * @param status - Certificate status
     * @return The peer status that was set
     */
    std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(serial_number_t serial_number, const certs::CertificateStatus &status);

    /**
     * @brief Sets the peer status for the given certificate
     * @param cert_ptr - Certificate
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(X509 *cert_ptr, std::shared_ptr<const certs::CertificateStatus> status) {
        return setCachedPeerStatus(getSerialNumber(cert_ptr), status);
    }

    /**
     * @brief Sets the peer status for the given serial number
     * @param serial_number - Serial number
     * @param status - Certificate status
     * @return The peer status that was set
     */
    inline std::shared_ptr<const certs::CertificateStatus> setCachedPeerStatus(serial_number_t serial_number, const std::shared_ptr<const certs::CertificateStatus> status) {
        Guard G(lock);
        peer_statuses[serial_number].status = status;
        return peer_statuses[serial_number].status;
    }

    /**
     * @brief Returns the currently cached peer status if any.  Null if none cached
     * @param cert_ptr - Certificate
     * @return The the cached peer status
     */
    inline std::shared_ptr<const certs::CertificateStatus> getCachedPeerStatus(X509 *cert_ptr) const {
        return getCachedPeerStatus(getSerialNumber(cert_ptr));
    }

    /**
     * @brief Returns the currently cached peer status if any.  Null if none cached
     * @param serial_number - Serial number
     * @return The cached peer status
     */
    inline std::shared_ptr<const certs::CertificateStatus> getCachedPeerStatus(const serial_number_t serial_number) const {
        auto it = peer_statuses.find(serial_number);
        if (it != peer_statuses.end()) {
            return it->second.status;
        }
        return nullptr;
    }

    /**
     * @brief Subscribes to peer status if required and not already monitoring
     * @param cert_ptr - peer certificate status to subscribe to
     * @param fn - Function to call when the peer status changes from good to bad or vice versa
     */
    void subscribeToCertStatus(X509 *cert_ptr, std::function<void(bool)> fn);
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
    epicsMutex lock;  // To lock changes to context state that happen as a result of changes to certificate status
    static PVXS_API int NID_PvaCertStatusURI;
    SSL_CTX* ctx = nullptr;
    bool has_cert{false};       // set when a certificate has been established
    bool cert_is_valid{false};  // To signal that cert is valid when we have received the status for the certificate
    bool status_check_disabled{false};
    bool stapling_disabled{false};

    PVXS_API
    static SSLContext for_client(const impl::ConfigCommon& conf);
    PVXS_API
    static SSLContext for_server(const impl::ConfigCommon& conf);

    CertStatusExData* ex_data() const;

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
