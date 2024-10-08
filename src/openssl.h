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

#include <epicsAssert.h>

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
