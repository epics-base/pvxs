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
#include "statuslistener.h"

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

struct SSLError : public std::runtime_error {
    explicit SSLError(const std::string& msg);
    virtual ~SSLError();
};

struct ShowX509 {
    const X509* cert;
};
std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);

struct SSLContext {
    SSL_CTX* ctx = nullptr;

    PVXS_API
    static SSLContext for_client(const impl::ConfigCommon& conf);
    PVXS_API
    static SSLContext for_server(const impl::ConfigCommon& conf);

    SSLContext() = default;
    inline SSLContext(const SSLContext& o) : ctx(o.ctx) {
        if (ctx) {
            auto ret(SSL_CTX_up_ref(ctx));
            assert(ret == 1);  // can up_ref actually fail?
        }
    }
    inline SSLContext(SSLContext& o) noexcept : ctx(o.ctx) { o.ctx = nullptr; }
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
        return *this;
    }
    inline SSLContext& operator=(SSLContext&& o) {
        SSL_CTX_free(ctx);
        ctx = o.ctx;
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
    std::atomic<bool> fw_stop_flag_{false};
    std::atomic<bool> sl_stop_flag_{false};
    static PVXS_API int NID_PvaCertStatusURI;
    std::shared_ptr<certs::P12FileWatcher<client::Config>> client_file_watcher_;
    std::shared_ptr<certs::StatusListener<client::Config>> client_status_listener_;
    std::shared_ptr<certs::P12FileWatcher<server::Config>> server_file_watcher_;
    std::shared_ptr<certs::StatusListener<server::Config>> server_status_listener_;

    static bool fill_credentials(PeerCredentials& cred, const SSL* ctx);
    void unWatchCertificate();
};

}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_OPENSSL_H