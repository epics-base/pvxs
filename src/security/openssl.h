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

#include "ownedptr.h"

namespace pvxs {
struct PeerCredentials;
namespace ossl {

struct SSLError : public std::runtime_error {
    explicit
    SSLError(const std::string& msg);
    virtual ~SSLError();
};

struct ShowX509 { const X509* cert; };
std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);

struct SSLContext {
    SSL_CTX *ctx = nullptr;

    PVXS_API
    static
    SSLContext for_client(const impl::ConfigCommon& conf);
    PVXS_API
    static
    SSLContext for_server(const impl::ConfigCommon &conf);

    SSLContext() =default;
    inline
    SSLContext(const SSLContext& o)
        :ctx(o.ctx)
    {
        if(ctx) {
            auto ret(SSL_CTX_up_ref(ctx));
            assert(ret==1); // can up_ref actually fail?
        }
    }
    inline
    SSLContext(SSLContext& o) noexcept
        :ctx(o.ctx)
    {
        o.ctx = nullptr;
    }
    inline
    ~SSLContext() {
        SSL_CTX_free(ctx); // If ctx is NULL nothing is done.
    }
    inline
    SSLContext& operator=(const SSLContext& o)
    {
        if(o.ctx) {
            auto ret(SSL_CTX_up_ref(o.ctx));
            assert(ret==1); // can up_ref actually fail?
        }
        SSL_CTX_free(ctx);
        ctx = o.ctx;
        return *this;
    }
    inline
    SSLContext& operator=(SSLContext&& o)
    {
        SSL_CTX_free(ctx);
        ctx = o.ctx;
        o.ctx = nullptr;
        return *this;
    }

    explicit operator bool() const { return ctx; }

    bool have_certificate() const;
    const X509* certificate0() const;

    static
    bool fill_credentials(PeerCredentials& cred, const SSL *ctx);
};

} // namespace ossl
} // namespace pvxs

#endif  // PVXS_OPENSSL_H
