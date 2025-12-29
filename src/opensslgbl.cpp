/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "opensslgbl.h"

#include <algorithm>
#include <dlfcn.h>
#include <fstream>
#include <stdexcept>

#include <epicsExit.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <pvxs/log.h>

#include "certstatusmanager.h"
#include "evhelper.h"
#include "openssl.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
DEFINE_LOGGER(setup, "pvxs.ossl.init");
#endif

namespace pvxs {
namespace ossl {

int NID_SPvaCertStatusURI = NID_undef;
int NID_SPvaCertConfigURI = NID_undef;

OSSLGbl* ossl_gbl = nullptr;

void free_SSL_CTX_sidecar(void *, void *ptr, CRYPTO_EX_DATA *, int, long, void *) noexcept {
    delete static_cast<CertStatusExData*>(ptr);
}

void logOsslVersions()
{
    log_debug_printf(setup, "pvxs: OpenSSL build:  %s (0x%lx)\n", OPENSSL_VERSION_TEXT, (unsigned long)OPENSSL_VERSION_NUMBER);
    log_debug_printf(setup, "pvxs: OpenSSL runtime:%s (0x%lx)\n", OpenSSL_version(OPENSSL_VERSION), (unsigned long)OpenSSL_version_num());
}


void logSymbolOrigin(const char* name, const void* sym)
{
    Dl_info info;
    if(dladdr(sym, &info) && info.dli_fname) {
        log_debug_printf(setup, "pvxs: %s from %s\n", name, info.dli_fname);
    } else {
        log_debug_printf(setup, "pvxs: %s origin unknown\n", name);
    }
}

void logOsslSymbolOrigins()
{
    logSymbolOrigin("OpenSSL_version", (const void*)&OpenSSL_version);   // crypto
    logSymbolOrigin("ERR_get_error",   (const void*)&ERR_get_error);     // crypto
    logSymbolOrigin("EVP_MD_fetch",    (const void*)&EVP_MD_fetch);      // crypto (OpenSSL 3)
    logSymbolOrigin("SSL_CTX_new_ex",  (const void*)&SSL_CTX_new_ex);    // ssl
}

void verifySSLLibraries() {
    // Test creating an SSL context, and if it fails, then we know we are going to have problems later on
    const auto ssl_ctx = SSL_CTX_new_ex(ossl_gbl->libctx.get(), nullptr, TLS_method());
    if (!ssl_ctx) {
        if (ERR_peek_error()==0) {
            logOsslVersions();
            logOsslSymbolOrigins();
            log_err_printf(setup, "OpenSSL library mismatch detected; disabling TLS%s", "\n");
        } else {
            log_err_printf(setup, "SSL_CTX_new_ex failed: %s\n", SSLError("SSL_CTX_new_ex").what());
        }
        ossl_gbl->tls_disabled = true;
        return;
    }
    SSL_CTX_free(ssl_ctx);
}

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
void sslkeylogfile_exit(void *) noexcept {
    if (!ossl_gbl) return;
    auto gbl = ossl_gbl;
    try {
        epicsGuard<epicsMutex> G(gbl->keylock);
        if (gbl->keylog.is_open()) {
            gbl->keylog.flush();
            gbl->keylog.close();
        }
    } catch (std::exception &e) {
        static bool once = false;
        if (!once) {
            fprintf(stderr, "Error while writing to SSLKEYLOGFILE\n");
            once = true;
        }
    }
}
#endif

static void osslInitImpl() {
    log_debug_printf(setup, "One-time initialisation of OpenSSL subsystem starting ...%s\n", "");
    NID_SPvaCertStatusURI = OBJ_create(NID_SPvaCertStatusURIID, SN_SPvaCertStatusURI, LN_SPvaCertStatusURI);
    if(NID_SPvaCertStatusURI == NID_undef) {
        throw std::runtime_error("Failed to create NID for " SN_SPvaCertStatusURI);
    }
    NID_SPvaCertConfigURI = OBJ_create(NID_SPvaCertConfigURIID, SN_SPvaCertConfigURI, LN_SPvaCertConfigURI);
    if(NID_SPvaCertConfigURI == NID_undef) {
        throw std::runtime_error("Failed to create NID for " SN_SPvaCertConfigURI);
    }

    ossl_ptr<OSSL_LIB_CTX> ctx(__FILE__, __LINE__, OSSL_LIB_CTX_new());
    // read $OPENSSL_CONF or eg. /usr/lib/ssl/openssl.cnf
    (void)CONF_modules_load_file_ex(ctx.get(), nullptr, "pvxs", CONF_MFLAGS_IGNORE_MISSING_FILE | CONF_MFLAGS_IGNORE_RETURN_CODES);
    std::unique_ptr<OSSLGbl> gbl{new OSSLGbl};
    gbl->SSL_CTX_ex_idx = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, free_SSL_CTX_sidecar);
#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    if (auto env = getenv("SSLKEYLOGFILE")) {
        epicsGuard<epicsMutex> G(gbl->keylock);
        gbl->keylog.open(env);
        if (gbl->keylog.is_open()) {
            epicsAtExit(sslkeylogfile_exit, nullptr);
            log_warn_printf(setup, "TLS Debug Enabled: logging TLS secrets to %s\n", env);
        } else {
            log_err_printf(setup, "TLS Debug Disabled: Unable to open SSL key log file: %s\n", env);
        }
    }
#endif  // PVXS_ENABLE_SSLKEYLOGFILE
    ossl_gbl = gbl.release();
    ossl_gbl->libctx = std::move(ctx);

    // Disable SSL if libraries are incompatible (can happen with incorrect python bindings)
    verifySSLLibraries();

    log_debug_printf(setup, "One-time initialisation of OpenSSL subsystem complete%s\n", "");
}

void osslInit() {
    impl::threadOnce<&osslInitImpl>();;
}


}  // namespace ossl
}  // namespace pvxs
