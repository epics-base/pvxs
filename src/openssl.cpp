/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#include <fstream>
#include <stdexcept>
#include <tuple>

#include <epicsExit.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <pvxs/log.h>

#include "evhelper.h"
#include "ownedptr.h"
#include "utilpvt.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

DEFINE_LOGGER(_setup, "pvxs.ossl.setup");
DEFINE_LOGGER(_io, "pvxs.ossl.io");

namespace pvxs {
namespace ossl {

int ossl_verify(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    // note: no context pointer passed directly.  If needed see: man SSL_CTX_set_verify
    if (!preverify_ok) {
        //        X509_STORE_CTX_print_verify_cb(preverify_ok, x509_ctx);
        auto err = X509_STORE_CTX_get_error(x509_ctx);

        // TODO Remove Dev mode to ignore contexts with no chain &
        // TODO Remove Dev mode to accept self signed certs as trusted
        // If the error is that the certificate is self-signed, we accept it
        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY || err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
            err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            return 1;  // Accept self-signed certificates
        }

        auto cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        log_err_printf(_io, "Unable to verify peer cert: %s : %s\n", X509_verify_cert_error_string(err), std::string(SB() << ShowX509{cert}).c_str());
    }
    if (preverify_ok) {  // cert passed initial inspection
    }
    log_printf(_io, preverify_ok ? Level::Debug : Level::Err, "TLS verify %s\n", preverify_ok ? "Ok" : "Reject");
    return preverify_ok;
}

namespace {

constexpr int ossl_verify_depth = 5;

// see NOTE in "man SSL_CTX_set_alpn_protos"
const unsigned char pva_alpn[] = "\x05pva/1";

struct OSSLGbl {
    ossl_ptr<OSSL_LIB_CTX> libctx;
    int SSL_CTX_ex_idx;
#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    std::ofstream keylog;
    epicsMutex keylock;
#endif
} *ossl_gbl;

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
void sslkeylogfile_exit(void *) noexcept {
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

void sslkeylogfile_log(const SSL *, const char *line) noexcept {
    auto gbl = ossl_gbl;
    try {
        epicsGuard<epicsMutex> G(gbl->keylock);
        if (gbl->keylog.is_open()) {
            gbl->keylog << line << '\n';
            gbl->keylog.flush();
        }
    } catch (std::exception &e) {
        static bool once = false;
        if (!once) {
            fprintf(stderr, "Error while writing to SSLKEYLOGFILE\n");
            once = true;
        }
    }
}
#endif  // PVXS_ENABLE_SSLKEYLOGFILE

struct SSL_CTX_sidecar {
    ossl_ptr<X509> cert;
};

void free_SSL_CTX_sidecar(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) noexcept {
    auto car = static_cast<SSL_CTX_sidecar *>(ptr);
    delete car;
}

void OSSLGbl_init() {
    ossl_ptr<OSSL_LIB_CTX> ctx(__FILE__, __LINE__, OSSL_LIB_CTX_new());
    // read $OPENSSL_CONF or eg. /usr/lib/ssl/openssl.cnf
    (void)CONF_modules_load_file_ex(ctx.get(), NULL, "pvxs", CONF_MFLAGS_IGNORE_MISSING_FILE | CONF_MFLAGS_IGNORE_RETURN_CODES);
    std::unique_ptr<OSSLGbl> gbl{new OSSLGbl};
    gbl->SSL_CTX_ex_idx = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, free_SSL_CTX_sidecar);
#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    if (auto env = getenv("SSLKEYLOGFILE")) {
        epicsGuard<epicsMutex> G(gbl->keylock);
        gbl->keylog.open(env);
        if (gbl->keylog.is_open()) {
            epicsAtExit(sslkeylogfile_exit, nullptr);
            log_warn_printf(_setup, "TLS Debug Enabled: logging TLS secrets to %s\n", env);
        } else {
            log_err_printf(_setup, "TLS Debug Disabled: Unable to open SSL key log file: %s\n", env);
        }
    }
#endif  // PVXS_ENABLE_SSLKEYLOGFILE
    ossl_gbl = gbl.release();
}

int ossl_alpn_select(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *) {
    unsigned char *selected;
    auto ret(SSL_select_next_proto(&selected, outlen, pva_alpn, sizeof(pva_alpn) - 1u, in, inlen));
    if (ret == OPENSSL_NPN_NEGOTIATED) {
        *out = selected;
        log_debug_printf(_io, "TLS ALPN select%s", "\n");
        return SSL_TLSEXT_ERR_OK;
    } else {  // OPENSSL_NPN_NO_OVERLAP
        log_err_printf(_io, "TLS ALPN reject%s", "\n");
        return SSL_TLSEXT_ERR_ALERT_FATAL;  // could fail soft w/ SSL_TLSEXT_ERR_NOACK
    }
}

/**
 * @brief Get a certificate from the given file
 *
 * This function reads a p12 object from the provided file and returns true if successful.
 *
 * @param fp The file pointer of the p12 file.
 * @param p12 The PKCS12 object reference to be updated
 * @param ssl_client True if the request came from a client, false from a server
 * @param p12_filename The filename of the p12 file
 *
 * @return true if the p12 file exists and can be read
 * @return false if the p12 file does not exist or is invalid and the request was from a client
 *
 * @throws std::runtime_error("Invalid, Untrusted, or Nonexistent p12 file  ...")
 *         if p12 file not found or invalid and it if for a server
 */
bool checkP12File(file_ptr &fp, ossl_ptr<PKCS12> &p12, const uint16_t &usage, const std::string &p12_filename) {
    // Return true if it exists and is readable
    if (fp && d2i_PKCS12_fp(fp.get(), p12.acquire())) return true;

    // If file not found or unreadable
    if (usage == ssl::kForClient) {
        // Client ONLY can create SSL session even though it has no certificate/key as long as the server allows it
        return false;
    } else {
        throw std::runtime_error(SB() << "Invalid, Untrusted, or Nonexistent p12 file at [" << p12_filename << "]");
    }
}

/**
 * @brief Verifies the key usage of a given certificate.
 *
 * This function checks the key usage extension of the specified certificate
 * and verifies that the key usage flags match the intended purpose.
 * If ssl_client is set to true, it will verify that the key usage includes
 * the key encipherment flag.
 *
 * If ssl_client is set to false, it will verify
 * that the key usage includes the digital signature flag.
 *
 * @param cert The X509 certificate to verify key usage for.
 * @param ssl_client A flag indicating whether the certificate is for SSL
 * client.
 * @return Don't throw if the key usage is valid for the intended purpose,
 * throw an exception otherwise.
 */
void verifyKeyUsage(const ossl_ptr<X509> &cert,
                    bool ssl_client) {  // some early sanity checks
    auto flags(X509_get_extension_flags(cert.get()));
    auto kusage(X509_get_extended_key_usage(cert.get()));

    if (flags & EXFLAG_CA) throw std::runtime_error(SB() << "Found CA Certificate when End Entity expected");

    if ((ssl_client && !(kusage & XKU_SSL_CLIENT)) || (!ssl_client && !(kusage & XKU_SSL_SERVER)))
        throw std::runtime_error(SB() << "Extended Key Usage does not permit usage as a Secure PVAccesss " << (ssl_client ? "Client" : "Server"));

    log_debug_printf(_setup, "Using%s cert %s\n", (flags & EXFLAG_SS) ? " self-signed" : "", std::string(SB() << ShowX509{cert.get()}).c_str());
}

/**
 * @brief Extracts the certificate authorities from the provided CAs and
 * adds them to the given context.
 *
 * java keytool adds an extra attribute to indicate that a certificate
 * is trusted.  However, PKCS12_parse() circa 3.1 does not know about
 * this, and gives us all the certs. in one blob for us to sort through.
 *
 * We _assume_ that any root CA included in a PKCS#12 file is meant to
 * be trusted.  Otherwise, such a cert. could never appear in a valid
 * chain.
 *
 * @param ctx the context to add the CAs to
 * @param CAs the stack of X509 CA certificates
 */
void extractCAs(SSLContext &ctx, const ossl_ptr<stack_st_X509> &CAs) {
    for (int i = 0, N = sk_X509_num(CAs.get()); i < N; i++) {
        auto ca = sk_X509_value(CAs.get(), i);

        auto canSign(X509_check_ca(ca));
        auto flags(X509_get_extension_flags(ca));

        if (canSign == 0 && i != 0) {
            log_err_printf(_setup, "non-CA certificate in PKCS#12 chain%s\n", "");
            log_err_printf(_setup, "%s\n", (SB() << ShowX509{ca}).str().c_str());
            throw std::runtime_error(SB() << "non-CA certificate found in PKCS#12 chain");
        }

        if (flags & EXFLAG_SS) {        // self-signed (aka. root)
            assert(flags & EXFLAG_SI);  // circa OpenSSL, self-signed implies self-issued

            log_debug_printf(_setup, "Trusting root CA %s\n", std::string(SB() << ShowX509{ca}).c_str());

            // populate SSL_CTX::cert_store
            auto trusted = SSL_CTX_get_cert_store(ctx.ctx);
            assert(trusted);
            if (!X509_STORE_add_cert(trusted, ca)) throw SSLError("X509_STORE_add_cert");

        } else {  // signed by another CA
            log_debug_printf(_setup, "Using untrusted/chain CA cert %s\n", std::string(SB() << ShowX509{ca}).c_str());

            // note: chain certs added this way are ignored unless SSL_BUILD_CHAIN_FLAG_UNTRUSTED
            //       passed below.
            // appends SSL_CTX::cert::chain
            if (!SSL_CTX_add0_chain_cert(ctx.ctx, ca)) throw SSLError("SSL_CTX_add0_chain_cert");
        }
    }
}

/**
 * @brief Common setup for OpenSSL SSL context
 *
 * This function sets up the OpenSSL SSL context used for SSL/TLS communication.
 * It configures the SSL method, whether it is for a client or a server, and the
 * common configuration options.
 *
 * @param method The SSL_METHOD object representing the SSL method to use.
 * @param ssl_client A boolean indicating whether the setup is for a client or a
 * server.
 * @param conf The common configuration object.
 *
 * @return SSLContext initialised appropriately - clients can have an empty
 * context so that they can connect to ssl servers without having a certificate
 */
SSLContext ossl_setup_common(const SSL_METHOD *method, bool ssl_client, const impl::ConfigCommon &conf) {
    impl::threadOnce<&OSSLGbl_init>();

    // Initialise SSL subsystem and add our custom extensions (idempotent)
    SSLContext::sslInit();

    SSLContext ctx;
    ctx.ctx = SSL_CTX_new_ex(ossl_gbl->libctx.get(), NULL, method);
    if (!ctx.ctx) throw SSLError("Unable to allocate SSL_CTX");

    {
        std::unique_ptr<SSL_CTX_sidecar> car{new SSL_CTX_sidecar};
        if (!SSL_CTX_set_ex_data(ctx.ctx, ossl_gbl->SSL_CTX_ex_idx, car.get())) throw SSLError("SSL_CTX_set_ex_data");
        car.release();  // SSL_CTX_free() now responsible
    }

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    //    assert(!SSL_CTX_get_keylog_callback(ctx.ctx));
    (void)SSL_CTX_set_keylog_callback(ctx.ctx, &sslkeylogfile_log);
#endif

    // TODO: SSL_CTX_set_options(), SSL_CTX_set_mode() ?

    // we mandate TLS >= 1.3
    (void)SSL_CTX_set_min_proto_version(ctx.ctx, TLS1_3_VERSION);
    (void)SSL_CTX_set_max_proto_version(ctx.ctx, 0);  // up to max.

    if (ssl_client && conf.tls_disabled) {
        // For clients if tls is disabled then allow server to make a tls
        // connection if it can but disable client side
        return ctx;
    }

    if (conf.isTlsConfigured()) {
        // Get key
        ossl_ptr<EVP_PKEY> key;
        {
            const std::string &key_filename = conf.tls_private_key_filename, &key_password = conf.tls_private_key_password;
            log_debug_printf(_setup, "private key filename (PKCS12) %s;%s\n", key_filename.c_str(), key_password.empty() ? "" : " w/ password");

            file_ptr fp(fopen(key_filename.c_str(), "rb"), false);
            ossl_ptr<PKCS12> p12;

            // Check the key file
            if (!checkP12File(fp, p12, (ssl_client ? ssl::kForClient : ssl::kForServer), key_filename))
                // If this is a client then continue without a cert
                return ctx;

            if (!PKCS12_parse(p12.get(), key_password.c_str(), key.acquire(), nullptr, nullptr))
                throw SSLError(SB() << "Unable to process \"" << key_filename << "\"");
        }

        // Get certificate
        ossl_ptr<X509> cert;
        ossl_ptr<STACK_OF(X509)> CAs(__FILE__, __LINE__, sk_X509_new_null());
        {
            const std::string &filename = conf.tls_cert_filename, &password = conf.tls_cert_password;
            log_debug_printf(_setup, "cert filename (PKCS12) %s;%s\n", filename.c_str(), password.empty() ? "" : " w/ password");

            file_ptr fp(fopen(filename.c_str(), "rb"), false);
            ossl_ptr<PKCS12> p12;

            // Try to open the certificate file
            if (!checkP12File(fp, p12, (ssl_client ? ssl::kForClient : ssl::kForServer), filename))
                // If this is a client then continue without cert
                return ctx;

            ossl_ptr<EVP_PKEY> pkey;  // to discard
            if (!PKCS12_parse(p12.get(), password.c_str(), pkey.acquire(), cert.acquire(), CAs.acquire()))
                throw SSLError(SB() << "Unable to process \"" << filename << "\"");
        }
        if (cert) {
            // some early sanity checks
            verifyKeyUsage(cert, ssl_client);
        }

        // the following is ~= SSL_CTX_use_cert_and_key()
        // except for special handling of root CA (maybe) appearing in PKCS12 chain

        // sets SSL_CTX::cert
        if (cert && !SSL_CTX_use_certificate(ctx.ctx, cert.get())) throw SSLError("SSL_CTX_use_certificate");
        if (key && !SSL_CTX_use_PrivateKey(ctx.ctx, key.get())) throw SSLError("SSL_CTX_use_certificate");

        /* java keytool adds an extra attribute to indicate that a certificate
         * is trusted.  However, PKCS12_parse() circa 3.1 does not know about
         * this, and gives us all of the certs. in one blob for us to sort through.
         *
         * We _assume_ that any root CA included in a PKCS#12 file is meant to be
         * trusted.  Otherwise, such a cert. could never appear in a valid chain.
         */

        // extract CAs (intermediate and root) from PKCS12 bag
        extractCAs(ctx, CAs);

        if (key && !SSL_CTX_check_private_key(ctx.ctx)) throw SSLError("invalid private key");

        if (cert) {
            auto car = static_cast<SSL_CTX_sidecar *>(SSL_CTX_get_ex_data(ctx.ctx, ossl_gbl->SSL_CTX_ex_idx));
            car->cert = std::move(cert);

            if (!SSL_CTX_build_cert_chain(ctx.ctx, SSL_BUILD_CHAIN_FLAG_UNTRUSTED))  // SSL_BUILD_CHAIN_FLAG_CHECK
                throw SSLError("invalid cert chain");
        }
    }

    {
        /* wrt. SSL_VERIFY_CLIENT_ONCE
         *   TLS 1.3 does not support session renegotiation.
         *   Does allow server to re-request client cert. via CertificateRequest.
         *   However, no way for client to re-request server cert.
         *   So we don't bother with this, and instead for connection reset
         *   when new certs. loaded.
         */
        int mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
        if (!ssl_client && conf.tls_client_cert_required == ConfigCommon::Require) {
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            log_debug_printf(_setup, "This Secure PVAccess Server requires an X.509 client certificate%s", "\n");
        }
        SSL_CTX_set_verify(ctx.ctx, mode, &ossl_verify);
        SSL_CTX_set_verify_depth(ctx.ctx, ossl_verify_depth);
    }

    return ctx;
}

}  // namespace

// Must be set up with correct values after OpenSSL initialisation to retrieve status PV from certs
int SSLContext::NID_PvaCertStatusURI = NID_undef;

bool SSLContext::have_certificate() const {
    if (!ctx) throw std::invalid_argument("NULL");

    auto car = static_cast<SSL_CTX_sidecar *>(SSL_CTX_get_ex_data(ctx, ossl_gbl->SSL_CTX_ex_idx));
    return car->cert.operator bool();
}

const X509 *SSLContext::certificate0() const {
    if (!ctx) throw std::invalid_argument("NULL");

    auto car = static_cast<SSL_CTX_sidecar *>(SSL_CTX_get_ex_data(ctx, ossl_gbl->SSL_CTX_ex_idx));
    return car->cert.get();
}

bool SSLContext::fill_credentials(PeerCredentials &C, const SSL *ctx) {
    if (!ctx) throw std::invalid_argument("NULL");

    if (auto cert = SSL_get0_peer_certificate(ctx)) {
        PeerCredentials temp(C);  // copy current as initial (don't overwrite isTLS)
        auto subj = X509_get_subject_name(cert);
        char name[64];
        if (subj && X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name) - 1)) {
            name[sizeof(name) - 1] = '\0';
            log_debug_printf(_io, "Peer CN=%s\n", name);
            temp.method = "x509";
            temp.account = name;

            // try to use root CA name to qualify authority
            if (auto chain = SSL_get0_verified_chain(ctx)) {
                auto N = sk_X509_num(chain);
                X509 *root;
                X509_NAME *rootName;
                // last cert should be root CA
                if (N && !!(root = sk_X509_value(chain, N - 1)) && !!(rootName = X509_get_subject_name(root)) &&
                    X509_NAME_get_text_by_NID(rootName, NID_commonName, name, sizeof(name) - 1)) {
                    if (X509_check_ca(root) && (X509_get_extension_flags(root) & EXFLAG_SS)) {
                        temp.authority = name;

                    } else {
                        log_warn_printf(_io, "Last cert in peer chain is not root CA?!? %s\n", std::string(SB() << ossl::ShowX509{root}).c_str());
                    }
                }
            }
        }

        C = std::move(temp);
        return true;
    } else {
        return false;
    }
}

SSLContext SSLContext::for_client(const impl::ConfigCommon &conf) {
    auto ctx(ossl_setup_common(TLS_client_method(), true, conf));

    if (0 != SSL_CTX_set_alpn_protos(ctx.ctx, pva_alpn, sizeof(pva_alpn) - 1))
        throw SSLError("Unable to agree on Application Layer Protocol to use: Both sides should use pva/1");

    return ctx;
}

SSLContext SSLContext::for_server(const impl::ConfigCommon &conf) {
    auto ctx(ossl_setup_common(TLS_server_method(), false, conf));

    SSL_CTX_set_alpn_select_cb(ctx.ctx, &ossl_alpn_select, nullptr);

    return ctx;
}

SSLError::SSLError(const std::string &msg)
    : std::runtime_error([&msg]() -> std::string {
          std::ostringstream strm;
          const char *file = nullptr;
          int line = 0;
          const char *data = nullptr;
          int flags = 0;
          while (auto err = ERR_get_error_all(&file, &line, nullptr, &data, &flags)) {
              strm << file << ':' << line << ':' << ERR_reason_error_string(err);
              if (data && (flags & ERR_TXT_STRING)) strm << ':' << data;
              strm << ", ";
          }
          strm << msg;
          return strm.str();
      }()) {}

SSLError::~SSLError() = default;

std::ostream &operator<<(std::ostream &strm, const ShowX509 &cert) {
    if (cert.cert) {
        auto name = X509_get_subject_name(cert.cert);
        auto issuer = X509_get_issuer_name(cert.cert);
        assert(name);
        ossl_ptr<BIO> io(__FILE__, __LINE__, BIO_new(BIO_s_mem()));
        (void)BIO_printf(io.get(), "subject:");
        (void)X509_NAME_print(io.get(), name, 1024);
        (void)BIO_printf(io.get(), " issuer:");
        (void)X509_NAME_print(io.get(), issuer, 1024);
        if (auto atm = X509_get0_notBefore(cert.cert)) {
            if (atm) {
                (void)BIO_printf(io.get(), " from: ");
                ASN1_TIME_print(io.get(), atm);
            }
        }
        if (auto atm = X509_get0_notAfter(cert.cert)) {
            if (atm) {
                (void)BIO_printf(io.get(), " until: ");
                ASN1_TIME_print(io.get(), atm);
            }
        }
        {
            char *str = nullptr;
            if (auto len = BIO_get_mem_data(io.get(), &str)) {
                strm.write(str, len);
            }
        }
    } else {
        strm << "NULL";
    }
    return strm;
}

}  // namespace ossl
}  // namespace pvxs
