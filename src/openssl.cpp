/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <tuple>

#include <epicsExit.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <pvxs/log.h>

#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "evhelper.h"
#include "ownedptr.h"
#include "serverconn.h"
#include "utilpvt.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

DEFINE_LOGGER(setup, "pvxs.ossl.init");
DEFINE_LOGGER(stapling, "pvxs.stapling");
DEFINE_LOGGER(watcher, "pvxs.certs.mon");
DEFINE_LOGGER(io, "pvxs.ossl.io");

namespace pvxs {
namespace ossl {

int ossl_verify(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    X509 *cert_ptr = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (!preverify_ok) {
        auto err = X509_STORE_CTX_get_error(x509_ctx);
        log_err_printf(io, "Unable to verify peer cert: %s : %s\n", X509_verify_cert_error_string(err), std::string(SB() << ShowX509{cert_ptr}).c_str());
    }
    log_printf(io, preverify_ok ? Level::Debug : Level::Err, "TLS verify %s\n", preverify_ok ? "Ok" : "Reject");
    return preverify_ok;
}

void ensureTrusted(const ossl_ptr<X509> &ca_cert, const ossl_ptr<STACK_OF(X509)> &CAs) {
    // Create a new X509_STORE with trusted root CAs
    ossl_ptr<X509_STORE> store(X509_STORE_new(), false);
    if (!store) {
        throw std::runtime_error("Failed to create X509_STORE to verify CA trust");
    }

    // Load trusted root CAs from a predefined location
    if (X509_STORE_set_default_paths(store.get()) != 1) {
        throw std::runtime_error("Failed to load system default CA certificates to verify CA trust");
    }

    // Set up a store context for verification
    ossl_ptr<X509_STORE_CTX> ctx(X509_STORE_CTX_new(), false);
    if (!ctx) {
        throw std::runtime_error("Failed to create X509_STORE_CTX to verify CA trust");
    }

    if (X509_STORE_CTX_init(ctx.get(), store.get(), ca_cert.get(), CAs.get()) != 1) {
        throw std::runtime_error("Failed to initialize X509_STORE_CTX to verify CA certificate");
    }

    // Set parameters for verification of the CA certificate
    X509_STORE_CTX_set_flags(ctx.get(),
                             X509_V_FLAG_PARTIAL_CHAIN |           // Succeed as soon as at least one intermediary is trusted
                                 X509_V_FLAG_CHECK_SS_SIGNATURE |  // Allow self-signed root CA
                                 X509_V_FLAG_TRUSTED_FIRST         // Check the trusted locations first
    );
    if (X509_verify_cert(ctx.get()) != 1) {
        throw std::runtime_error("Certificate is not trusted by this host");
    }
}

/**
 * @brief Check cert status and set the TLS context state to TCP_READY or TLS_READY
 *
 * Monitor all certs that need monitoring and then set the TCP/TLS status appropriately
 *
 * @param cert_data
 */
void SSLContext::monitorStatusAndSetState(certs::CertData &cert_data) {
    if (!status_check_disabled) {
        if (certs::CertStatusManager::shouldMonitor(cert_data.cert.get())) {
            auto cert_to_monitor = ossl_ptr<X509>(X509_dup(cert_data.cert.get()));
            cert_monitor = certs::CertStatusManager::subscribe(std::move(cert_to_monitor), [=](const certs::PVACertificateStatus &pva_status) {
                {
                    Guard G(lock);
                    cert_status = pva_status;
                }
                // set TLS context state appropriately based on new status
                setTlsOrTcpMode();

                // Start validity timer for status
                setStatusValidityCountdown();
            }, allow_self_signed_ca);
        } else {
            Guard G(lock);
            cert_status = certs::PVACertificateStatus(certs::UnCertifiedCertificateStatus());
        }
    }

    // Set the state
    Guard G(lock);
    state = (status_check_disabled || cert_status.isGood()) ? TlsReady : TcpReady;
}

/**
 * @brief Set degraded mode
 *
 * Clear all monitors and statuses then set tls context state to degraded
 */
void SSLContext::setDegradedMode(bool clear) {
    Guard G(lock);
    if (cert_monitor) cert_monitor->unsubscribe();
    if (clear) {
        cert_monitor.reset();
        cert_status = {};
    }
    state = DegradedMode;
}

/**
 * @brief Transition TLS mode when monitored statuses change good
 */
void SSLContext::setTlsOrTcpMode() {
    Guard G(lock);
    if (((certs::CertificateStatus)cert_status).isRevokedOrExpired()) {
        setDegradedMode();
        return;
    }
    if (state == TcpReady && cert_status.isGood()) state = TlsReady;
    if (state == TlsReady && !cert_status.isGood()) state = TcpReady;
}

SSLContext::SSLContext(const impl::evbase &loop) : loop(loop) {}

SSLContext::SSLContext(const SSLContext &o)
    : ctx(o.ctx), state(o.state), status_check_disabled(o.status_check_disabled), stapling_disabled(o.stapling_disabled), loop(o.loop) {
    if (ctx) {
        auto ret(SSL_CTX_up_ref(ctx.get()));
        assert(ret == 1);  // can up_ref actually fail?
    }
}

SSLContext::SSLContext(SSLContext &o) noexcept
    : ctx(o.ctx), state(o.state), status_check_disabled(o.status_check_disabled), stapling_disabled(o.stapling_disabled), loop(o.loop) {
    o.ctx = nullptr;
}

SSLContext &SSLContext::operator=(SSLContext &&o) noexcept {
    if (cert_monitor) cert_monitor->unsubscribe();

    ctx = o.ctx;
    state = o.state;
    status_check_disabled = o.status_check_disabled;
    stapling_disabled = o.stapling_disabled;
    cert_status = o.cert_status;
    status_validity_timer = std::move(o.status_validity_timer);
    cert_monitor = std::move(o.cert_monitor);

    o.ctx = nullptr; // Invalidate the other tls_context
    return *this;
}

void SSLContext::setStatusValidityCountdown() {
    auto now = time(nullptr);
    timeval validity_end = {cert_status.status_valid_until_date.t - now, 0};
    if (status_validity_timer) {
        event_del(status_validity_timer.get());
        if (event_add(status_validity_timer.get(), &validity_end)) log_err_printf(watcher, "Error starting certificate status validity timer\n%s", "");
    }
}

void SSLContext::statusValidityExpirationHandler(evutil_socket_t fd, short evt, void *raw) {
    auto self = *static_cast<SSLContext *>(raw);
    if (!self.cert_status.isValid()) {
        {
            Guard G(self.lock);
            // We need to get the PVAStatus because we may need the OCSP stapling data if this is a server
            self.cert_status = *self.cert_monitor->getPVAStatus();
        }
        self.setTlsOrTcpMode();
    }
    // Chain another status validity check if new status is valid
    if (self.cert_status.isValid()) self.setStatusValidityCountdown();
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

void free_SSL_CTX_sidecar(void *, void *ptr, CRYPTO_EX_DATA *, int, long, void *) noexcept {
    auto car = static_cast<CertStatusExData *>(ptr);
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
            log_warn_printf(setup, "TLS Debug Enabled: logging TLS secrets to %s\n", env);
        } else {
            log_err_printf(setup, "TLS Debug Disabled: Unable to open SSL key log file: %s\n", env);
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
        log_debug_printf(io, "TLS ALPN select%s", "\n");
        return SSL_TLSEXT_ERR_OK;
    } else {  // OPENSSL_NPN_NO_OVERLAP
        log_err_printf(io, "TLS ALPN reject%s", "\n");
        return SSL_TLSEXT_ERR_ALERT_FATAL;  // could fail soft w/ SSL_TLSEXT_ERR_NOACK
    }
}

/**
 * @brief Verifies the key usage of a given certificate.
 *
 * This function checks the key usage extension of the specified certificate
 * and verifies that the key usage flags match the intended purpose.
 * If isForClient is set to true, it will verify that the key usage includes
 * the key encipherment flag.
 *
 * If isForClient is set to false, it will verify
 * that the key usage includes the digital signature flag.
 *
 * @param cert The X509 certificate to verify key usage for.
 * @param isForClient A flag indicating whether the certificate is for SSL
 * client.
 * @return Don't throw if the key usage is valid for the intended purpose,
 * throw an exception otherwise.
 */
void verifyKeyUsage(const ossl_ptr<X509> &cert,
                    bool isForClient) {  // some early sanity checks
    auto flags(X509_get_extension_flags(cert.get()));
    auto kusage(X509_get_extended_key_usage(cert.get()));

    if (flags & EXFLAG_CA) throw std::runtime_error(SB() << "Found CA Certificate when End Entity expected");

    if ((isForClient && !(kusage & XKU_SSL_CLIENT)) || (!isForClient && !(kusage & XKU_SSL_SERVER)))
        throw std::runtime_error(SB() << "Extended Key Usage does not permit usage as a Secure PVAccess " << (isForClient ? "Client" : "Server"));

    log_debug_printf(setup, "Using%s cert %s\n", (flags & EXFLAG_SS) ? " self-signed" : "", std::string(SB() << ShowX509{cert.get()}).c_str());
}

/**
 * @brief Extracts the certificate authorities from the provided CAs and
 * adds them to the given context.
 *
 * java keytool adds an extra attribute to indicate that a certificate
 * is trusted.  However, PKCS12_parse() circa 3.1 does not know about
 * this, and gives us all the certs. in one blob for us to sort through.
 *
 * We _assume_ that any root CA included in a keychain file is meant to
 * be trusted.  Otherwise, such a cert. could never appear in a valid
 * chain.
 *
 * @param ctx the context to add the CAs to
 * @param CAs the stack of X509 CA certificates
 */
void extractCAs(std::shared_ptr<SSLContext> ctx, const ossl_shared_ptr<STACK_OF(X509)> &CAs) {
    for (int i = 0, N = sk_X509_num(CAs.get()); i < N; i++) {
        auto ca = sk_X509_value(CAs.get(), i);

        auto canSign(X509_check_ca(ca));
        auto flags(X509_get_extension_flags(ca));

        // Check for non-CA certificates
        if (canSign == 0 && i != 0) {
            log_err_printf(setup, "non-CA certificate in keychain%s\n", "");
            log_err_printf(setup, "%s\n", (SB() << ShowX509{ca}).str().c_str());
            throw std::runtime_error(SB() << "non-CA certificate found in keychain");
        }

        if (flags & EXFLAG_SS) {        // self-signed (aka. root)
            assert(flags & EXFLAG_SI);  // circa OpenSSL, self-signed implies self-issued

            if (!ctx->allow_self_signed_ca) {
                throw std::runtime_error(SB() << "Self-signed certificate: "  << ShowX509{ca});
            }

            // populate the context's trust store with the self-signed root cert
            X509_STORE *trusted_store = SSL_CTX_get_cert_store(ctx->ctx.get());
            if (!X509_STORE_add_cert(trusted_store, ca)) throw SSLError("X509_STORE_add_cert");
        } else {
            // signed by another CA
            // note: chain certs added this way are ignored unless SSL_BUILD_CHAIN_FLAG_UNTRUSTED is used
            // appends SSL_CTX::cert::chain
        }
        if (!SSL_CTX_add0_chain_cert(ctx->ctx.get(), ca)) throw SSLError("SSL_CTX_add0_chain_cert");
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
 * @param isForClient A boolean indicating whether the setup is for a client or a
 * server.
 * @param conf The common configuration object.
 *
 * @return SSLContext initialised appropriately - clients can have an empty
 * context so that they can connect to ssl servers without having a certificate
 */
std::shared_ptr<SSLContext> commonSetup(const SSL_METHOD *method, bool isForClient, const impl::ConfigCommon &conf, const impl::evbase& loop) {
    impl::threadOnce<&OSSLGbl_init>();

    // Initialise SSL subsystem and add our custom extensions (idempotent)
    SSLContext::sslInit();

    auto tls_context = std::make_shared<SSLContext>(SSLContext(loop));
    tls_context->status_check_disabled = conf.tls_disable_status_check;
    tls_context->stapling_disabled = conf.tls_disable_stapling;
    tls_context->allow_self_signed_ca = conf.allow_self_signed_ca;
    tls_context->ctx = ossl_shared_ptr<SSL_CTX>(SSL_CTX_new_ex(ossl_gbl->libctx.get(), NULL, method));
    if (!tls_context->ctx) throw SSLError("Unable to allocate SSL_CTX");

    {
        // Add the CertStatusExData to the SSL context so that it will be available
        // any time the SSL context is available to provide access to the entity certificate,
        // peer statuses and other custom data.
        std::unique_ptr<CertStatusExData> car{new CertStatusExData(loop, !tls_context->status_check_disabled, tls_context->allow_self_signed_ca)};
        if (!SSL_CTX_set_ex_data(tls_context->ctx.get(), ossl_gbl->SSL_CTX_ex_idx, car.get())) throw SSLError("SSL_CTX_set_ex_data");
        car.release();  // SSL_CTX_free() now responsible (using our registered callback `free_SSL_CTX_sidecar`)
    }

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    // Set the keylog callback to log the TLS secrets to the file
    (void)SSL_CTX_set_keylog_callback(tls_context->ctx.get(), &sslkeylogfile_log);
#endif

    // Set minimum and maximum protocol versions.  Version 1.3 is the minimum
    (void)SSL_CTX_set_min_proto_version(tls_context->ctx.get(), TLS1_3_VERSION);
    (void)SSL_CTX_set_max_proto_version(tls_context->ctx.get(), 0);

    // If TLS is disabled or not configured then set the context to degraded mode so that
    // only TCP connections are allowed.
    if (conf.tls_disabled || !conf.isTlsConfigured()) {
        tls_context->state = ossl::SSLContext::DegradedMode;
        return tls_context;
    }

    // TLS is configured, so get the key and certificate from the file or files
    const std::string &filename = conf.tls_cert_filename, &password = conf.tls_cert_password;
    auto key_filename = conf.tls_private_key_filename.empty() ? filename : conf.tls_private_key_filename;
    auto key_password = conf.tls_private_key_password.empty() ? password : conf.tls_private_key_password;
    auto cert_data = certs::IdFileFactory::createReader(filename, password, key_filename, key_password)->getCertDataFromFile();
    if (!cert_data.cert) throw std::runtime_error("No Certificate");

    // Verify the key usage of the certificate
    verifyKeyUsage(cert_data.cert, isForClient);

    // Use the certificate in the context
    if (!SSL_CTX_use_certificate(tls_context->ctx.get(), cert_data.cert.get())) throw SSLError("using certificate");

    // Check the private key
    if (!cert_data.key_pair) throw std::runtime_error("No private key");
    if (!SSL_CTX_use_PrivateKey(tls_context->ctx.get(), cert_data.key_pair->pkey.get())) throw SSLError("using private key");
    extractCAs(tls_context, cert_data.ca);
    if (!cert_data.key_pair->pkey || !SSL_CTX_check_private_key(tls_context->ctx.get())) throw SSLError("invalid private key");

    // Build the certificate chain and set verification flags
    // Note useful flags are:
    //  SSL_BUILD_CHAIN_FLAG_CHECK - Fully check CA certificate chain and fail if any are not trusted
    //  SSL_BUILD_CHAIN_FLAG_UNTRUSTED - Flag untrusted in build chain but still use it
    //  0 - run defualt checks
    if (!SSL_CTX_build_cert_chain(tls_context->ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK))
        throw SSLError("invalid cert chain");

    // TLS is now configured:
    //  - Entity certificate valid,
    //  - CA certificate valid,
    //  - CA certificate chain valid,
    //  - CA certificate trusted,
    //  - Private key valid
    // Start monitoring entity certificate status and set TLS context state accordingly
    tls_context->monitorStatusAndSetState(cert_data);

    // Move entity certificate to the custom data in the SSL context
    auto cert_status_ex_data = tls_context->getCertStatusExData();
    cert_status_ex_data->cert = std::move(cert_data.cert);

    // Configure what and how to verify certificates in the TLS handshake
    // Note useful mode flags are:
    //  - SSL_VERIFY_PEER - Verify peer certificate
    //  - SSL_VERIFY_CLIENT_ONCE - Verify client certificate once
    //  - SSL_VERIFY_FAIL_IF_NO_PEER_CERT - Fail if no peer certificate present (only for servers)
    {
        int mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
        if (!isForClient && conf.tls_client_cert_required == ConfigCommon::Require) {
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            log_debug_printf(setup, "This Secure PVAccess Server requires an X.509 client certificate%s", "\n");
        }
        // Configure our custom verification function `ossl_verify` to be called by the TLS handshake
        SSL_CTX_set_verify(tls_context->ctx.get(), mode, &ossl_verify);
        // Configure the maximum depth of the certificate chain to verify
        SSL_CTX_set_verify_depth(tls_context->ctx.get(), ossl_verify_depth);
    }

    return tls_context;
}

}  // namespace

/**
 * @brief This is the callback that is made by the TLS handshake to add the server OCSP status to the payload
 *
 * @param ssl the SSL session to add the OCSP response to
 * @param server the server object to get the OCSP response from
 * @return SSL_TLSEXT_ERR_OK if the OCSP response was added successfully,
 *         SSL_TLSEXT_ERR_ALERT_WARNING if the callback should not have been called, (never happens)
 *         SSL_TLSEXT_ERR_NOACK if the OCSP response was not added - no status available to staple at this time
 *         SSL_TLSEXT_ERR_ALERT_FATAL if the OCSP response was not added - some error occurred adding the OCSP response
 */
int serverOCSPCallback(SSL *ssl, pvxs::server::Server::Pvt *server) {
    if (SSL_get_tlsext_status_type(ssl) != -1) {
        // Should never be triggered.  Because the callback should only be called when the client has requested stapling.
        return SSL_TLSEXT_ERR_ALERT_WARNING;
    }

    if (!((certs::CertificateStatus)server->tls_context->get_status()).isValid()) {
        log_warn_printf(stapling, "Server OCSP Stapling: No server status to staple%s\n", "");
        return SSL_TLSEXT_ERR_NOACK;
    }

    auto& current_status = server->tls_context->get_status();
    auto ocsp_data_ptr = (void *)current_status.ocsp_bytes.data();
    auto ocsp_data_len = current_status.ocsp_bytes.size();

    if (!server->cached_ocsp_response || server->cached_ocsp_status_date != current_status.status_date.t) {
        // if status has changed
        Guard G(server->tls_context->lock);

        // Free up response
        if (server->cached_ocsp_response) {
            OPENSSL_free(server->cached_ocsp_response);
        }
        // Allocate a new one and copy in the response data
        server->cached_ocsp_response = OPENSSL_malloc(ocsp_data_len);
        memcpy(server->cached_ocsp_response, ocsp_data_ptr, ocsp_data_len);
        server->cached_ocsp_status_date = current_status.status_date.t;

        // Staple the data as the OCSP response for the TLS handshake
        if (SSL_set_tlsext_status_ocsp_resp(ssl, server->cached_ocsp_response, ocsp_data_len) != 1) {
            log_warn_printf(stapling, "Server OCSP Stapling: unable to staple server status%s\n", "");
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        } else
            log_info_printf(stapling, "Server OCSP Stapling: server status stapled%s\n", "");
    }
    return SSL_TLSEXT_ERR_OK;
}

/**
 * @brief Configure the server's OCSP callback
 *
 * This sets the callback that will be used called during TLS handshake to staple OCSP data on
 * the entity cert to the handshake data.
 *
 * The server object is passed to the callback so that the server can be referenced when the callback is called.
 * This allows the server's certificate status to be retrieved and used to staple the OCSP response to the handshake data.
 *
 * @param server_ptr pointer to the server object who's tls context is to be configured for stapling
 */
void configureServerOCSPCallback(void *server_ptr, SSL *) {
    auto server = (pvxs::server::Server::Pvt *)server_ptr;
    SSL_CTX_set_tlsext_status_arg(server->tls_context->ctx.get(), server);
    SSL_CTX_set_tlsext_status_cb(server->tls_context->ctx.get(), serverOCSPCallback);
}

// Must be set up with correct values after OpenSSL initialisation to retrieve status PV from certs
int SSLContext::NID_PvaCertStatusURI = NID_undef;

/**
 * @brief Sets the peer status for the given serial number
 *
 * This function sets the peer status for the certificate identified by the given serial number.
 * Only call this function if the status has changed or the status has expired.
 *
 * Peer status is cached in the CertStatusExData associated with the SSL context.
 * Each peer status associated with the TLS context is stored in a map with the serial number as the key.
 * Statuses have a validity period so the cached value is not updated until the validity period has expired.
 *
 * @param serial_number - Serial number
 * @param status - Certificate status
 * @return The peer status that was set
 */
std::shared_ptr<const certs::CertificateStatus> CertStatusExData::setCachedPeerStatus(serial_number_t serial_number, const certs::CertificateStatus &status, std::function<void(bool)> fn) {
    return setCachedPeerStatus(serial_number, std::make_shared<certs::CertificateStatus>(status), fn);
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
SSLPeerStatus &CertStatusExData::getOrCreatePeerStatus(serial_number_t serial_number, std::function<void(bool)> fn) {
    auto it = peer_statuses.find(serial_number);
    if (it != peer_statuses.end()) return it->second;

    auto sve_hparam = sveh_params.emplace(serial_number, StatusValidityExpirationHandlerParam{*this, serial_number}).second;
    impl::evevent validity_timer{__FILE__, __LINE__, event_new(loop.base, -1, EV_TIMEOUT, statusValidityExpirationHandler, &sve_hparam)};
    peer_statuses.emplace(serial_number,
                          SSLPeerStatus{std::make_shared<certs::CertificateStatus>(certs::UnknownCertificateStatus()), std::move(validity_timer), fn});
    return peer_statuses.find(serial_number)->second;
}

/**
 * @brief Subscribes to cert status if not already monitoring
 *
 * Subscribe to status is not already monitoring.
 * @param cert_ptr - Certificate status to subscribe to
 * @param fn - Function to call when the certificate status changes from good to bad or vice versa
 */
void CertStatusExData::subscribeToPeerCertStatus(X509 *cert_ptr, std::function<void(bool)> fn) noexcept {
    if (!cert_ptr) return;  // Nothing to subscribe to
    auto serial_number = getSerialNumber(cert_ptr);
    auto &peer_status = getOrCreatePeerStatus(serial_number, fn);
    auto &cert_status_manager = peer_status.cert_status_manager;
    if (cert_status_manager) return;  // Already subscribed

    if (!status_check_enabled) {
        // If we are subscribing to certificate status then we know the cert was VALID to make the connection
        // so if status checking is disabled we set it to be permanently VALID without getting further certification from PVACMS
        auto cached_peer_status = getCachedPeerStatus(serial_number);
        if (!cached_peer_status->isGood()) setCachedPeerStatus(serial_number, certs::UnCertifiedCertificateStatus());
        return;
    }

    try {
        auto cert_to_monitor = ossl_ptr<X509>(X509_dup(cert_ptr));
        // Subscribe to the certificate status
        cert_status_manager =
            certs::CertStatusManager::subscribe(std::move(cert_to_monitor), [this, &peer_status, serial_number, fn](certs::PVACertificateStatus status) {
                // Get the previous status
                auto previous_status = getCachedPeerStatus(serial_number);
                auto was_good = previous_status && previous_status->isGood();

                // Update the cached state
                setCachedPeerStatus(serial_number, status, fn);

                // Call the callback if there has been any state change
                bool is_good = status.isGood();
                if (is_good != was_good) {
                    fn(is_good);
                }
                if (status.isValid() && !status.isPermanent()) setStatusValidityCountdown(peer_status);
            }, allow_self_signed_ca);
    } catch (...) {
    }
}

/**
 * @brief Set the status validity countdown
 *
 * This sets the status validity countdown for the given peer status.  It also cancels any existing timer and starts a new one.
 * The timer is set to expire when the status validity period ends.
 *
 * @param peer_status - The peer status to set the validity countdown for
 */
void CertStatusExData::setStatusValidityCountdown(SSLPeerStatus &peer_status) {
    Guard G(lock);
    auto &status = peer_status.status;
    auto &status_validity_timer = peer_status.validity_timer;
    auto now = time(nullptr);
    timeval validity_end = {status->status_valid_until_date.t - now, 0};
    if (status_validity_timer) {
        event_del(status_validity_timer.get());
        if (event_add(status_validity_timer.get(), &validity_end)) log_err_printf(watcher, "Error starting peer certificate status validity timer\n%s", "");
    }
}

/**
 * @brief The event handler for the status validity expiration timer
 *
 * This is the event handler for the status validity expiration timer.  It is called when the timer expires and
 * the status validity period has ended.  It finds the CertStatusExData instance uaing the callback parameters that were set
 * and then calls its status validity expiration handler with the serial number of the peer status that expired.
 *
 * @param raw - The parameter for the event handler
 */
void CertStatusExData::statusValidityExpirationHandler(evutil_socket_t, short, void *raw) {
    auto sve_param = static_cast<StatusValidityExpirationHandlerParam *>(raw);
    auto &cert_status_ex_data = sve_param->cert_status_ex_data;
    cert_status_ex_data.statusValidityExpirationHandler(sve_param->serial_number);
}

/**
 * @brief The status validity expiration handler
 *
 * This is the status validity expiration handler.  It is called when the timer expires and
 * the status validity period has ended.  It finds the peer status using the serial number and then
 * updates the status and calls the callback if the status has changed and a callback is set.
 *
 * @param serial_number - The serial number of the peer status that expired
 */
void CertStatusExData::statusValidityExpirationHandler(serial_number_t serial_number) {
    auto it = peer_statuses.find(serial_number);
    if (it == peer_statuses.end()) {
        log_warn_printf(watcher, "Status Validation Expiration Handler called for certificate that is not monitored: %llu\n", serial_number);
        return;  // should never happen
    }
    auto &peer_status = it->second;
    auto &status = peer_status.status;
    auto &fn = peer_status.fn;
    auto was_good = status->isOstensiblyGood();
    setCachedPeerStatus(serial_number, peer_status.cert_status_manager->getStatus(), fn);
    auto is_good = status->isGood();
    if (is_good != was_good && fn) {
        fn(is_good);
    }
    // Chain another status validity check if new status is valid
    if (status->isValid()) setStatusValidityCountdown(peer_status);
}

/**
 * @brief Get the CertStatusExData from the given X509 store context
 *
 * This function retrieves the CertStatusExData from the SSL context associated with the given X509 store context.
 * This is the custom data that is added to the SSL context during tls context creation.
 *
 * @param x509_ctx the X509_STORE_CTX to get the SSL context and subsequently the CertStatusExData from
 * @return the CertStatusExData
 */
CertStatusExData *CertStatusExData::fromSSL_X509_STORE_CTX(X509_STORE_CTX *x509_ctx) {
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    return fromSSL(ssl);
}

/**
 * @brief Get the CertStatusExData from the SSL session
 *
 * This function retrieves the CertStatusExData from the SSL context associated with the given SSL session.
 * This is the custom data that is added to the SSL context during tls context creation.
 *
 * @param ssl the SSL session to get the CertStatusExData from
 * @return the CertStatusExData
 */
CertStatusExData *CertStatusExData::fromSSL(SSL *ssl) {
    if (!ssl) {
        return nullptr;
    }
    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    return fromSSL_CTX(ssl_ctx);
}

/**
 * @brief Get the CertStatusExData from the SSL context
 *
 * This function retrieves the CertStatusExData from the SSL context. This is the
 * custom data that is added to the SSL context during tls context creation.
 *
 * @param ssl_ctx the SSL context to get the CertStatusExData from
 * @return the CertStatusExData
 */
CertStatusExData *CertStatusExData::fromSSL_CTX(SSL_CTX *ssl_ctx) {
    if (!ssl_ctx) {
        return nullptr;
    }
    return static_cast<CertStatusExData *>(SSL_CTX_get_ex_data(ssl_ctx, ossl_gbl->SSL_CTX_ex_idx));
}

/**
 * @brief Get the CertStatusExData from the PVXS SSL context
 *
 * This function retrieves the CertStatusExData from the SSL context associated with the PVXS SSL context.
 * This is the custom data that is added to the SSL context during tls context creation.
 *
 * @return the CertStatusExData
 */
CertStatusExData *SSLContext::getCertStatusExData() const { return CertStatusExData::fromSSL_CTX(ctx.get()); }

/**
 * @brief Get the entity certificate from the custom data in the SSL context
 *
 * This function retrieves the entity certificate from the custom data in the SSL context.
 * During tls context creation the entity certificate is added to the custom data if TLS is configured
 *
 * @return the entity certificate
 */
const X509 *SSLContext::getEntityCertificate() const {
    if (!ctx) throw std::invalid_argument("NULL");

    auto car = static_cast<CertStatusExData *>(SSL_CTX_get_ex_data(ctx.get(), ossl_gbl->SSL_CTX_ex_idx));
    return car->cert.get();
}

/**
 * @brief Get the peer credentials from the SSL context
 *
 * This function retrieves the peer credentials from the SSL context and fills the PeerCredentials structure.
 * It also attempts to use the root CA name to qualify the authority.
 *
 * @param C the PeerCredentials to fill
 * @param ctx the SSL context to get the peer credentials from
 * @return true if the peer credentials were successfully retrieved, false otherwise
 */
bool SSLContext::getPeerCredentials(PeerCredentials &C, const SSL *ctx) {
    if (!ctx) throw std::invalid_argument("NULL");

    if (auto cert = SSL_get0_peer_certificate(ctx)) {
        PeerCredentials temp(C);  // copy current as initial (don't overwrite isTLS)
        auto subj = X509_get_subject_name(cert);
        char name[64];
        if (subj && X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name) - 1)) {
            name[sizeof(name) - 1] = '\0';
            log_debug_printf(io, "Peer CN=%s\n", name);
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
                        log_warn_printf(io, "Last cert in peer chain is not root CA?!? %s\n", std::string(SB() << ossl::ShowX509{root}).c_str());
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

/**
 * @brief Subscribe to the peer certificate status
 *
 * This function subscribes to the peer certificate status and calls the given function when the status changes.
 *
 * @param ctx the SSL context to get the peer certificate from
 * @param fn the function to call when the certificate status changes
 * @return true if the peer certificate status was successfully subscribed, false otherwise
 */
bool SSLContext::subscribeToPeerCertStatus(const SSL *ctx, std::function<void(bool)> fn) {
    if (!ctx) throw std::invalid_argument("NULL");

    if (auto cert = SSL_get0_peer_certificate(ctx)) {
        // Subscribe to peer certificate status if necessary
        auto ex_data = CertStatusExData::fromSSL(const_cast<SSL *>(ctx));
        if (ex_data) {
            ex_data->subscribeToPeerCertStatus(cert, [=](bool is_good) { fn(is_good); });
        }
        return true;
    } else {
        return false;
    }
}

std::shared_ptr<SSLContext> SSLContext::for_client(const impl::ConfigCommon &conf, const impl::evbase& loop) {
    auto ctx(commonSetup(TLS_client_method(), true, conf, loop));

    if (0 != SSL_CTX_set_alpn_protos(ctx->ctx.get(), pva_alpn, sizeof(pva_alpn) - 1))
        throw SSLError("Unable to agree on Application Layer Protocol to use: Both sides should use pva/1");

    return ctx;
}

std::shared_ptr<SSLContext>  SSLContext::for_server(const impl::ConfigCommon &conf, const impl::evbase& loop) {
    auto ctx(commonSetup(TLS_server_method(), false, conf, loop));

    SSL_CTX_set_alpn_select_cb(ctx->ctx.get(), &ossl_alpn_select, nullptr);

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
            (void)BIO_printf(io.get(), " from: ");
            ASN1_TIME_print(io.get(), atm);
        }
        if (auto atm = X509_get0_notAfter(cert.cert)) {
            (void)BIO_printf(io.get(), " until: ");
            ASN1_TIME_print(io.get(), atm);
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
