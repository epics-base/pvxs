/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
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
#include "opensslgbl.h"
#include "serverconn.h"
#include "utilpvt.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

DEFINE_LOGGER(setup, "pvxs.ossl.init");
DEFINE_LOGGER(stapling, "pvxs.stapling");
DEFINE_LOGGER(watcher, "pvxs.certs.mon");
DEFINE_LOGGER(io, "pvxs.ossl.io");
DEFINE_LOGGER(status_cli, "pvxs.st.cli");
DEFINE_LOGGER(status_svr, "pvxs.st.svr");

namespace pvxs {
namespace ossl {

int ossl_verify(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    const X509 *cert_ptr = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (!preverify_ok) {
        const auto err = X509_STORE_CTX_get_error(x509_ctx);
        log_err_printf(io, "Unable to verify peer cert: %s : %s\n", X509_verify_cert_error_string(err), std::string(SB() << ShowX509{cert_ptr}).c_str());
    }
    log_printf(io, preverify_ok ? Level::Debug : Level::Err, "TLS verify %s\n", preverify_ok ? "Ok" : "Reject");
    return preverify_ok;
}

/**
 * @brief Check cert status and set the TLS context state to TCP_READY or TLS_READY
 *
 * Monitor all certs that need monitoring and then set the TCP/TLS status appropriately
 *
 * @param cert
 * @param trusted_store_ptr the trusted store that we'll use to verify the peer OCSP status responses
 */
void SSLContext::monitorStatusAndSetState(const ossl_ptr<X509> &cert, X509_STORE *trusted_store_ptr) {
    bool no_status_extension{false};
    if (!status_check_disabled) {
        try {
            const auto status_pv = certs::CertStatusManager::getStatusPvFromCert(cert.get());
            log_debug_printf(watcher, "Installing Certificate Status Monitor: %s\n", status_pv.c_str());
            cert_monitor = certs::CertStatusManager::subscribe(getCertStatusExData()->client, trusted_store_ptr, status_pv, [=](const certs::PVACertificateStatus &pva_status) {
                const auto cert_status_category = static_cast<certs::CertificateStatus>(pva_status).getStatusCategory();
                log_debug_printf(watcher, "Received: %s certificate status\n", pva_status.status.s.c_str());
                if (cert_status_category != certs::GOOD_STATUS) {
                    log_warn_printf(watcher, "Certificate not valid: %s\n", pva_status.status.s.c_str());
                }

                {
                    {
                        Guard G(lock);
                        cert_status = pva_status;

                        // Cancel any existing status validity timer
                        if (event_pending(status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
                            event_del(status_validity_timer.get());
                        }
                    }

                    // If it's a BAD status, then set state and exit
                    if (cert_status_category == certs::BAD_STATUS) {
                        setTlsOrTcpMode(cert_status_category);
                        return;
                    }

                    // Start a new timer based on the status validity period
                    const time_t now = time(nullptr);
                    const time_t valid_until = pva_status.status_valid_until_date.t;
                    const time_t valid_from = pva_status.status_date.t;

                    if (valid_until > now && valid_from <= now) {
                        timeval delay;
                        delay.tv_sec = valid_until - now;
                        delay.tv_usec = 0;
                        event_add(status_validity_timer.get(), &delay);
                    } else {
                        log_debug_printf(watcher, "Certificate status is no longer valid: %s\n", pva_status.status.s.c_str());
                        setTlsOrTcpMode(certs::UNKNOWN_STATUS);
                        return;
                    }
                }

                // set TLS context state appropriately based on the new status
                setTlsOrTcpMode();
            });
            log_debug_printf(watcher, "Installed Certificate Status Monitor: %s\n", status_pv.c_str());
        } catch (certs::CertStatusNoExtensionException &e) {
            no_status_extension = true;
            log_debug_printf(watcher, "No certificate status extension found in certificate: %s\n", e.what());
        }
    } else {
        log_debug_printf(watcher, "Status check is disabled%s", "\n");
    }

    // Set the state
    const auto cert_status_category = static_cast<certs::CertificateStatus>(cert_status).getEffectiveStatusCategory();
    if ( cert_status_category == certs::BAD_STATUS ) {
        // Should never happen
        setDegradedMode(true);
        log_debug_printf(watcher, "Setting initial TLS connection state to: %s\n", "DegradedMode");
    } else { // GOOD and UNKNOWN
        Guard G(lock);
        state = (status_check_disabled || no_status_extension || cert_status.isGood()) ? TlsReady : TcpReady;
        log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", state == TlsReady ? "TlsReady" : "TcpReady", "SSLContext::monitorStatusAndSetState()", this);
    }
}

/**
 * @brief Called back when the entity certificate status becomes invalid
 * @param fd
 * @param evt
 * @param raw
 */
void SSLContext::statusValidityTimerCallback(evutil_socket_t fd, short evt, void* raw) {
    auto* ctx = static_cast<SSLContext*>(raw);
    log_debug_printf(watcher, "Certificate status validity expired - marking status as %s\n", "UNKNOWN");

    // Set certificate state to UNKNOWN
    ctx->setTlsOrTcpMode();
}

/**
 * @brief Set degraded mode
 *
 * Clear all monitors and statuses, then set tls context state to Degraded
 */
void SSLContext::setDegradedMode(const bool clear) {
    log_debug_printf(watcher, "Permanently switching TLS state to Degraded%s\n", "");
    Guard G(lock);
    if (clear) {
        cert_monitor.reset();   // Unsubscribe from the certificate status monitor if any
        cert_status = {};    // Set the certificate status to be UNKNOWN
    }
    state = DegradedMode;
    log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-11s : SSLContext::setDegradedMode()\n", "SSLContext::state", "DegradedMode");
}

/**
 * @brief Transition TLS mode based on the given certificate status
 *
 * Will never be called if cert is EXPIRED of REVOKED so we can set to TcpReady if NOT GOOD because it may become GOOD again later
 *
 * @param cert_status_category the given certificate status category
 */
void SSLContext::setTlsOrTcpMode(const certs::cert_status_category_t cert_status_category) {
    log_debug_printf(watcher, "Received a %s certificate status from the status monitor\n", cert_status.status.s.c_str());
    if (state == DegradedMode) {
        log_warn_printf(watcher, "Logic Error. Should not be monitoring certificate status: Because the context state is %s\n", "DegradedMode");
        return;
    }

    switch (cert_status_category) {
        case certs::GOOD_STATUS:
            switch (state) {
                case Init:
                case TcpReady:
                    log_debug_printf(watcher, "Setting TLS Ready State%s\n", "");
                    {
                        Guard G(lock);
                        state = TlsReady;
                        log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "TlsReady", "SSLContext::setTlsOrTcpMode()", this);
                    }
                    break;
                case TlsReady:
                default:
                    log_debug_printf(watcher, "Skipping setting TLS Ready State: Because the state is already%s\n", "TlsReady");
                    break;
            }
            break;
        case certs::BAD_STATUS:
            setDegradedMode();
            break;
        case certs::UNKNOWN_STATUS:
        default:
            switch (state) {
                case Init:
                    log_debug_printf(watcher, "Keeping Init state until a VALID status is received%s\n", "");
                    break;
                case TlsReady:
                    log_debug_printf(watcher, "Switching TLS state to TcpReady until a new VALID status is received%s\n", "");
                    {
                        Guard G(lock);
                        state = TcpReady;
                        log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "TcpReady", "SSLContext::setTlsOrTcpMode()", this);
                    }
                case TcpReady:
                default:
                    log_debug_printf(watcher, "Skipping setting TCP Ready State: Because the state is already%s\n", "TcpReady");
                    break;
            }
            break;
    }
}

/**
 * @brief Transition TLS mode when entity certificate status changes
 */
void SSLContext::setTlsOrTcpMode() {
    const auto status = static_cast<certs::CertificateStatus>(cert_status);
    setTlsOrTcpMode(status.getEffectiveStatusCategory());
}

SSLContext::SSLContext(const impl::evbase loop, const bool is_client) : loop(loop), is_client(is_client)
    , status_validity_timer(event_new(loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))
{}

SSLContext::SSLContext(const SSLContext &o)
    : loop(o.loop)
    , ctx(o.ctx)
    , is_client(o.is_client)
    , state(o.state)
    , status_check_disabled(o.status_check_disabled)
    , stapling_disabled(o.stapling_disabled)
    , cert_monitor(o.cert_monitor)  // Copy the monitor
    , cert_status(o.cert_status)    // Copy the status
    , status_validity_timer(event_new(loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create a new timer for this instance
{
    // If the original timer was pending, restart ours with the remaining time
    if (o.status_validity_timer.get() && event_pending(o.status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
        restartStatusValidityTimerFromCertStatus();
    }
}

SSLContext::SSLContext(SSLContext &o) noexcept
    : loop(o.loop)
    , ctx(std::move(o.ctx))
    , is_client(o.is_client)
    , state(o.state)
    , status_check_disabled(o.status_check_disabled)
    , stapling_disabled(o.stapling_disabled)
    , cert_monitor(std::move(o.cert_monitor))  // Move the monitor
    , cert_status(std::move(o.cert_status))    // Move the status
    , status_validity_timer(event_new(loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create new timer
{
    // If the original timer was pending, restart ours and cancel the original
    if (o.status_validity_timer.get() && event_pending(o.status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
        restartStatusValidityTimerFromCertStatus();
        // Cancel the timer in the source object since we're moving
        event_del(o.status_validity_timer.get());
    }

}

void SSLContext::restartStatusValidityTimerFromCertStatus() const {
    if (!status_validity_timer.get()) {
        return; // Timer is not initialized
    }

    // Calculate the remaining time from the status validity date
    if (cert_status.status_valid_until_date.t > 0) {
        const time_t now = time(nullptr);
        if (cert_status.status_valid_until_date.t > now) {
            timeval delay{};
            delay.tv_sec = cert_status.status_valid_until_date.t - now;
            delay.tv_usec = 0;
            event_add(status_validity_timer.get(), &delay);
        }
    }
}

SSLContext::~SSLContext() {
    if (status_validity_timer.get()) {
        event_del(status_validity_timer.get());
    }
}

CertStatusExData::~CertStatusExData() noexcept = default;

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
void sslkeylogfile_log(const SSL *, const char *line) noexcept {
    if (!ossl_gbl) return;
    auto gbl = ossl_gbl;
    try {
        epicsGuard<epicsMutex> G(gbl->keylock);
        if(gbl->keylog) {
            size_t n = strlen(line);
            FLock lk(gbl->keylog.get(), true);
            int pos = fseek(gbl->keylog.get(), 0, SEEK_END);
            if(pos==-1)
                throw std::runtime_error("seek");
            auto ret = fwrite(line, 1, n, gbl->keylog.get());
            if(ret>=0)
                ret = fputc('\n', gbl->keylog.get());
            if(ret>=0)
                ret = fflush(gbl->keylog.get());
            else
                ret = -1;
            if(ret) {
                throw std::runtime_error("I/O");
            }
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


namespace {

constexpr int ossl_verify_depth = 5;

// see NOTE in "man SSL_CTX_set_alpn_protos"
const unsigned char pva_alpn[] = "\x05pva/1";

int ossl_alpn_select(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *) {
    unsigned char *selected;
    const auto ret(SSL_select_next_proto(&selected, outlen, pva_alpn, sizeof(pva_alpn) - 1u, in, inlen));
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
    const auto flags(X509_get_extension_flags(cert.get()));
    const auto kusage(X509_get_extended_key_usage(cert.get()));

    if (flags & EXFLAG_CA) throw std::runtime_error(SB() << "Found certificate authority certificate when End Entity expected");

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
 * We _assume_ that any root certificate authority included in a keychain file is meant to
 * be trusted.  Otherwise, such a cert. could never appear in a valid
 * chain.
 *
 * @param ctx the context to add the CAs to
 * @param CAs the stack of X509 Certificate Authority certificates
 */
ossl_ptr<X509> extractCAs(std::shared_ptr<SSLContext> ctx, const ossl_shared_ptr<STACK_OF(X509)> &CAs) {
    ossl_ptr<X509> trusted_root_ca{};
    for (int i = 0, N = sk_X509_num(CAs.get()); i < N; i++) {
        const auto cert_auth = sk_X509_value(CAs.get(), i);

        const auto canSign(X509_check_ca(cert_auth));
        const auto flags(X509_get_extension_flags(cert_auth));

        // Check for non-Certificate Authority certificates
        if (canSign == 0 && i != 0) {
            log_err_printf(setup, "non-certificate-authority certificate in keychain%s\n", "");
            log_err_printf(setup, "%s\n", (SB() << ShowX509{cert_auth}).str().c_str());
            throw std::runtime_error(SB() << "non-certificate-authority certificate found in keychain");
        }

        if (flags & EXFLAG_SS) {  // self-signed (aka. root)
            trusted_root_ca = ossl_ptr<X509>(X509_dup(cert_auth));
            assert(flags & EXFLAG_SI);  // circa OpenSSL, self-signed implies self-issued

            // populate the context's trust store with the self-signed root cert
            X509_STORE *trusted_store = SSL_CTX_get_cert_store(ctx->ctx.get());
            if (!X509_STORE_add_cert(trusted_store, cert_auth)) throw SSLError("X509_STORE_add_cert");
        } else {
            // signed by another certificate authority
            // note: chain certs added this way are ignored unless SSL_BUILD_CHAIN_FLAG_UNTRUSTED is used
            // appends SSL_CTX::cert::chain
        }
        if (!SSL_CTX_add0_chain_cert(ctx->ctx.get(), cert_auth)) throw SSLError("SSL_CTX_add0_chain_cert");
    }
    return trusted_root_ca;
}

/**
 * @brief Common setup for OpenSSL SSL context
 *
 * This function sets up the OpenSSL SSL context used for SSL/TLS communication.
 * It configures the SSL method, whether it is for a client or a server, and the
 * common configuration options.
 *
 * @param method The SSL_METHOD object representing the SSL method to use.
 * @param is_for_client A boolean indicating whether the setup is for a client or a server.
 * @param conf The common configuration object.
 * @param client the inner client to use to create any status subscriptions
 * @param loop The event loop used to schedule custom events
 *
 * @return SSLContext initialised appropriately - clients can have an empty
 * context so that they can connect to ssl servers without having a certificate
 */
std::shared_ptr<SSLContext> commonSetup(const SSL_METHOD *method, const bool is_for_client, const ConfigCommon &conf, const client::Context &client, const evbase &loop) {
    osslInit();

    auto tls_context = std::make_shared<SSLContext>(SSLContext(loop, is_for_client));
    log_debug_printf(tls_context->is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "Init", "commonSetup()", tls_context.get());
    assert(tls_context && "TLS context is null");

    tls_context->status_check_disabled = conf.tls_disable_status_check;
    tls_context->stapling_disabled = conf.tls_disable_stapling;
    tls_context->ctx = ossl_shared_ptr<SSL_CTX>(SSL_CTX_new_ex(ossl_gbl->libctx.get(), nullptr, method));
    if (!tls_context->ctx) throw SSLError("Unable to allocate SSL_CTX");

    {
        // Add the CertStatusExData to the SSL context so that it will be available
        // any time the SSL context is available to provide access to the entity certificate,
        // peer statuses and other custom data.
        std::unique_ptr<CertStatusExData> car{new CertStatusExData(loop, !tls_context->status_check_disabled, client)};
        if (!SSL_CTX_set_ex_data(tls_context->ctx.get(), ossl_gbl->SSL_CTX_ex_idx, car.get())) throw SSLError("SSL_CTX_set_ex_data");
        car.release();  // SSL_CTX_free() now responsible (using our registered callback `free_SSL_CTX_sidecar`)
    }

    // Read back a pointer to cert ext data
    const auto cert_status_ex_data = tls_context->getCertStatusExData();
    if (!cert_status_ex_data) {
        throw std::runtime_error("Unable to attach extended certificate data to tls context");
    }

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    // Set the keylog callback to log the TLS secrets to the file
    (void)SSL_CTX_set_keylog_callback(tls_context->ctx.get(), &sslkeylogfile_log);
#endif

    // Set minimum and maximum protocol versions.  Version 1.3 is the minimum
    (void)SSL_CTX_set_min_proto_version(tls_context->ctx.get(), TLS1_3_VERSION);
    (void)SSL_CTX_set_max_proto_version(tls_context->ctx.get(), 0);

    // If TLS is disabled or not configured, then set the context to Degraded mode so that
    // only TCP connections will be accepted.
    if (conf.tls_disabled || !conf.isTlsConfigured()) {
        tls_context->state = SSLContext::DegradedMode;
        log_debug_printf(tls_context->is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "DegradedMode", "commonSetup()", tls_context.get());
        return tls_context;
    }

    // Get the key and certificate from the file or files
    log_debug_printf(setup, "Getting private key and certificate from configured keychain file: %s\n", conf.tls_keychain_file.c_str());
    const std::string &filename = conf.tls_keychain_file, &password = conf.tls_keychain_pwd;
    auto cert_data = certs::IdFileFactory::createReader(filename, password)->getCertDataFromFile();

    log_debug_printf(setup, "Getting trusted root from certificate chain. %s\n", "");
    const ossl_ptr<X509> trusted_root_ca(extractCAs(tls_context, cert_data.cert_auth_chain));
    if (!trusted_root_ca) throw SSLError("Could not find Trusted Root Certificate Authority Certificate in keychain");

    // Get the context's trust store that has been established by reading the CAs from the file
    X509_STORE *store_ptr = SSL_CTX_get_cert_store(tls_context->ctx.get());
    if (!store_ptr) {
        throw std::invalid_argument("Trusted store pointer is null.");
    }
    cert_status_ex_data->trusted_store_ptr = store_ptr;

    // If no cert
    if (!cert_data.cert) {
        // But this is a client then try a server-only tls connection
        if (is_for_client) {
            log_debug_printf(setup, "No certificate found in keychain file.  Setting up server-only TLS context%s\n", "");
            tls_context->state = SSLContext::TlsReady;
            log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "TlsReady", "commonSetup()", tls_context.get());
            log_info_printf(setup, "TLS server-only mode selected%s", "\n");
            return tls_context;
        }
        log_debug_printf(setup, "No certificate found in keychain file but %s\n", "");
        // otherwise we can't continue to create a TLS connection
        throw std::runtime_error("No Certificate");
    }

    // Verify the key usage of the certificate
    verifyKeyUsage(cert_data.cert, is_for_client);

    // Use the certificate in the context
    if (!SSL_CTX_use_certificate(tls_context->ctx.get(), cert_data.cert.get())) throw SSLError("using certificate");

    // Check the private key
    assert(cert_data.key_pair);
    if (!SSL_CTX_use_PrivateKey(tls_context->ctx.get(), cert_data.key_pair->pkey.get())) throw SSLError("using private key");
    if (!cert_data.key_pair->pkey || !SSL_CTX_check_private_key(tls_context->ctx.get())) throw SSLError("invalid private key");

    // Build the certificate chain and set verification flags
    // Note useful flags are:
    //  SSL_BUILD_CHAIN_FLAG_CHECK - Fully check certificate authority's certificate chain and fail if any are not trusted
    //  SSL_BUILD_CHAIN_FLAG_UNTRUSTED - Flag untrusted in build chain but still use it
    //  0 - run default checks
    if (!SSL_CTX_build_cert_chain(tls_context->ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK)) throw SSLError("invalid cert chain");

    // Move entity certificate to the custom data in the SSL context
    cert_status_ex_data->cert = std::move(cert_data.cert);

    // TLS is now configured:
    //  - Entity certificate valid,
    //  - certificate authority certificate valid,
    //  - certificate authority's certificate chain valid,
    //  - Private key valid
    // Start monitoring entity certificate status and set TLS context state accordingly
    tls_context->monitorStatusAndSetState(cert_status_ex_data->cert, store_ptr);

    // Configure what and how to verify certificates in the TLS handshake
    // Note useful mode flags are:
    //  - SSL_VERIFY_PEER - Verify peer certificate
    //  - SSL_VERIFY_CLIENT_ONCE - Verify client certificate once
    //  - SSL_VERIFY_FAIL_IF_NO_PEER_CERT - Fail if no peer certificate present (only for servers)
    {
        int mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
        if (!is_for_client && conf.tls_client_cert_required == ConfigCommon::Require) {
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
 * @param raw the pointer to cast to a Server::Pvt object to get the OCSP response from
 * @return SSL_TLSEXT_ERR_OK if the OCSP response was added successfully,
 *         SSL_TLSEXT_ERR_ALERT_WARNING if the callback should not have been called, (never happens)
 *         SSL_TLSEXT_ERR_NOACK if the OCSP response was not added - no status available to staple at this time
 *         SSL_TLSEXT_ERR_ALERT_FATAL if the OCSP response was not added - some error occurred adding the OCSP response
 */
int serverOCSPCallback(SSL *ssl, void *raw) {
    auto ret_val = SSL_TLSEXT_ERR_OK;
    const auto server = static_cast<server::Server::Pvt *>(raw);
    log_debug_printf(stapling, "Server OCSP Stapling: %s\n", "serverOCSPCallback");

    if (const auto &tls_context = server->tls_context) {
        auto &current_status = tls_context->get_cert_status();
        if (current_status.isValid()) {
            uint8_t *ocsp_data_ptr_copy = nullptr;
            const auto ocsp_data_ptr = (void *)current_status.ocsp_bytes.data();
            const auto ocsp_data_len = current_status.ocsp_bytes.size();

             // OpenSSL API takes an int length. Check for overflow.
            if (ocsp_data_len > INT_MAX) {
                log_warn_printf(stapling, "OCSP response too large to staple (%zu)\n", ocsp_data_len);
                ret_val = SSL_TLSEXT_ERR_NOACK;
            } else {
                // Allocate a new one and copy in the response data
                ocsp_data_ptr_copy = static_cast<uint8_t *>(OPENSSL_malloc(ocsp_data_len));
                if (!ocsp_data_ptr_copy) {
                    log_warn_printf(stapling, "Unable to allocate memory for OCSP response%s\n", "");
                    ret_val = SSL_TLSEXT_ERR_NOACK;
                } else {
                    memcpy(ocsp_data_ptr_copy, ocsp_data_ptr, ocsp_data_len);

                    // On success, OpenSSL takes ownership and will OPENSSL_free() it later.
                    if (SSL_set_tlsext_status_ocsp_resp(ssl, ocsp_data_ptr_copy, ocsp_data_len) != 1) {
                        // On failure, we must free it.
                        OPENSSL_free(ocsp_data_ptr_copy);

                        log_warn_printf(stapling, "Server OCSP Stapling: %s\n", "unable to staple server status");
                        ret_val = SSL_TLSEXT_ERR_NOACK;
                    } else {
                        log_info_printf(stapling, "Server OCSP Stapling: %s\n", "server status stapled");
                    }
                }
            }
        } else {
            log_info_printf(stapling, "Server OCSP Stapling: %s\n", "Server status not valid.  Not stapling");
            ret_val = SSL_TLSEXT_ERR_NOACK;
        }
    } else {
        log_warn_printf(stapling, "Server OCSP Stapling: %s\n", "No server status to staple");
        ret_val = SSL_TLSEXT_ERR_NOACK;
    }

    return ret_val;
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
    auto server = static_cast<server::Server::Pvt *>(server_ptr);
    SSL_CTX_set_tlsext_status_arg(server->tls_context->ctx.get(), server);
    SSL_CTX_set_tlsext_status_cb(server->tls_context->ctx.get(), serverOCSPCallback);
}

/**
 * @brief Called when last  peer connection is being destroyed to remove the
 * peer status and monitor from the tls context's list of statuses and monitors
 */
SSLPeerStatusAndMonitor::~SSLPeerStatusAndMonitor() {
    if (status_validity_timer) {
        Guard G(lock);
        event_del(status_validity_timer.get());
    }
    {
        Guard G(lock);
        // Remove self from the global list of peer statuses
        ex_data_ptr->removePeerStatusAndMonitor(serial_number);
    }
    subscribed = false;
}

/**
 * @brief Callback triggered when the certificate status validity timer expires
 *
 * This function is invoked when the certificate status validity timer expires, indicating
 * that the certificate status has become invalid. It notifies any registered listeners about
 * this change in status.
 *
 * @param fd The file descriptor associated with the event (not used in this function)
 * @param evt The event type that triggered the callback
 * @param raw Pointer to the SSLPeerStatusAndMonitor instance managing the certificate status
 */
void SSLPeerStatusAndMonitor::statusValidityTimerCallback(evutil_socket_t fd, short evt, void* raw) {
    const auto* peer_status_and_monitor = static_cast<SSLPeerStatusAndMonitor*>(raw);
    log_debug_printf(watcher, "Certificate status validity expired - notifying listeners%s\n", "");

    // Set notify listeners that status has changed
    if (peer_status_and_monitor->fn) peer_status_and_monitor->fn(certs::UNKNOWN_STATUS);
}

/**
 * @brief Restart the status validity timer based on the validity of the certificate.
 *
 * This method handles restarting a timer that monitors the validity of a peer certificate status.
 * It ensures that any existing timers are canceled and calculates the remaining status validity
 * duration to set up a new timer accordingly.
 *
 * If the certificate is marked as non-permanent and has a status valid expiration date
 * greater than the current time, then the timer is scheduled to trigger after the remaining
 * status validity period. Logs are generated for debugging purposes to indicate the countdown.
 */
void SSLPeerStatusAndMonitor::restartStatusValidityTimerFromCertStatus() {
    if (!status_validity_timer.get()) return; // Timer is not initialized

    // Cancel any existing status validity timer
    if (event_pending(status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
        Guard G(lock);
        event_del(status_validity_timer.get());
    }

    // Calculate the remaining time from the status validity date
    if (!status.isPermanent() && status.status_valid_until_date.t > 0) {
        const time_t now = time(nullptr);
        if (status.status_valid_until_date.t > now) {
            const auto status_validity_seconds_remaining = status.status_valid_until_date.t - now;
            log_debug_printf(watcher, "Counting down Peer Certificate validity: %ld seconds\n", status_validity_seconds_remaining);
            const timeval delay{status_validity_seconds_remaining};
            event_add(status_validity_timer.get(), &delay);
        }
    }
}

/**
 * @brief Sets the peer status for the given peer certificate
 * @param peer_cert_ptr - Peer certificate pointer
 * @param new_status - Certificate status
 * @param fn function to be configured to be called for updates
 * @return The peer status that was set
 */
std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::setPeerStatus(X509 *peer_cert_ptr,
    const certs::CertificateStatus &new_status, const std::function<void(certs::cert_status_category_t)> &fn) {
    const auto serial_number = getSerialNumber(peer_cert_ptr);
    std::shared_ptr<SSLPeerStatusAndMonitor> peer_status_and_monitor;
    if (status_check_enabled && fn) {
        const auto status_pv = certs::CertStatusManager::getStatusPvFromCert(peer_cert_ptr);
        peer_status_and_monitor = getOrCreatePeerStatus(serial_number, status_pv, fn);
    } else {
        peer_status_and_monitor = getOrCreatePeerStatus(serial_number);
    }

    peer_status_and_monitor->updateStatus(new_status);
    return peer_status_and_monitor;
}

std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::getOrCreatePeerStatus(const serial_number_t serial_number, const std::string &status_pv, const std::function<void(certs::cert_status_category_t)> &fn) {
    // Create a holder for peer status or return current holder if already exists
    auto peer_status = createPeerStatus(serial_number, fn);

    // Subscribe if we have a pv and a function and we're not yet subscribed
    if (!status_pv.empty() && fn && status_check_enabled && !peer_status->isSubscribed()) {
        // Subscribe to certificate status updates
        std::weak_ptr<SSLPeerStatusAndMonitor> weak_peer_status = peer_status;
        {
            Guard G(peer_status->lock);
            peer_status->subscribed = true;
        }
        peer_status->cert_status_manager =
            certs::CertStatusManager::subscribe(client, trusted_store_ptr, status_pv, [weak_peer_status](const certs::PVACertificateStatus &status) {
                log_debug_printf(watcher, "Received: %s PEER certificate status\n", status.status.s.c_str());
                const auto peer_status_update = weak_peer_status.lock();
                if (!status.isGood())
                    log_warn_printf(watcher, "Peer certificate not VALID: %s\n", status.status.s.c_str());
                // Update the cached state
                if (peer_status_update) peer_status_update->updateStatus(static_cast<const certs::CertificateStatus>(status));
            });
    }
    return peer_status;
}

/**
 * @brief Create a peer status in the list of statuses or return an existing one
 * @param serial_number the serial number to index into the list
 * @param fn optional function that will be called as status changes if provided
 * @return the existing or new peer status
 */
std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::createPeerStatus(serial_number_t serial_number, const std::function<void(certs::cert_status_category_t)> &fn) {
    const auto existing_peer_status_entry = peer_statuses.find(serial_number);
    if (existing_peer_status_entry != peer_statuses.end()) {
        auto peer_status (existing_peer_status_entry->second.lock());
        if (peer_status) {
            return peer_status;
        }
        peer_statuses.erase(serial_number);
    }

    std::shared_ptr<SSLPeerStatusAndMonitor> new_peer_status;
    if (fn) new_peer_status = std::make_shared<SSLPeerStatusAndMonitor>(serial_number, this, fn);
    else new_peer_status = std::make_shared<SSLPeerStatusAndMonitor>(serial_number, this, nullptr);
    peer_statuses.emplace(serial_number, new_peer_status);
    return new_peer_status;
};

SSLPeerStatusAndMonitor::SSLPeerStatusAndMonitor(const serial_number_t serial_number, CertStatusExData* ex_data_ptr, const std::function<void(certs::cert_status_category_t)>& fn)
    : fn(fn), serial_number{serial_number}, ex_data_ptr{ex_data_ptr}
    , status_validity_timer(event_new(ex_data_ptr->loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create a new timer for this instance
    {}

SSLPeerStatusAndMonitor::SSLPeerStatusAndMonitor(const serial_number_t serial_number, CertStatusExData* ex_data_ptr, const certs::CertificateStatus& status)
    : serial_number{serial_number}, ex_data_ptr{ex_data_ptr}, status{status}
    , status_validity_timer(event_new(ex_data_ptr->loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create a new timer for this instance
    {}

/**
 * @brief Update the status with the given value and call the callback if supplied and restart the status validity timer
 * @param new_status the new status to set
 */
void SSLPeerStatusAndMonitor::updateStatus(const certs::CertificateStatus &new_status) {
    if (!new_status.isValid()) // Ignore invalid statuses
        return;

    const auto prior_cert_status = status.getStatusCategory();
    {
        // Update the status
        Guard G(lock);
        status = new_status;
    }

    // Call the callback if there has been any change in the status category
    const auto cert_status = status.getStatusCategory();
    if (fn && cert_status != prior_cert_status) fn(cert_status);

    // Restart status validity countdown timer for this new status
    restartStatusValidityTimerFromCertStatus();
}

std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::subscribeToPeerCertStatus(X509 *cert_ptr, const std::function<void(certs::cert_status_category_t)> &fn) {
    Guard G(lock);
    assert(cert_ptr && "Peer Cert NULL");
    return setPeerStatus(cert_ptr, fn);
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

    const auto car = static_cast<CertStatusExData *>(SSL_CTX_get_ex_data(ctx.get(), ossl_gbl->SSL_CTX_ex_idx));
    return car->cert.get();
}

bool SSLContext::hasExpired() const {
    if (!ctx) throw std::invalid_argument("NULL");
    const auto now = time(nullptr);
    const auto cert = getEntityCertificate();
    if (!cert) return false;
    const certs::CertDate expiry_date = X509_get_notAfter(cert);
    return expiry_date.t < now;
}

/**
 * @brief Get the peer credentials from the SSL context
 *
 * This function retrieves the peer credentials from the SSL context and fills the PeerCredentials structure.
 * It also attempts to use the root certificate authority name to qualify the authority.
 *
 * @param C the PeerCredentials to fill
 * @param ctx the SSL context to get the peer credentials from
 * @return true if the peer credentials were successfully retrieved, false otherwise
 */
bool SSLContext::getPeerCredentials(PeerCredentials &C, const SSL *ctx) {
    if (!ctx) throw std::invalid_argument("NULL");

    if (const auto cert = SSL_get0_peer_certificate(ctx)) {
        PeerCredentials temp(C);  // copy current as initial (don't overwrite isTLS)
        const auto subj = X509_get_subject_name(cert);
        char name[64];
        if (subj && X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name) - 1)) {
            name[sizeof(name) - 1] = '\0';
            log_debug_printf(io, "Peer CN=%s\n", name);
            temp.method = "x509";
            temp.account = name;

            // Get serial number
            const ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(cert);
            if (!serial_asn1) throw std::runtime_error("Failed to retrieve serial number from peer certificate");
            serial_number_t serial = 0;
            for (int i = 0; i < serial_asn1->length; ++i) serial = serial << 8 | serial_asn1->data[i];
            temp.serial = std::to_string(serial);

            // try to use certificate chain authority names to qualify
            if (const auto chain = SSL_get0_verified_chain(ctx)) {
                const auto N = sk_X509_num(chain);

                if (N > 0) {
                    std::string authority;
                    char common_name[256];

                    // Start from index 1 to skip the entity certificate (first in chain)
                    // But if there's only one certificate, we don't skip it
                    const int start_index = (N > 1) ? 1 : 0;

                    // Process certificates in the chain in reverse order, from root to issuer
                    for (int i = N - 1; i >= start_index; i--) {
                        const auto chain_cert = sk_X509_value(chain, i);
                        const X509_NAME *certName = X509_get_subject_name(chain_cert);

                        if (chain_cert && certName &&
                            X509_NAME_get_text_by_NID(certName, NID_commonName, common_name, sizeof(common_name) - 1)) {

                            // Add this name to the authority string
                            if (!authority.empty()) {
                                authority += '\n';
                            }
                            authority += common_name;

                            // If this is the issuer cert (first in the chain after entity), also set the issuer_id
                            if (i == start_index) {
                                temp.issuer_id = certs::CertStatus::getSkId(chain_cert);
                            }
                            if (i == N - 1 && !(X509_check_ca(chain_cert) || (X509_get_extension_flags(chain_cert) & EXFLAG_SS))) {
                                log_warn_printf(io, "Last cert in peer chain is not root Root certificate authority certificate? %s\n",
                                                std::string(SB() << ossl::ShowX509{chain_cert}).c_str());
                            }
                        }
                    }

                    // Only set the authority if we found at least one name
                    if (!authority.empty()) {
                        temp.authority = authority;
                    }
                }
            }
        }

        C = std::move(temp);
        return true;
    }
    return false;
}

/**
 * @brief Subscribe to the peer certificate status
 *
 * This function subscribes to the peer certificate status and calls the given function when the status changes.
 *
 * @param ssl the SSL context to get the peer certificate from
 * @param fn the function to call when the certificate status changes
 * @return true if the peer certificate status was successfully subscribed, false otherwise
 */
std::shared_ptr<SSLPeerStatusAndMonitor> SSLContext::subscribeToPeerCertStatus(const SSL *ssl, const std::function<void(certs::cert_status_category_t)> &fn) {
    if (!ssl) throw std::invalid_argument("NULL");

    if (const auto cert = SSL_get0_peer_certificate(ssl)) {
        // Subscribe to peer certificate status if necessary
        const auto ex_data = CertStatusExData::fromSSL(const_cast<SSL *>(ssl));
        if (ex_data) {
            return ex_data->subscribeToPeerCertStatus(cert, [=](const certs::cert_status_category_t status) { fn(status); });
        }
    }
    throw certs::CertStatusNoExtensionException("No Certificate");
}

std::shared_ptr<SSLContext> SSLContext::for_client(const ConfigCommon &conf, const client::Context &client, const evbase &loop) {
    auto ctx(commonSetup(TLS_client_method(), true, conf, client, loop));

    if (0 != SSL_CTX_set_alpn_protos(ctx->ctx.get(), pva_alpn, sizeof(pva_alpn) - 1))
        throw SSLError("Unable to agree on Application Layer Protocol to use: Both sides should use pva/1");

    return ctx;
}

std::shared_ptr<SSLContext> SSLContext::for_server(const ConfigCommon &conf, const client::Context &client, const evbase &loop) {
    auto ctx(commonSetup(TLS_server_method(), false, conf, client, loop));

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
          while (const auto err = ERR_get_error_all(&file, &line, nullptr, &data, &flags)) {
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
        const auto name = X509_get_subject_name(cert.cert);
        const auto issuer = X509_get_issuer_name(cert.cert);
        assert(name);
        const ossl_ptr<BIO> io(__FILE__, __LINE__, BIO_new(BIO_s_mem()));
        {
            try {
                const auto cert_id = certs::CertStatusManager::getCertIdFromCert(cert.cert);
                (void)BIO_printf(io.get(), "\nCertificate ID : ");
                (void)BIO_printf(io.get(), cert_id.c_str());
            } catch (...) {}
        }
        (void)BIO_printf(io.get(), "\nEntity Subject : ");
        (void)X509_NAME_print(io.get(), name, 1024);
        (void)BIO_printf(io.get(), "\nIssuer Subject : ");
        (void)X509_NAME_print(io.get(), issuer, 1024);
        if (const auto atm = X509_get0_notBefore(cert.cert)) {
            const certs::CertDate the_date(atm);
            (void)BIO_printf(io.get(), "\nValid From     : ");
            (void)BIO_printf(io.get(), the_date.s.c_str());
        }
        if (const auto atm = X509_get0_notAfter(cert.cert)) {
            const certs::CertDate the_date(atm);
            (void)BIO_printf(io.get(), "\nExpires On     : ");
            (void)BIO_printf(io.get(), the_date.s.c_str());
        }
        {
            char *str = nullptr;
            if (const auto len = BIO_get_mem_data(io.get(), &str)) {
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
