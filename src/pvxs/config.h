/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CONFIG_H
#define PVXS_CONFIG_H

#ifdef __linux__
#include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
#endif

#include <iterator>
#include <map>

#include <regex>
#include <string>

#include <pvxs/version.h>

namespace pvxs {
namespace impl {

/**
 * @brief Common configuration for the client and server
 */
struct PVXS_API ConfigCommon {
    /**
     * @brief Destructor for the ConfigCommon class
     */
    virtual ~ConfigCommon() = 0;

    //! TCP port to bind.  Default is 5075.  May be zero.
    unsigned short tcp_port = 5075;
    //! UDP port to bind.  Default is 5076.  May be zero, cf. Server::config()
    //! to find allocated port.
    unsigned short udp_port = 5076;

    //! Inactivity timeout interval for TCP connections.  (seconds)
    //! @since 0.2.0
    double tcpTimeout = 40.0;

#ifdef PVXS_ENABLE_OPENSSL
    //! TCP port to bind for TLS traffic.  Default is 5076
    //! @since UNRELEASED
    unsigned short tls_port = 5076;

    /**
     * @brief Set to true to disable TLS.  This will override the environment TLS configuration
     * settings and will also override config TLS configuration fields.  Suitable for testing.
     * server
     */
    bool tls_disabled = false;

    /** Path to keychain file containing certificates and private key.
     *  @since UNRELEASED
     */
    std::string tls_keychain_file;

    /** Path to file containing password for keychain file.
     *  @since UNRELEASED
     */
    std::string tls_keychain_pwd;

    /** Client certificate request during TLS handshake.
     *
     *  - Default.   Currently equivalent to Optional
     *  - Optional.  Server will ask for a client cert.  But will continue if none is provided.
     *               If a client cert. is provided, then it is validated.  An invalid cert.
     *               will fail the handshake.
     *  - Require.   Server will require a valid client cert. or the TLS handshake will fail.
     *
     *  @since UNRELEASED
     */
    enum CertificateRequiredness {
        Default,
        Optional,
        Require,
    } tls_client_cert_required = Default;

    /**
     * @brief Behaviour of server and client if the certificate expires
     * during the long-running session.
     *  - FallbackToTCP.  Only for clients, this will reinitialise the
     * connection but in server-only authentication mode.
     *  - Shutdown.       This will stop the process immediately
     *  - Standby.        For servers, this will keep the server running but will reject all connections until the certificate has been renewed.
     */
    enum OnExpirationBehaviour {
        FallbackToTCP,
        Shutdown,
        Standby,
    } expiration_behaviour = FallbackToTCP;

    /**
     * @brief True if status checking from the PVACMS is disabled irrespective of whether configured in the certificate
     */
    bool tls_disable_status_check{false};

    /**
     * @brief True if stapling is disabled irrespective of whether TLS is configured
     */
    bool tls_disable_stapling{false};

    /**
     * @brief True if we want to throw an exception if we can't verify a cert with the
     * PVACMS, otherwise we downgrade to a tcp connection
     */
    bool tls_throw_if_cant_verify{false};

    /**
     * @brief The request timeout specified in a user call
     * @note Cannot be set by an environment variable, but is passed in by commandline tools, or set programmatically
     */
    double request_timeout_specified{5.0};


    /**
     * @brief the prefix to append to the URI for CREATE, STATUS, ROOT, etc
     * default "CERT"
     */
    std::string cert_pv_prefix{"CERT"};

    /**
     * True if the environment is configured for TLS.  All this means is that
     * the location of the keychain file has been specified in
     * EPICS_PVA_TLS_KEYCHAIN.
     *
     * @return true if the location of the keychain file has been specified,
     * false otherwise
     */
    bool isTlsConfigured() const { return !tls_disabled && !tls_keychain_file.empty(); }
#endif  // PVXS_ENABLE_OPENSSL
};
}  // namespace impl
}  // namespace pvxs

#endif  // PVXS_CONFIG_H
