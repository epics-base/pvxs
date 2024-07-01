/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_SERVER_H
#define PVXS_SERVER_H

#include <array>
#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <epicsEndian.h>
#include <osiSock.h>

#include <pvxs/data.h>
#include <pvxs/netcommon.h>
#include <pvxs/util.h>
#include <pvxs/version.h>

namespace pvxs {
namespace client {
struct Config;
}
namespace server {

struct SharedPV;
struct Source;
struct Config;

/** PV Access protocol server instance
 *
 * Use a Config to determine how this server will bind, listen,
 * and announce itself.
 *
 * In order to be useful, a Server will have one or more Source instances added
 * to it with addSource().
 *
 * As a convenience, each Server instance automatically contains a "__builtin" StaticSource
 * to which SharedPV instances can be directly added.
 * The "__builtin" has priority zero, and can be accessed or even removed like any Source
 * explicitly added with addSource().
 *
 * There is also a "__server" source which provides the special "server" PV
 * used by the pvlist CLI.
 */
class PVXS_API Server
{
public:

    //! An empty/dummy Server
    constexpr Server() = default;
    //! Create/allocate, but do not start, a new server with the provided config.
    explicit Server(const Config&);
    Server(const Server&) = default;
    Server(Server&& o) = default;
    Server& operator=(const Server&) = default;
    Server& operator=(Server&& o) = default;
    ~Server();

    /** Create new server based on configuration from $EPICS_PVA* environment variables.
     *
     * Shorthand for @code Config::fromEnv().build() @endcode.
     * @since 0.2.1
     */
    static
    Server fromEnv(bool tls_disabled = false, impl::ConfigCommon::ConfigTarget target = impl::ConfigCommon::SERVER);
#ifdef PVXS_ENABLE_JWT_AUTH
    static
    Server fromEnvWithJwt(const std::string& token);
#endif

    //! Begin serving.  Does not block.
    Server& start();
    //! Stop server
    Server& stop();

    /** start() and then (maybe) stop()
     *
     * run() may be interrupted by calling interrupt(),
     * or by SIGINT or SIGTERM (only one Server per process)
     *
     * Intended to simple CLI programs.
     * Only one Server in a process may be in run() at any moment.
     * Other use case should call start()/stop()
     */
    Server& run();
    //! Queue a request to break run()
    Server& interrupt();

    /** Apply (in part) updated configuration
     *
     * Currently, only updates TLS configuration.  Causes all in-progress
     * Operations to be disconnected.
     *
     * @since UNRELEASED
     */
    void reconfigure(const Config&);

    //! effective config
    //! @since UNRELEASED Reference invalidated by a call to reconfigure()
    const Config& config() const;

    //! Create a client configuration which can communicate with this Server.
    //! Suitable for use in self-contained unit-tests.
    client::Config clientConfig() const;

    //! Add a SharedPV to the "__builtin" StaticSource
    Server& addPV(const std::string& name, const SharedPV& pv);
    //! Remove a SharedPV from the "__builtin" StaticSource
    Server& removePV(const std::string& name);

    //! Add a Source to this server with an arbitrary source name.
    //!
    //! Source names beginning with "__" are reserved for internal use.
    //! eg. "__builtin" and "__server".
    //!
    //! @param name Source name
    //! @param src The Source.  A strong reference to this Source which will be released by removeSource() or ~Server()
    //! @param order Determines the order in which this Source::onCreate() will be called.  Lowest first.
    //!
    //! @throws std::runtime_error If this (name, order) has already been added.
    Server& addSource(const std::string& name,
                      const std::shared_ptr<Source>& src,
                      int order =0);

    //! Disassociate a Source using the name and priority given to addSource()
    std::shared_ptr<Source> removeSource(const std::string& name,
                                         int order =0);

    //! Fetch a previously added Source.
    std::shared_ptr<Source> getSource(const std::string& name,
                                      int order =0);

    //! List all source names and priorities.
    std::vector<std::pair<std::string, int> > listSource();

#ifdef PVXS_EXPERT_API_ENABLED
    //! Compile report about peers and channels
    //! @param zero If true, zero counters after reading
    //! @since 0.2.0
    Report report(bool zero=true) const;
#endif

    explicit operator bool() const { return !!pvt; }

    friend
    PVXS_API
    std::ostream& operator<<(std::ostream& strm, const Server& serv);

    struct Pvt;
private:
    std::shared_ptr<Pvt> pvt;
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Server& serv);

//! Configuration for a Server
struct PVXS_API Config : public impl::ConfigCommon {
    //! List of network interface addresses (**not** host names) to which this server will bind.
    //! interfaces.empty() treated as an alias for "0.0.0.0", which may also be given explicitly.
    //! Port numbers are optional and unused (parsed and ignored)
    std::vector<std::string> interfaces;
    //! Ignore client requests originating from addresses in this list.
    //! Entries must be IP addresses with optional port numbers.
    //! Port number zero (default) is treated as a wildcard which matches any port.
    //! @since 0.2.0
    std::vector<std::string> ignoreAddrs;
    //! Addresses (**not** host names) to which (UDP) beacons message will be sent.
    //! May include broadcast and/or unicast addresses.
    //! Supplemented only if auto_beacon==true
    std::vector<std::string> beaconDestinations;
    //! Whether to populate the beacon address list automatically.  (recommended)
    bool auto_beacon = true;

    //////////////
    // SECURITY //
    //////////////

    /**
     * @brief true if server should stop if no cert can is available or can be
     * comissioned
     */
    bool tls_stop_if_no_cert = false;

    /**
     * @brief PVACMS only: Minutes before expiry that `EXPIRY_IMMINENT`
     * status should be set on a certificate status.
     *
     * When a server or client receives such a status it will try to
     * renew the cert but will keep a backup and if it fails to renew
     * it will continue to use the original one.
     */
    uint32_t cert_pre_expiry_mins = 1440;

    /**
     * @brief PVACMS only: When basic credentials are used then set to true to
     * request administrator approval to issue client certificates.
     *
     * This will mean that clients will have to keep retrying connections
     * until the certificate request is approved by an administrator.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_client_require_approval = false;

    /**
     * @brief PVACMS only: When basic credentials are used then set to true
     * to request administrator approval to issue server certificates.
     * This will mean that servers will have to keep retrying connections
     * until the certificate request is approved by an administrator.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_server_require_approval = true;

    /**
     * @brief OCSP-PVA only: The port for the OCSP server to listen on.
     */
    unsigned short ocsp_port = 8080;

    /**
     * @brief PVACMS only: This is the string that determines the fully
     * qualified path to a file that will be used as the sqlite PVACMS
     * certificate database for a PVACMS process.
     *
     * The default is the current directory in a file called certs.db
     */
    std::string ca_db_filename = "certs.db";

    /**
     * @brief PVACMS and OCSP-PVA only: This is the string that determines
     * the fully qualified path to the PKCS#12 keychain file that contains
     * the CA certificate, and public and private keys.
     *
     * This is used to sign certificates being created in the PVACMS or
     * sign certificate status responses being delivered by OCSP-PVA.
     * If this is not specified it defaults to the TLS_KEYCHAIN file.
     *
     * Note: This certificate needs to be trusted by all EPICS agents.
     */
    std::string ca_keychain_filename;

    /**
     * @brief PVACMS and OCSP-PVA only: This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the `ca_keychain_filename`.
     *
     * This is optional.  If not specified, the `ca_keychain_filename`
     * contents will not be encrypted.
     */
    std::string ca_keychain_password;

    /**
     * @brief PVACMS only: This is the string that determines the
     * fully qualified path to a file that will be used as the
     * ACF file that configures the permissions that are accorded
     * to validated peers of the PVACMS.
     *
     * This will specify administrators that have the right to revoke
     * certificates, and the default read permissions for certificate statuses.
     * There is no default so it must be specified on the command line or
     * as an environment variable.
     *
     * e.g.
     * @code
     *      AG(ADMINS) {
     *       "ed@slac.stanford.edu",
     *       "greg@slac.stanford.edu"
     *      }
     *
     *      SG(SPECIAL) {
     *       RULE(1,WRITE,TRAPWRITE) {
     *         UAG(ADMINS)
     *      }
     *
     * @endcode
     *
     */
    std::string ca_acf_filename;

    /**
     * @brief PVACMS only: If a CA root certificate has not been established
     * prior to the first time that the PVACMS starts up, then one
     * will be created automatically.
     *
     * To provide the name (CN) to be used in the subject of the
     * CA certificate we can use this environment variable.
     */
    std::string ca_name = "EPICS Root CA";

    /**
     * @brief PVACMS only: If a CA root certificate has not been established
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the CA certificate we can use this environment variable.
     */
    std::string ca_organization = "ca.epics.org";

    /**
     * @brief PVACMS only: If a CA root certificate has not been
     * established prior to the first time that the PVACMS starts up,
     * then one will be created automatically.
     *
     * To provide the organizational unit (OU) to be used in the
     * subject of the CA certificate we can use this environment variable.
     */
    std::string ca_organizational_unit = "EPICS Certificate Authority";

#ifdef PVXS_ENABLE_JWT_AUTH
    /**
     * @brief PVACMS only: For Servers this is the trusted URI of the JWT
     * verifier.
     */
    std::string jwt_trusted_uri;

    /**
     * @brief PVACMS only: This is the request format for the JWT verifier.
     *
     * PVACMS only: A string that is used verbatim as the payload
     * for the verification request while substituting the string
     * #token# for the token value, and #kid# for the key id.
     * This is used when the verification server requires a formatted.
     *
     * If the string is #token# (default) then the verification endpoint
     * is called with the raw token as the payload.
     */
    std::string jwt_request_format = "#token#";

    /**
     * @brief PVACMS only: format for JWT verification response value
     *
     * PVACMS only: A pattern string that we can use to decode
     * the response from a verification endpoint if the response
     * is formatted text.  All white space is removed in the given
     * string and in the response.  Then all the text prior to
     * #response# is matched and removed from the response and
     * all the text after the response is likewise removed, what
     * remains is the response value.  An asterisk in the string
     * matches any sequence of characters in the response.  It
     * is converted to lowercase and interpreted as valid if it
     * equals valid, ok, true, t, yes, y, or 1.
     *
     * If the string is #response# (default) then the response
     * is raw and is converted to lowercase and compared without
     * removing any formatting.
     */
    std::string jwt_response_format = "#response#";

    /**
     * @brief PVACMS only: Determines whether the JWT verification endpoint will
     * be called with HTTP GET or POST
     *
     * If called with POST, then the payload is exactly what is defined
     * by the REQUEST_FORMAT variable.
     *
     * If called with GET, then the token is passed in the
     * Authorization header of the HTTP GET request.
     */
    enum JwtRequestMethod {
        POST,
        GET,
    } jwt_request_method = POST;

    /**
     * @brief PVACMS only: If set this tells PVACMS that when it receives a
     * 200 HTTP-response code from the HTTP request then the
     * token is valid, and invalid for any other response code.
     */
    bool jwt_use_response_code = false;

    /**
     * @brief PVACMS only: Get the request string based on the configured
     * request format
     * @param token the token to insert into the request format
     * @param key_id the key id to insert into the request format
     * @return the formatted request string
     */
    inline std::string getJwtRequest(const std::string& token,
                                     const std::string& key_id) const {
        static const std::string kTokenPlaceholder = "#token#";
        static const std::string kKeyIDPlaceholder = "#kid#";

        std::string request = jwt_request_format;

        size_t token_pos = request.find(kTokenPlaceholder);
        if (token_pos != std::string::npos) {
            request.replace(token_pos, kTokenPlaceholder.length(), token);
        }

        size_t key_id_pos = request.find(kKeyIDPlaceholder);
        if (key_id_pos != std::string::npos) {
            request.replace(key_id_pos, kKeyIDPlaceholder.length(), key_id);
        }

        return request;
    }

    /**
     * PVACMS only: Match a given response against the response format
     */
    inline bool isJwtResponseValid(std::string response) const noexcept {
        // Escape braces in response format string
        auto jwt_clean_response_format = jwt_response_format;
        std::regex open_braces("\\{");
        jwt_clean_response_format =
            std::regex_replace(jwt_clean_response_format, open_braces, "\\{");

        std::regex close_braces("\\}");
        jwt_clean_response_format =
            std::regex_replace(jwt_clean_response_format, close_braces, "\\}");

        // Remove whitespace from the input strings
        response.erase(
            std::remove_if(response.begin(), response.end(), ::isspace),
            response.end());
        jwt_clean_response_format.erase(
            std::remove_if(jwt_clean_response_format.begin(),
                           jwt_clean_response_format.end(), ::isspace),
            jwt_clean_response_format.end());

        // Convert response format to regex but remember where the #response# is
        // located by first creating a placeholders position map with the
        // placeholder and the position it will need to be inserted into the
        // given response format string when all prior placeholders are
        // already replaced by the regex equivalent.
        int index_of_response = 0;
        static const char* kPlaceholderRegex = "(.*)";
        size_t position = 0, position_adjust = 0;
        std::string placeholders[] = {"*", "#response#"};
        std::map<size_t, std::string> placeholder_positions;

        // Fill placeholders position map with all occurrences of placeholders
        for (const auto& placeholder : placeholders) {
            position = 0;
            while ((position = jwt_clean_response_format.find(
                        placeholder, position)) != std::string::npos) {
                placeholder_positions[position + position_adjust] = placeholder;
                position += placeholder.size();

                // diff between placeholder len and len of placeholder regex
                position_adjust +=
                    (strlen(kPlaceholderRegex) - placeholder.length());
            }
        }

        // Replace all occurrences in order of appearance
        int counter = 1;
        for (auto& placeholder_position : placeholder_positions) {
            if (placeholder_position.second == "#response#") {
                index_of_response = counter;
            }
            jwt_clean_response_format.replace(
                placeholder_position.first, placeholder_position.second.size(),
                kPlaceholderRegex);
            counter++;
        }

        // Make a regex from the converted response format
        std::regex pattern(jwt_clean_response_format);
        std::smatch match;
        if (std::regex_search(response, match, pattern) &&
            static_cast<int>(match.size()) > index_of_response) {
            // If the response matches the format
            // Then extract the response match
            std::string response_value = match[index_of_response];

            // Convert the response match to lower case
            std::transform(response_value.begin(), response_value.end(),
                           response_value.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            // Check if it matches any of the valid responses
            return (response_value == "valid" || response_value == "ok" ||
                    response_value == "true" || response_value == "t" ||
                    response_value == "yes" || response_value == "y" ||
                    response_value == "1");
        }

        // Response is not valid if it does not match the specified format
        return false;
    }
#endif

#ifdef PVXS_ENABLE_KERBEROS_AUTH
    /**
     * @brief PVACMS only: This string is the fully qualified
     * path to the location of the keytab file.
     *
     * It is used to retrieve the secret key used to decode
     * messages destined for a Kerberos service
     */
    std::string krb_keytab;
#endif

#ifdef PVXS_ENABLE_LDAP_AUTH
    /**
     * @brief PVACMS only: distinguished name for an account with
     * sufficient permissions to query the LDAP directory
     *
     * e.g. "cn=admin,dc=slac,dc=stanford,dc=edu"
     */
    std::string ldap_account;

    /**
     * @brief PVACMS only: The password for the configured LDAP account
     */
    std::string ldap_account_password;

    /**
     * @brief PVACMS only: hostname or IP address of the LDAP server.
     *
     * This server will be queried to determine if the principal
     * obtained by GSS-API comes from the directory store.
     *
     * This must be specified for the LDAP authentication method
     */
    std::string ldap_host;

    /**
     * @brief PVACMS only: this is the port number to contact the LDAP service
     */
    unsigned short ldap_port;

    /**
     * @brief PVACMS only: distinguished name for location within LDAP
     * directory to start search
     *
     * e.g. "cn=slac,dc=stanford,dc=edu"
     */
    std::string ldap_search_root;
#endif

    //! Server unique ID.  Only meaningful in readback via Server::config()
    ServerGUID guid{};

private:
    bool BE = EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG;
    bool UDP = true;
public:

    // compat
    static inline Config from_env(const bool tls_disabled = false, const ConfigTarget target = SERVER) {
        return Config{}.applyEnv(tls_disabled, target);
    }
#ifdef PVXS_ENABLE_JWT_AUTH
    static inline Config from_env_with_jwt(const std::string& token, const ConfigTarget target) {
        return Config{}.applyEnvWithJwt(token, target);
    }
#endif

    //! Default configuration using process environment
    static inline Config fromEnv(const bool tls_disabled = false,
                                 const ConfigTarget target = SERVER) {
        auto config = Config{}.applyEnv(tls_disabled, target);
        if (target == PVACMS) {
            config.tls_stop_if_no_cert = true;
            config.cert_auto_provision = false;
        }
        return config;
    }
#ifdef PVXS_ENABLE_JWT_AUTH
    static inline Config fromEnvWithJwt(const std::string& token, const ConfigTarget target) {
        return Config{}.applyEnvWithJwt(token, target);
    }
#endif

    //! Configuration limited to the local loopback interface on a randomly chosen port.
    //! Suitable for use in self-contained unit-tests.
    //! @since 0.3.0 Address family argument added.
    static Config isolated(int family=AF_INET);

    //! update using defined EPICS_PVA* environment variables
    Config& applyEnv(const bool tls_disabled = false, const ConfigTarget target = SERVER);
    Config& applyEnv(const bool tls_disabled = false);
#ifdef PVXS_ENABLE_JWT_AUTH

    Config& applyEnvWithJwt(const std::string& token, const ConfigTarget target = SERVER);
#endif

    typedef std::map<std::string, std::string> defs_t;
    //! update with definitions as with EPICS_PVA* environment variables.
    //! Process environment is not changed.
    Config& applyDefs(const defs_t& def);

    //! extract definitions with environment variable names as keys.
    //! Process environment is not changed.
    void updateDefs(defs_t& defs) const;

    /** Apply rules to translate current requested configuration
     *  into one which can actually be loaded based on current host network configuration.
     *
     *  Explicit use of expand() is optional as the Context ctor expands any Config given.
     *  expand() is provided as a aid to help understand how Context::effective() is arrived at.
     *
     *  @post autoAddrList==false
     */
    void expand();

    //! Create a new Server using the current configuration.
    inline Server build() const {
        return Server(*this);
    }

#ifdef PVXS_EXPERT_API_ENABLED
    // for protocol compatibility testing
    inline Config& overrideSendBE(bool be) { BE = be; return *this; }
    inline bool sendBE() const { return BE; }
    inline Config& overrideShareUDP(bool share) { UDP = share; return *this; }
    inline bool shareUDP() const { return UDP; }
#endif
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Config& conf);

}} // namespace pvxs::server

#endif // PVXS_SERVER_H
