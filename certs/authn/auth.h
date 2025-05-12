/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_H
#define PVXS_AUTH_H

#include <functional>
#include <string>
#include <vector>

#include <certstatusfactory.h>

#include <pvxs/client.h>
#include <pvxs/data.h>

#include <CLI/App.hpp>

#include "ccrmanager.h"
#include "certfactory.h"
#include "configstd.h"
#include "security.h"
#include "sslinit.h"

#pragma once

namespace pvxs {
namespace certs {

/**
 * @class Auth
 * @brief Abstract class for authentication operations.
 *
 * The Auth class provides an interface for retrieving credentials and
 * creating and validating Certificate Creation Requests (CCRs).
 */
using namespace certs;
class Auth {
   public:
    std::string type_{};
    std::vector<Member> verifier_fields_{};

    // Constructor and Destructor
    Auth(const std::string &type, const std::vector<Member> &verifier_fields) : type_(type), verifier_fields_(verifier_fields) {}

    virtual ~Auth() = default;

    /**
     * @brief Get credentials for the given configuration and usage.
     *
     * This function returns a shared pointer to a Credentials object for the given configuration and usage.
     * Implementers should fill in the Credentials object with the appropriate values for the given configuration and usage.
     *
     * @param config The configuration to use for the credentials
     * @param for_client Whether the credentials are for a client or server
     * @return A shared pointer to the Credentials object
     */
    virtual std::shared_ptr<Credentials> getCredentials(const client::Config &config, bool for_client = true) const = 0;

    /**
     * @brief Verify a Certificate Creation Request (CCR).
     *
     * This function verifies a Certificate Creation Request (CCR). It is called inside PVACMS to verify the CCR.
     * Automatically compiles into the PVACMS if the auth method is registered, PVACMS will
     * look at any CCR it receives and call the overridden function with the CCR as the argument.
     * Implementers should provide appropriate code to verify the authenticity of the CCR.
     *
     * @param ccr The CCR to verify
     * @return True if the CCR is valid, false otherwise
     */
    virtual bool verify(Value &ccr) const = 0;

    /**
     * @brief Get the authenticator configuration from the environment.
     *
     * This function gets the authenticator configuration from the environment.
     * Implementers should get any authenticator specific configuration options from the environment.
     *
     * @param config The configuration to fill in
     */
    virtual void fromEnv(std::unique_ptr<client::Config> &config) = 0;

    /**
     * @brief Create a Certificate Creation Request (CCR) for the given credentials and key pair.
     *
     * This function creates a Certificate Creation Request (CCR) for the given credentials and key pair.
     * Implementers should fill in the CCR with the appropriate values for the given credentials and key pair.
     *
     * @param credentials The credentials to use for the CCR
     * @param key_pair The key pair to use for the CCR
     * @param usage The usage of the CCR
     * @param config The configuration to use for the CCR
     * @return A shared pointer to the CCR
     */
    virtual std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                           const std::shared_ptr<KeyPair> &key_pair,
                                                                           const uint16_t &usage,
                                                                           const ConfigAuthN &config) const = 0;

    /**
     * @brief Get the placeholder text for the options help text.
     *
     * This function returns a string containing the placeholder text for the options help text.
     * This will be inserted into the usage documentation for PVACMS to indicate where this authenticator's options should be placed.
     * Implementers should return a string containing the placeholder text for the options help text.
     * e.g. "Enter the kerberos principal name: ".  This should be enclosed in square brackets for consistency to indicate optional arguments.
     *
     * @return A string containing the placeholder text for the options help text
     */
    virtual std::string getOptionsPlaceholderText() { return {}; }

    /**
     * @brief Get the options help text.
     *
     * This function returns a string containing the options help text.
     * Implementers should return a string containing the options help text.
     * The string will be multi-line and will be formatted to fit into the usage documentation for PVACMS.
     * It should start with a string heading that matches the name given in the getOptionsPlaceholderText() function.
     *
     * e.g. if getOptionsPlaceholderText() returns "[kerberos Options]", the heading should be "kerberos Options"
     * followed by multiple lines of help text for the kerberos options.
     *
     * @return A string containing the options help text
     */
    virtual std::string getOptionsHelpText() { return {}; }

    /**
     * @brief Add the options to the CLI application.
     *
     * This function adds the options to the CLI application object so that they can be parsed from the command line.
     * Implementers should add all required options to the CLI application object.
     * They should expect to find a configuration object that matches the type of the authenticator in the map under the key of the type name.
     * They should use this entry to store the values retrieved from the command line for the authenticator's options
     *
     * @param app The CLI application object
     * @param authn_config_map A map of the authenticator configuration
     */
    virtual void addOptions(CLI::App &app, std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map) {}

    /**
     * This function transfers the configuration from the given config object to the authenticator.
     * Useful for when configuration is not available when using an authenticator. Only implement this
     * if required.
     * Implementers should transfer any configuration options that are required for situations where configuration
     * is not available when using an authenticator.
     *
     * @param config The configuration to transfer
     */
    virtual void configure(const client::Config &config) {}

    /**
     * @brief Process a Certificate Creation Request (CCR).
     *
     * This function processes a Certificate Creation Request (CCR).
     * It will return a string containing the PEM encoded certificate.
     *
     * @param ccr The CCR to process
     * @param timeout The timeout for the processing
     * @param cert_pv_prefix the CMS pv prefix
     * @param issuer_id the issuer ID of the CMS
     * @return The PEM encoded certificate
     */
    std::string processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr, const std::string &cert_pv_prefix, const std::string &issuer_id, double timeout) const;

    /**
     * @brief Update the definitions with the authenticator-specific definitions.
     *
     * This function is called from PVACMS to update the definitions with the authenticator-specific definitions.
     * It updates the given definitions with the authenticator-specific definitions.
     *
     * @param defs the definitions to update with the authenticator-specific definitions
     */
    virtual void updateDefs(client::Config::defs_t &defs) const {}

    /**
     * @brief Registration of all supported auth methods.
     *
     * This static member is used to store all the supported authenticators.
     * The registration performed by each authenticator adds an entry to this map.
     * Registration is performed as follows:
     *
     * @code
     * #define PVXS_XXX_AUTH_TYPE "xxx"
     * struct AuthXxxRegistrar {
     *     AuthXxxRegistrar() {
     *         AuthRegistry::instance().registerAuth(PVXS_XXX_AUTH_TYPE, std::unique_ptr<Auth>(new AuthXxx()));
     *     }
     * } auth_n_xxx_registrar;
     * @endcode
     *
     * This will add an entry to the map for AuthXxx.
     */
    static std::map<const std::string, std::shared_ptr<Auth>> auths;

    /**
     * @brief Get the authenticator for the given type.
     *
     * This function returns a pointer to the authenticator for the given type.
     * Uses the authenticator map to find the authenticator for the given type.
     * If the type is not found, it will throw an exception.
     *
     * @param type The type of the authenticator
     * @return A pointer to the authenticator for the given type
     */
    static Auth *getAuth(const std::string &type);

    void runAuthNDaemon(const ConfigAuthN &authn_config, bool for_client, CertData &&cert_data, const std::function<CertData()> &&fn);

   protected:
    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    static std::string ccrToString(const std::shared_ptr<CertCreationRequest> &ccr, const uint16_t &usage) {
        return SB() << ccr->type                            // Type
                    << ccr->credentials->name               // Name
                    << ccr->credentials->country            // Country
                    << ccr->credentials->organization       // Organization
                    << ccr->credentials->organization_unit  // Organizational Unit
                    << ccr->credentials->not_before         // Not before
                    << ccr->credentials->not_after          // Not After
                    << ccr->credentials->config_uri_base    // Config URL Base
                    << usage;                               // Usage
    }

    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    static std::string ccrToString(const Value &ccr) {
        return SB() << ccr["type"].as<std::string>()               // Type
                    << ccr["name"].as<std::string>()               // Name
                    << ccr["country"].as<std::string>()            // Country
                    << ccr["organization"].as<std::string>()       // Organization
                    << ccr["organization_unit"].as<std::string>()  // Organizational Unit
                    << ccr["not_before"].as<time_t>()              // Not before
                    << ccr["not_after"].as<time_t>()               // Not After
                    << ccr["config_uri_base"].as<std::string>()    // Config URL Base
                    << ccr["usage"].as<uint16_t>();                // Usage
    }

   private:
    server::Server config_server_{};
    class ConfigMonitorParams {
       public:
        const ConfigAuthN &config_;
        mutable ossl_ptr<X509> cert_{};
        const std::function<CertData()> fn_{};
        int adaptive_timeout_mins_{0};
#define PVXS_CONFIG_MONITOR_TIMEOUT_MAX 1440

        ConfigMonitorParams(const ConfigAuthN &config, ossl_ptr<X509> &cert, const std::function<CertData()> &&fn)
            : config_(config), cert_(std::move(cert)), fn_(std::move(fn)) {}
    };

    static timeval configurationMonitor(ConfigMonitorParams &config_monitor_params, server::SharedPV &pv);
    static std::string formatTimeDuration(time_t total_seconds);

    /**
     * @brief The prototype of the data returned for a certificate configuration PV
     *
     * A serial number, issuer ID, the keychain file and how long before it expires.
     * Each config change will update the serial number and expires_in value.
     * Keychain and issuer will stay the same
     *
     * @return The prototype of the data returned for a certificate configuration PV
     */
    static Value getConfigurationPrototype() {
        using namespace members;

        auto value = TypeDef(TypeCode::Struct,
                             {
                                 Member(TypeCode::UInt64, "serial"),
                                 Member(TypeCode::String, "issuer_id"),
                                 Member(TypeCode::String, "keychain"),
                                 Member(TypeCode::String, "expires_in"),
                             })
                         .create();
        return value;
    }

    /**
     * @brief Set a value in a Value object marking any changes to the field if the values changed and if not then
     * the field is unmarked.  Doesn't work for arrays or enums so you need to do that manually.
     *
     * @param target The Value object to set the value in
     * @param field The field to set the value in
     * @param new_value The new value to set
     */
    template <typename T>
    static void setValue(Value &target, const std::string &field, const T &new_value) {
        const auto current_field = target[field];
        auto current_value = current_field.as<T>();
        if (current_value == new_value) {
            target[field].unmark();
        } else {
            target[field] = new_value;
        }
    }

    CCRManager ccr_manager_{};
};

/**
 * @brief Function to cast a pointer to a base class into a pointer to a
 * subclass
 *
 * This function checks if the given class S is a subclass of the given base
 * class C, then casts the given argument of type C into a pointer to S.
 *
 * @tparam S The derived class type
 * @tparam C The base class type
 * @param base_class A shared pointer to the base class object
 * @return A shared pointer to the derived class object if it is a subclass of
 * the base class, nullptr otherwise.
 *
 * @throws std::bad_cast If the cast from base class to derived class fails
 * @throws std::invalid_argument If S is not a subclass of C
 *
 * @note This function uses std::is_base_of to check for subclass relationship
 * and std::dynamic_pointer_cast for safe casting from base class to derived
 * class.
 *
 * @code
 *
 * // Example usage:
 *
 * class BaseClass {};
 * class DerivedClass : public BaseClass {};
 *
 * std::shared_ptr<BaseClass> base = std::make_shared<DerivedClass>();
 *
 * std::shared_ptr<DerivedClass> derived = castAs<DerivedClass>(base);
 *
 * if (derived != nullptr) {
 *  // Successfully casted to derived class
 * } else {
 *  // Not a subclass of derived class
 * }
 *
 * @endcode
 */
template <typename S, typename C>
std::shared_ptr<S> castAs(const std::shared_ptr<C> &base_class) {
    static_assert(std::is_base_of<C, S>::value, "not a subclass");
    return std::dynamic_pointer_cast<S>(base_class);
}

template <typename ConfigT, typename AuthT>
CertData getCertificate(bool &retrieved_credentials, ConfigT config, uint16_t cert_usage, const AuthT &authenticator, const std::string &tls_keychain_file,
                        const std::string &tls_keychain_pwd);

template <typename ConfigT, typename AuthT>
int runAuthenticator(int argc, char *argv[], std::function<void(ConfigT &, AuthT &)> pre_configure_hook = nullptr);

/**
 * @brief Get a certificate for the given authenticator
 *
 * This function gets a certificate for the given authenticator.
 *
 * @param retrieved_credentials the retrieved credentials flag - true if credentials were retrieved
 * @param config the configuration to use for the certificate
 * @param cert_usage the certificate usage client, server, or ioc
 * @param authenticator the authenticator to use for the certificate
 * @param tls_keychain_file the TLS keychain file to use for the certificate
 * @param tls_keychain_pwd the TLS keychain password to use for the certificate, none if empty
 * @return The certificate data
 */
template <typename ConfigT, typename AuthT>
CertData getCertificate(bool &retrieved_credentials, ConfigT config, uint16_t cert_usage, const AuthT &authenticator, const std::string &tls_keychain_file,
                        const std::string &tls_keychain_pwd) {
    DEFINE_LOGGER(auth, std::string("pvxs.auth." + authenticator.type_).c_str());
    CertData cert_data;

    if (auto credentials = authenticator.getCredentials(config, IS_USED_FOR_(cert_usage, pvxs::ssl::kForClient))) {
        std::shared_ptr<KeyPair> key_pair;
        log_debug_printf(auth, "Credentials retrieved for: %s authenticator\n", authenticator.type_.c_str());
        retrieved_credentials = true;

        // Get or create the key pair.  Store it in the keychain file if not already present
        try {
            // Check if the key pair exists
            key_pair = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getKeyFromFile();
        } catch (std::exception &e) {
            // Make a new key pair file
            try {
                log_debug_printf(auth, "%s\n", e.what());
                key_pair = IdFileFactory::createKeyPair();
            } catch (std::exception &new_e) {
                throw std::runtime_error(SB() << "Error creating client key: " << new_e.what());
            }
        }

        // Create a Certificate Creation Request (CCR) using the credentials and key pair
        auto cert_creation_request = authenticator.createCertCreationRequest(credentials, key_pair, cert_usage, config);

        log_debug_printf(auth, "CCR created for: %s Authenticator\n", authenticator.type_.c_str());

        // Attempt to create a certificate with the Certificate Creation Request (CCR)
        auto p12_pem_string = authenticator.processCertificateCreationRequest(cert_creation_request, config.cert_pv_prefix, config.issuer_id, config.request_timeout_specified);

        // If the certificate was created successfully, write it to the keychain file
        if (!p12_pem_string.empty()) {
            log_debug_printf(auth, "Cert generated by PVACMS and successfully received: %s\n", p12_pem_string.c_str());

            // Attempt to write the certificate and private key to a cert file protected by the configured password
            auto file_factory = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd, key_pair, nullptr, nullptr, p12_pem_string);
            file_factory->writeIdentityFile();

            // Read the certificate and private key back from the keychain file for info and verification
            cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
            const auto serial_number = CertStatusFactory::getSerialNumber(cert_data.cert);
            const auto issuer_id = CertStatus::getIssuerId(cert_data.cert_auth_chain);

            // Get the start and end dates of the certificate
            const std::string from = std::ctime(&credentials->not_before);
            const std::string to = std::ctime(&credentials->not_after);

            // Log the certificate info
            log_info_printf(auth, "%s\n", (pvxs::SB() << "CERT_ID: " << issuer_id << ":" << serial_number).str().c_str());
            log_info_printf(auth, "%s\n", (pvxs::SB() << "TYPE: " << authenticator.type_).str().c_str());
            log_info_printf(auth, "%s\n", (pvxs::SB() << "OUTPUT TO: " << tls_keychain_file).str().c_str());
            log_info_printf(auth, "%s\n", (pvxs::SB() << "NAME: " << credentials->name).str().c_str());
            log_info_printf(auth, "%s\n", (pvxs::SB() << "ORGANIZATION: " << credentials->organization).str().c_str());
            log_info_printf(auth, "%s\n", (pvxs::SB() << "ORGANIZATIONAL UNIT: " << credentials->organization_unit).str().c_str());
            log_info_printf(auth, "%s\n", (pvxs::SB() << "COUNTRY: " << credentials->country).str().c_str());
            log_info_printf(auth, "%s\n",
                            (pvxs::SB() << "VALIDITY: " << from.substr(0, from.size() - 1) << " to " << to.substr(0, to.size() - 1)).str().c_str());
            std::cout << "Certificate identifier  : " << issuer_id << ":" << serial_number << std::endl;

            log_info_printf(auth, "--------------------------------------%s", "\n");
        }
    }
    return cert_data;
}

/**
 * @brief Run the authenticator
 *
 * This function runs the authenticator to get a certificate.  It may run in daemon mode
 * if the daemon flag is set.
 *
 * It assumes that readParameters exists with the correct signature for the templated ConfigT
 * and returns a non-zero exit status if it fails.
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @param pre_configure_hook the pre configure hook to call before the authenticator is configured
 * @return The exit status 0 if successful, non-zero if an error occurs and we should exit
 */
template <typename ConfigT, typename AuthT>
int runAuthenticator(int argc, char *argv[], std::function<void(ConfigT &, AuthT &)> pre_configure_hook) {
    AuthT authenticator{};
    DEFINE_LOGGER(auth, std::string("pvxs.auth." + authenticator.type_).c_str());
    ;
    logger_config_env();
    bool retrieved_credentials{false};

    try {
        ossl::sslInit();

        auto config = ConfigT::fromEnv();

        bool verbose{false}, debug{false}, daemon_mode{false}, force{false};
        uint16_t cert_usage{pvxs::ssl::kForClient};

        const auto parse_result = readParameters(argc, argv, config, verbose, debug, cert_usage, daemon_mode, force);
        if (parse_result) return parse_result == -1 ? 0 : parse_result;

        if (verbose) logger_level_set(std::string("pvxs.auth." + authenticator.type_ + "*").c_str(), pvxs::Level::Info);
        if (debug) logger_level_set(std::string("pvxs.auth." + authenticator.type_ + "*").c_str(), pvxs::Level::Debug);

        // Execute special case hook if provided
        if (pre_configure_hook) {
            pre_configure_hook(config, authenticator);
        }

        authenticator.configure(config);

        if (verbose) {
            std::cout << "Effective config\n" << config << std::endl;
        }

        const std::string tls_keychain_file = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_file : config.tls_keychain_file;
        const std::string tls_keychain_pwd = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_pwd : config.tls_keychain_pwd;

        CertData cert_data;
        try {
            auto new_cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
            const auto now = time(nullptr);
            const auto not_after_time = (!cert_data.cert) ? 0 :  CertFactory::getNotAfterTimeFromCert(new_cert_data.cert);
            if (not_after_time > now) {
                cert_data = std::move(new_cert_data);
            }
        } catch (std::exception &) {
        }

        if (!cert_data.cert || force) {
            cert_data = getCertificate(retrieved_credentials, config, cert_usage, authenticator, tls_keychain_file, tls_keychain_pwd);
        } else if (!daemon_mode ) {
            log_warn_printf(auth, "%s: Valid certificate found: Use `--force` flag to overwrite\n", tls_keychain_file.c_str());
        }

        if (cert_data.cert && daemon_mode) {
            authenticator.runAuthNDaemon(config, IS_USED_FOR_(cert_usage, pvxs::ssl::kForClient), std::move(cert_data),
                                         [&retrieved_credentials, config, cert_usage, authenticator, tls_keychain_file, tls_keychain_pwd] {
                                             return getCertificate(retrieved_credentials, config, cert_usage, authenticator, tls_keychain_file,
                                                                   tls_keychain_pwd);
                                         });
        }
        return 0;
    } catch (std::exception &e) {
        if (retrieved_credentials)
            log_warn_printf(auth, "%s\n", e.what());
        else
            log_err_printf(auth, "%s\n", e.what());
        return -1;
    }
}

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_H
