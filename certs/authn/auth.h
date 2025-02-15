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

#include <pvxs/data.h>

#include <CLI/App.hpp>

#include "ccrmanager.h"
#include "certfactory.h"
#include "configstd.h"
#include "security.h"

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
    std::string type_;
    std::vector<Member> verifier_fields_;

    // Constructor and Destructor
    Auth(const std::string &type, const std::vector<Member> &verifier_fields) : type_(type), verifier_fields_(verifier_fields) {};
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
     * look at any CCR it recieves and call the overriden function with the CCR as the argument.
     * Implementers should provide appropriate code to verify the authenticity of the CCR.
     *
     * @param ccr The CCR to verify
     * @return True if the CCR is valid, false otherwise
     */
    virtual bool verify(Value ccr) const = 0;

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
     * @return A shared pointer to the CCR
     */
    virtual std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                           const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const = 0;

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
    virtual std::string getOptionsPlaceholderText() {return {};};

    /**
     * @brief Get the options help text.
     *
     * This function returns a string containing the options help text.
     * Implementers should return a string containing the options help text.
     * The string will be multi-line and will be formatted to fit into the usage documentation for PVACMS.
     * It shuld start with a string heading that matches the name given in the getOptionsPlaceholderText() function.
     *
     * e.g. if getOptionsPlaceholderText() returns "[kerberos Options]", the heading should be "kerberos Options"
     * followed by multiple lines of help text for the kerberos options.
     *
     * @return A string containing the options help text
     */
    virtual std::string getOptionsHelpText() {return {};};

    /**
     * @brief Add the options to the CLI application.
     *
     * This function adds the options to the CLI application object so that they can be parsed from the command line.
     * Implementers should add all required options to the CLI application object.
     * They should expect to find a configuration object that matches the type of the authenticator in the map under the key of the type name.
     * They should use this entry to store the values retrieved from the command line for the authenticator's options
     *
     * @param app The CLI application object
     * @param authn_config_map A map of the authentication configuration
     */
    virtual void addOptions(CLI::App &app, std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map) {};

    /**
     * This function transfers the configuration from the given config object to the authenticator.
     * Useful for when configuration is not available when using an authenticator. Only implement this
     * if required.
     * Implementers should transfer any configuration options that are required for situations where configuration
     * is not available when using an authenticator.
     *
     * @param config The configuration to transfer
     */
    virtual void configure(const client::Config &config) {};

    /**
     * @brief Process a Certificate Creation Request (CCR).
     *
     * This function processes a Certificate Creation Request (CCR).
     * It will return a string containing the PEM encoded certificate.
     *
     * @param ccr The CCR to process
     * @param timeout The timeout for the processing
     * @return The PEM encoded certificate
     */
    std::string processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr, double timeout) const;

    /**
     * @brief Registration of all supported auth methods.
     *
     * This static member is used to store all the supported authentication methods.
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

   protected:
    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    static std::string ccrToString(const std::shared_ptr<CertCreationRequest> &ccr, const uint16_t &usage) {
        return SB() << ccr->type << ccr->credentials->name << ccr->credentials->country << ccr->credentials->organization << ccr->credentials->organization_unit
                    << ccr->credentials->not_before << ccr->credentials->not_after << usage;
    }

    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    static std::string ccrToString(const Value &ccr) {
        return SB() << ccr["type"].as<std::string>() << ccr["name"].as<std::string>() << ccr["country"].as<std::string>()
                    << ccr["organization"].as<std::string>() << ccr["organization_unit"].as<std::string>() << ccr["not_before"].as<time_t>()
                    << ccr["not_after"].as<time_t>() << ccr["usage"].as<uint16_t>();
    }

   private:
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
 * @param baseClass A shared pointer to the base class object
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
 std::shared_ptr<S> castAs(const std::shared_ptr<C> &baseClass) {
    static_assert(std::is_base_of<C, S>::value, "not a subclass");
    return std::dynamic_pointer_cast<S>(baseClass);
}

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_H
