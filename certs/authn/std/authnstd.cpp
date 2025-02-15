/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnstd.h"

#include <ifaddrs.h>
#include <osiProcess.h>

#include <pvxs/log.h>

#include <CLI/CLI.hpp>

#include "authregistry.h"
#include "certfilefactory.h"
#include "certstatusfactory.h"
#include "configstd.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"

DEFINE_LOGGER(auth, "pvxs.auth.std");

namespace pvxs {
namespace certs {

/**
 * @brief Registrar for the standard authenticator
 *
 * This will register the Standard authenticator with the AuthRegistry.
 * This allows it to be found by PVACMS to authenticate Standard certificate
 * creation requests (CCRs).
 *
 * The Standard authenticator uses the commandline, environment, or user/hostname
 * information to create the credentials for the certificate.
 */
struct AuthNStdRegistrar {
    AuthNStdRegistrar() {  // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_DEFAULT_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNStd()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_std_registrar;

/**
 * @brief Extract the country code from the given locale string
 *
 * This will extract the country code from a locale string.  It works by finding
 * the country part of the locale string, which is always after an underscore.
 * It then converts the country code to uppercase and returns it.
 *
 * @param locale_str the locale string to extract the country code from
 * @return the country code extracted from the locale string
 */
static std::string extractCountryCode(const std::string &locale_str) {
    // Look for underscore
    auto pos = locale_str.find('_');
    if (pos == std::string::npos || pos + 3 > locale_str.size()) {
        return "";
    }

    std::string country_code = locale_str.substr(pos + 1, 2);
    std::transform(country_code.begin(), country_code.end(), country_code.begin(), ::toupper);
    return country_code;
}

/**
 * @brief Get the current country code of where the process is running.
 *
 * This returns the two-letter country code.  It is always upper case.
 * For example for the United States it returns `US`, and for France, `FR`.
 *
 * The fact that a locale string is not always available and that the country part is optional
 * means that it rarely works.  It tries the following:
 *
 * 1. Try from std::locale("")
 * 2. Try from the LANG environment variable
 * 3. Default to "US" if both attempts failed
 *
 * @return the current country code of where the process is running
 */
static std::string getCountryCode() {
    // 1. Try from std::locale("")
    {
        std::locale loc("");
        std::string name = loc.name();
        if (name != "C" && name != "POSIX") {
            std::string cc = extractCountryCode(name);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 2. If we failed, try the LANG environment variable
    {
        const char *lang = std::getenv("LANG");
        if (lang && *lang) {
            std::string locale_str(lang);
            std::string cc = extractCountryCode(locale_str);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 3. Default to "US" if both attempts failed
    return "US";
}

/**
 * @brief Creates credentials for use in creating a certificate.
 *
 * This function retrieves the credentials required for creation of an X.509
 * certificate.  It uses supplied parameters, environment variables, current logged-on username/hostname,
 * or the current country code of where the process is running to obtain the common name,
 * organization, organizational unit, and country needed for the subject of the certificate.
 *
 * - If username is not specified in either the commandline or environment then use the logged in username
 * - If organization is not specified in either the commandline or environment then use the hostname of the machine
 * - If organizational unit is not specified in either the commandline or environment then leave blank
 * - If country is not specified in either the commandline or environment then use the current
 *   country code of where the process is running or default to "US"
 *
 * @param config The ConfigStd object containing the environment variables optionally overridden by commandline parameters and pre-filled with default values.
 * @param for_client true if getting credentials for a client
 * @return A structure containing the credentials required for creation of a certificate.
 */
std::shared_ptr<Credentials> AuthNStd::getCredentials(const client::Config &config, bool for_client) const {
    const auto &std_config = dynamic_cast<const ConfigStd &>(config);

    log_debug_printf(auth,
                     "\n******************************************\nDefault, "
                     "Standard Authenticator: %s\n",
                     "Begin acquisition");

    auto std_credentials = std::make_shared<DefaultCredentials>();

    // Set the expiration time of the certificate
    time_t now = time(nullptr);
    std_credentials->not_before = now;
    std_credentials->not_after = now + (std_config.cert_validity_mins * 60);

    // Should not be empty as defaults to username
    if (!std_config.name.empty()) {
        std_credentials->name = for_client ? std_config.name : std_config.server_name;
    }

    // Should not be empty as defaults to hostname
    if (!std_config.organization.empty()) {
        std_credentials->organization = for_client ? std_config.organization : std_config.server_organization;
    }

    if (!std_config.organizational_unit.empty()) {
        std_credentials->organization_unit = for_client ? std_config.organizational_unit : std_config.server_organizational_unit;
    }

    if (!std_config.country.empty()) {
        std_credentials->country = for_client ? std_config.country : std_config.server_country;
    } else {
        std_credentials->country = getCountryCode();
    }

    log_debug_printf(auth, "Standard Credentials retrieved for: %s@%s\n", std_credentials->name.c_str(), std_credentials->organization.c_str());

    return std_credentials;
}

/**
 * @brief Create a PVStructure that corresponds to the ccr parameter of a Certificate Creation Request (CCR).
 *
 * This request will be sent to the PVACMS through the default channel (PV Access) and will be used to create the certificate.
 *
 * @param credentials the credentials that describe the subject of the certificate
 * @param key_pair the public/private key to be used in the certificate, only public key is used
 * @param usage certificate usage
 * @return A managed shared CertCreationRequest object.
 */
std::shared_ptr<CertCreationRequest> AuthNStd::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                         const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const {
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);

    return cert_creation_request;
};

/**
 * @brief Verify the Certificate Creation Request (CCR)
 *
 * There is no verification for the Standard authenticator.  Just return true.
 *
 * All certificates generated by the standard authenticator normally require administrator approval
 * before becoming valid.  They are issued in PENDING_APPROVAL status.  An administrator must use the
 * PUT request to the status PV included as an extension in the certificate to approve the certificate.
 *
 * @param ccr the Certificate Creation Request (CCR)
 * @return true if the Certificate Creation Request (CCR) is valid
 */
bool AuthNStd::verify(const Value ccr) const { return true; }

}  // namespace certs
}  // namespace pvxs
