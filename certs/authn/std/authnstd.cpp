/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnstd.h"

#include <ifaddrs.h>
#include <osiProcess.h>
#include <CLI/CLI.hpp>

#include <pvxs/log.h>

#include "authregistry.h"
#include "certfilefactory.h"
#include "configstd.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"
#include "certstatusfactory.h"

DEFINE_LOGGER(auth, "pvxs.auth.std");

namespace pvxs {
namespace certs {

struct AuthNStdRegistrar {
    AuthNStdRegistrar() { // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_DEFAULT_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNStd()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_std_registrar;

/**
 * @brief Extract the country code from a locale string
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
 * @brief Get the current country code of where the process is running
 * This returns the two-letter country code.  It is always upper case.
 * For example for the United States it returns US, and for France, FR.
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
 * @brief Get the IP address of the current process' host.
 *
 * This will return the IP address based on the following rules.  It will
 * look through all the network interfaces and will skip local and self-assigned
 * addresses.  Then it will select any public IP address.
 * if no public IP addresses are found then it will return
 * the first private IP address that it finds
 *
 * @return the IP address of the current process' host
 */
std::string getIPAddress() {
    ifaddrs *if_addr_struct = nullptr;
    std::string chosen_ip;
    std::string private_ip;

    getifaddrs(&if_addr_struct);

    std::regex local_address_pattern(R"(^(127\.)|(169\.254\.))");
    std::regex private_address_pattern(R"(^(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.))");

    for (ifaddrs *ifa = if_addr_struct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // is a valid IPv4 Address
            void *tmp_addr_ptr = &reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr)->sin_addr;
            char address_buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmp_addr_ptr, address_buffer, INET_ADDRSTRLEN);

            // Skip local or self-assigned address. If it's a private address,
            // remember it.
            if (!std::regex_search(address_buffer, local_address_pattern)) {
                if (std::regex_search(address_buffer, private_address_pattern)) {
                    if (private_ip.empty()) {
                        private_ip = address_buffer;
                    }
                } else {
                    chosen_ip = address_buffer;
                    break;  // If a public address is found, exit the loop
                }
            }
        }
    }
    if (if_addr_struct != nullptr) freeifaddrs(if_addr_struct);

    // If no public IP addresses were found, use the first private IP that was
    // found.
    if (chosen_ip.empty()) {
        chosen_ip = private_ip;
    }

    return chosen_ip;
}

/**
 * @brief Creates credentials for use in creating an X.509 certificate.
 *
 * This function retrieves the credentials required for creation of an X.509
 * certificate.  It uses supplied parameters or environment variables to
 * obtain the common name, organization, organizational unit, and country.
 *
 * If username is not specified then use the logged in username
 *
 * @param config The ConfigStd object containing the environment variables
 *               optionally overridden by commandline parameters.
 * @return A structure containing the credentials required for creation of
 * certificate.
 */
std::shared_ptr<Credentials> AuthNStd::getCredentials(const client::Config &config) const {
    const auto & std_config = dynamic_cast<const ConfigStd&>(config);

    log_debug_printf(auth,
                     "\n******************************************\nDefault, "
                     "Standard Authenticator: %s\n",
                     "Begin acquisition");

    auto std_credentials = std::make_shared<DefaultCredentials>();

    // Set the expiration time of the certificate
    time_t now = time(nullptr);
    std_credentials->not_before = now;
    std_credentials->not_after = now + (std_config.cert_validity_mins * 60);

    // If name is configured then use it instead of getting the username
    if (!std_config.name.empty()) {
        std_credentials->name = std_config.name;
    } else {
        // Try to get username
        char username[PVXS_X509_AUTH_USERNAME_MAX];
        if (osiGetUserName(username, PVXS_X509_AUTH_USERNAME_MAX) == osiGetUserNameSuccess) {
            username[PVXS_X509_AUTH_USERNAME_MAX - 1] = '\0';
            std_credentials->name = username;
        } else {
            std_credentials->name = "nobody";
        }
    }

    // If we've specified an organization then use it otherwise use the hostname or IP
    if (!std_config.organization.empty()) {
        std_credentials->organization = std_config.organization;
    } else {
        // Get hostname or IP address (Organization)
        char hostname[PVXS_X509_AUTH_HOSTNAME_MAX];
        if (!!gethostname(hostname, PVXS_X509_AUTH_HOSTNAME_MAX)) {
            // If no hostname then try to get IP address
            strcpy(hostname, getIPAddress().c_str());
        }
        std_credentials->organization = hostname;
    }

    if (!std_config.organizational_unit.empty()) {
        std_credentials->organization_unit = std_config.organizational_unit;
    }

    if (!std_config.country.empty()) {
        std_credentials->country = std_config.country;
    } else {
        std_credentials->country = getCountryCode();
    }

    log_debug_printf(auth, "Standard Credentials retrieved for: %s@%s\n", std_credentials->name.c_str(), std_credentials->organization.c_str());

    return std_credentials;
}

/**
 * Create a PVStructure that corresponds to the ccr parameter of a certificate
 * creation request. This request will be sent to the PVACMS through the default
 * channel (PVAccess) and will be used to create the certificate.
 *
 * This default certificate creation request does nothing more than the base
 * certificate creation request.
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
 * @brief Verify the certificate creation request
 *
 * There is no verification for the basic credentials.  Just return true.
 *
 * @param ccr the certificate creation request
 * @return true if the certificate creation request is valid
 */
bool AuthNStd::verify(const Value ccr, std::function<bool(const std::string &, const std::string &)>) const { return true; }

}  // namespace certs
}  // namespace pvxs

