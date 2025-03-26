/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configauthn.h"

#include <authnstd.h>
#include <ifaddrs.h>
#include <osiProcess.h>

struct ifaddrs;

namespace pvxs {
namespace certs {

/**
 * @brief Get the base Authenticator configuration from the environment
 *
 * This will get the username, organization, and other information from the
 * environment and store it in the ConfigAuthN object.
 *
 * @param defs the map of environment variables that is required by PickOne
 */
void ConfigAuthN::fromAuthEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    char username[PVXS_X509_AUTH_USERNAME_MAX];
    std::string retrieved_username;

    // Try to get username
    if (osiGetUserName(username, PVXS_X509_AUTH_USERNAME_MAX) == osiGetUserNameSuccess) {
        username[PVXS_X509_AUTH_USERNAME_MAX - 1] = '\0';
        retrieved_username = username;
    } else {
        retrieved_username = "nobody";
    }

    // Get hostname or IP address (Organization)
    char hostname[PVXS_X509_AUTH_HOSTNAME_MAX];
    if (!!gethostname(hostname, PVXS_X509_AUTH_HOSTNAME_MAX)) {
        // If no hostname then try to get IP address
        strcpy(hostname, getIPAddress().c_str());
    }
    const std::string retrieved_organization = hostname;

    // EPICS_PVA_AUTH_NAME, EPICS_PVAS_AUTH_NAME
    name = pickone({"EPICS_PVA_AUTH_NAME"}) ? pickone.val : retrieved_username;
    server_name = pickone({"EPICS_PVAS_AUTH_NAME", "EPICS_PVA_AUTH_NAME"}) ? pickone.val : retrieved_username;

    // EPICS_PVA_AUTH_NO_STATUS, EPICS_PVAS_AUTH_NO_STATUS
    no_status = pickone({"EPICS_PVA_AUTH_NO_STATUS", "EPICS_PVAS_AUTH_NO_STATUS"}) && pickone.val == "YES";

    // EPICS_PVA_AUTH_ORGANIZATION, EPICS_PVAS_AUTH_ORGANIZATION
    organization = pickone({"EPICS_PVA_AUTH_ORGANIZATION"}) ? pickone.val : retrieved_organization;
    server_organization = pickone({"EPICS_PVAS_AUTH_ORGANIZATION", "EPICS_PVA_AUTH_ORGANIZATION"}) ? pickone.val : retrieved_organization;

    // EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT, EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT
    if (pickone({"EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"})) organizational_unit = pickone.val;
    if (pickone({"EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT", "EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"})) server_organizational_unit = pickone.val;

    // EPICS_PVA_AUTH_COUNTRY, EPICS_PVAS_AUTH_COUNTRY
    if (pickone({"EPICS_PVA_AUTH_COUNTRY"})) country = pickone.val;
    if (pickone({"EPICS_PVAS_AUTH_COUNTRY", "EPICS_PVA_AUTH_COUNTRY"})) server_country = pickone.val;

    // Fixup keychain files to make sure we have default values even when empty
    if (tls_keychain_file.empty()) {
        tls_keychain_file = SB() << config_home << OSI_PATH_SEPARATOR << "client.p12";
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN", "EPICS_PVA_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_srv_keychain_file = pickone.val);
        if (pickone.name == "EPICS_PVAS_TLS_KEYCHAIN") {
            // EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE
            if (pickone({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"})) tls_srv_keychain_pwd = getFileContents(pickone.val);
        } else
            tls_srv_keychain_pwd = tls_keychain_pwd;
    } else {
        const std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "server.p12";
        ensureDirectoryExists(tls_srv_keychain_file = filename);
    }
}

/**
 * Update the definitions with the generic authenticator definitions.
 *
 * This function is called from each authenticator to update the definitions with the generic authenticator definitions.
 * It updates the definitions with the name, server name, organization, server organization,
 * organizational unit, server organizational unit, country, server country, and TLS keychain file.
 *
 * @param defs the definitions to update with the generic authenticator definitions
 */
void ConfigAuthN::updateDefs(defs_t &defs) const {
    Config::updateDefs(defs);
    defs["EPICS_PVA_AUTH_NAME"] = name;
    defs["EPICS_PVAS_AUTH_NAME"] = server_name;
    defs["EPICS_PVA_AUTH_ORGANIZATION"] = organization;
    defs["EPICS_PVAS_AUTH_ORGANIZATION"] = server_organization;
    defs["EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"] = organizational_unit;
    defs["EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT"] = server_organizational_unit;
    defs["EPICS_PVA_AUTH_COUNTRY"] = country;
    defs["EPICS_PVAS_AUTH_COUNTRY"] = server_country;
    defs["EPICS_PVAS_TLS_KEYCHAIN"] = tls_srv_keychain_file;
    if (!tls_srv_keychain_pwd.empty()) defs["EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"] = "<password read>";
}

/**
 * @brief Get the IP address of the current process' host.
 *
 * This will return the IP address based on the following rules.
 * - It will look through all the network interfaces and will skip local and
 *   self-assigned addresses.
 * - Then it will select any public IP address.
 * - If no public IP addresses are found then it will return the first private
 *   IP address that it finds.
 *
 * @return the IP address of the current process' host
 */
std::string ConfigAuthN::getIPAddress() {
    ifaddrs *if_addr_struct = nullptr;
    std::string chosen_ip;
    std::string private_ip;

    getifaddrs(&if_addr_struct);

    // Regex to match local and self-assigned addresses
    const std::regex local_address_pattern(R"(^(127\.)|(169\.254\.))");
    // Regex to match private addresses
    const std::regex private_address_pattern(R"(^(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.))");

    // Iterate through all the network interfaces
    for (const ifaddrs *ifa = if_addr_struct; ifa != nullptr; ifa = ifa->ifa_next) {
        // Skip if the interface address is not valid
        if (!ifa->ifa_addr) {
            continue;
        }

        // Check if the address is an IPv4 address
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // Get the address
            const void *tmp_addr_ptr = &reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr)->sin_addr;
            char address_buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmp_addr_ptr, address_buffer, INET_ADDRSTRLEN);

            // Skip local or self-assigned address. If it's a private address,
            // remember it.  Otherwise, use it as the chosen IP address.
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

    // Free the memory allocated for the network interface addresses
    if (if_addr_struct != nullptr) freeifaddrs(if_addr_struct);

    // If no public IP addresses were found, use the first private IP that was
    // found.
    if (chosen_ip.empty()) {
        chosen_ip = private_ip;
    }

    // Return the chosen IP address
    return chosen_ip;
}

}  // namespace certs
}  // namespace pvxs
