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

void ConfigAuthN::fromAuthNEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_STD_NAME
    if (pickone({"EPICS_PVA_AUTH_STD_NAME"})) {
        name = pickone.val;
    } else {
        // Try to get username
        char username[PVXS_X509_AUTH_USERNAME_MAX];
        if (osiGetUserName(username, PVXS_X509_AUTH_USERNAME_MAX) == osiGetUserNameSuccess) {
            username[PVXS_X509_AUTH_USERNAME_MAX - 1] = '\0';
            name = username;
        } else {
            name = "nobody";
        }
    }

    // EPICS_AUTH_STD_ORG
    if (pickone({"EPICS_PVA_AUTH_STD_ORG"})) {
        organization = pickone.val;
    } else {
        // Get hostname or IP address (Organization)
        char hostname[PVXS_X509_AUTH_HOSTNAME_MAX];
        if (!!gethostname(hostname, PVXS_X509_AUTH_HOSTNAME_MAX)) {
            // If no hostname then try to get IP address
            strcpy(hostname, getIPAddress().c_str());
        }
        organization = hostname;
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_srv_keychain_file = pickone.val);
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "server.p12";
        ensureDirectoryExists(tls_srv_keychain_file = filename);
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"})) {
        tls_srv_keychain_pwd = getFileContents(pickone.val);
    }
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
std::string ConfigAuthN::getIPAddress() {
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


}  // namespace certs
}  // namespace pvxs
