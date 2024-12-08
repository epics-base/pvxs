/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnstd.h"

#include <ifaddrs.h>
#include <osiProcess.h>

#include <pvxs/log.h>

#include "certfilefactory.h"
#include "configstd.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"

DEFINE_LOGGER(auths, "pvxs.certs.auth.std");

namespace pvxs {
namespace certs {

void usage(const char *argv0) {
    std::cerr << "Usage: " << argv0
              << " <opts> \n"
                 "\n"
                 "  -v         Make more noise.\n"
                 "  -h         Show this help message and exit\n"
                 "  -d         Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make a lot of noise.\n"
                 "  -D         Run in Daemon mode.  Monitors and updates certs as needed\n"
                 "  -V         Show version and exit\n"
                 "  -u <use>   Usage. client, server, or gateway\n"
                 "  -N <name>  Name override the CN subject field\n"
                 "  -O <name>  Org override the O subject field\n"
                 "  -o <name>  Override the OU subject field\n"
                 "  \n"
                 "ENVIRONMENT VARIABLES: at least one mandatory variable must be set\n"
                 "\tEPICS_PVA_TLS_KEYCHAIN\t\t\tSet name and location of client certificate file (mandatory for clients)\n"
                 "\tEPICS_PVAS_TLS_KEYCHAIN\t\t\tSet name and location of server certificate file (mandatory for server)\n"
                 "\tEPICS_PVA_TLS_KEYCHAIN_PWD_FILE\t\tSet name and location of client certificate password file (optional)\n"
                 "\tEPICS_PVAS_TLS_KEYCHAIN_PWD_FILE\tSet name and location of server certificate password file (optional)\n"
                 "\tEPICS_PVA_TLS_PKEY\t\t\tSet name and location of client private key file (optional)\n"
                 "\tEPICS_PVAS_TLS_PKEY\t\t\tSet name and location of server private key file (optional)\n"
                 "\tEPICS_PVA_TLS_PKEY_PWD_FILE\t\tSet name and location of client private key password file (optional)\n"
                 "\tEPICS_PVAS_TLS_PKEY_PWD_FILE\t\tSet name and location of server private key password file (optional)\n"
                 ;
}

int readOptions(ConfigStd &config, int argc, char *argv[], bool &verbose, uint16_t &cert_usage, std::string &name, std::string &org, std::string &ou) {
    int opt;
    while ((opt = getopt(argc, argv, "vhVdu:N:O:o:D")) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            case 'D':
                usage(argv[0]);
                std::cerr << "\nNot yet supported: -" << char(optopt) << std::endl;
                return 4;
            case 'd':
                logger_level_set("pvxs.*", Level::Debug);
                break;
            case 'V':
                std::cout << pvxs::version_information;
                return 1;
            case 'u': {
                    std::string usage_str = optarg;
                    if ( usage_str == "gateway" || usage_str == "server") {
                        // Use the Server versions of environment variables
                        config.tls_cert_filename = config.tls_srv_cert_filename;
                        config.tls_private_key_filename = config.tls_srv_private_key_filename ;
                        config.tls_cert_password = config.tls_srv_cert_password;
                        config.tls_private_key_password = config.tls_srv_private_key_password ;
                        if (usage_str == "gateway") {
                            cert_usage = pvxs::ssl::kForClientAndServer;
                        } else if (usage_str == "server") {
                            cert_usage = pvxs::ssl::kForServer;
                        }
                    } else if (usage_str == "client") {
                        cert_usage = pvxs::ssl::kForClient;
                    } else {
                        usage(argv[0]);
                        std::cerr << "\nUnknown argument: -" << char(optopt) << " " << usage_str << std::endl;
                        return 2;
                    }
                }
                break;
            case 'N':
                name = optarg;
                break;
            case 'O':
                org = optarg;
                break;
            case 'o':
                ou = optarg;
                break;
            default:
                usage(argv[0]);
                std::cerr << "\nUnknown argument: -" << char(optopt) << std::endl;
                return 3;
        }
    }

    return 0;
}

/**
 * @brief Get the IP address of the current process' host.
 *
 * This will return the IP address based on the following rules.  It will
 * look through all the network interfaces and will skip local and self
 * assigned addresses.  Then it will select any public IP address.
 * if no public IP addresses are found then it will return
 * the first private IP address that it finds
 *
 * @return the IP address of the current process' host
 */
std::string getIPAddress() {
    struct ifaddrs *if_addr_struct = nullptr;
    struct ifaddrs *ifa;
    void *tmp_addr_ptr;
    std::string chosen_ip;
    std::string private_ip;

    getifaddrs(&if_addr_struct);

    std::regex local_address_pattern(R"(^(127\.)|(169\.254\.))");
    std::regex private_address_pattern(R"(^(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.))");

    for (ifa = if_addr_struct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // is a valid IPv4 Address
            tmp_addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
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
 * certificate.  It uses the hostname, and the username unless a process name
 * is provided in configuration, in which case it replaces the username.
 *
 * @param config The ConfigCommon object containing the optional process name.
 * @return A structure containing the credentials required for creation of
 * certificate.
 */
std::shared_ptr<Credentials> AuthStd::getCredentials(const ConfigStd &config) const {
    log_debug_printf(auths,
                     "\n******************************************\nDefault, "
                     "X.509 Authenticator: %s\n",
                     "Begin acquisition");

    auto x509_credentials = std::make_shared<DefaultCredentials>();

    // Set the expiration time of the certificate
    time_t now = time(nullptr);
    x509_credentials->not_before = now;
    x509_credentials->not_after = now + (config.cert_validity_mins*60);

    if (!config.device_name.empty()) {
        // Get Device Name (Organization)
        x509_credentials->organization = config.device_name;
    } else {
        // Get hostname or IP address (Organization)
        char hostname[PVXS_X509_AUTH_HOSTNAME_MAX];
        if (!!gethostname(hostname, PVXS_X509_AUTH_HOSTNAME_MAX)) {
            // If no hostname then try to get IP address
            strcpy(hostname, getIPAddress().c_str());
        }
        x509_credentials->organization = hostname;
    }

    // If process name is configured then use it instead of getting the username
    if (config.use_process_name) {
        x509_credentials->name = config.process_name;
    } else {
        // Try to get username
        char username[PVXS_X509_AUTH_USERNAME_MAX];
        if (osiGetUserName(username, PVXS_X509_AUTH_USERNAME_MAX) == osiGetUserNameSuccess) {
            username[PVXS_X509_AUTH_USERNAME_MAX - 1] = '\0';
            x509_credentials->name = username;
        } else {
            x509_credentials->name = "nobody";
        }
    }

    log_debug_printf(auths, "X.509 Credentials retrieved for: %s@%s\n", x509_credentials->name.c_str(), x509_credentials->organization.c_str());

    return x509_credentials;
};

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
std::shared_ptr<CertCreationRequest> AuthStd::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                        const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const {
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);

    return cert_creation_request;
};

bool AuthStd::verify(const Value ccr, std::function<bool(const std::string &, const std::string &)>) const { return true; }
}  // namespace certs
}  // namespace pvxs

using namespace pvxs::certs;
int main(int argc, char *argv[]) {
    pvxs::logger_config_env();

    bool verbose{false}, retrieved_credentials{false};
    uint16_t cert_usage{pvxs::ssl::kForClient};
    std::string name, org, ou;

    try {
        auto config = ConfigStd::fromEnv();
        std::shared_ptr<KeyPair> key_pair;

        // Read commandline options
        int exit_status;

        if ((exit_status = readOptions(config, argc, argv, verbose, cert_usage, name, org, ou))) {
            return exit_status - 1;
        }

        if ( config.tls_cert_filename.empty() ) {
            std::cerr << "You must set at least one mandatory environment variables to create certificates: " << std::endl;
            std::cerr << "\tEPICS_PVA_TLS_KEYCHAIN\t\t\tSet name and location of client certificate file (mandatory for clients)" << std::endl;
            std::cerr << "\tEPICS_PVAS_TLS_KEYCHAIN\t\t\tSet name and location of server certificate file (mandatory for server)" << std::endl;
            std::cerr << "\tEPICS_PVA_TLS_KEYCHAIN_PWD_FILE\t\tSet name and location of client certificate password file (optional)" << std::endl;
            std::cerr << "\tEPICS_PVAS_TLS_KEYCHAIN_PWD_FILE\tSet name and location of server certificate password file (optional)" << std::endl;
            std::cerr << "\tEPICS_PVA_TLS_PKEY\t\t\tSet name and location of client private key file (optional)" << std::endl;
            std::cerr << "\tEPICS_PVAS_TLS_PKEY\t\t\tSet name and location of server private key file (optional)" << std::endl;
            std::cerr << "\tEPICS_PVA_TLS_PKEY_PWD_FILE\t\tSet name and location of client private key password file (optional)" << std::endl;
            std::cerr << "\tEPICS_PVAS_TLS_PKEY_PWD_FILE\t\tSet name and location of server private key password file (optional)" << std::endl;
            return 10;
        }
        if (verbose) logger_level_set("pvxs.certs.auth.std*", pvxs::Level::Info);

        // Standard authenticator
        AuthStd authenticator;

        // Try to retrieve credentials from the authenticator
        if ( !name.empty() ) {
            config.use_process_name = true;
            config.process_name = name;
        }
        if ( !org.empty() ) {
            config.device_name = org;
        }
        if (auto credentials = authenticator.getCredentials(config)) {
            if ( !ou.empty() ) {
                credentials->organization_unit = ou;
            }
            log_debug_printf(auths, "Credentials retrieved for: %s authenticator\n", authenticator.type_.c_str());
            retrieved_credentials = true;

            // Get key pair
            try {
                // Check if the key pair exists
                key_pair = CertFileFactory::create(config.tls_private_key_filename, config.tls_private_key_password)->getKeyFromFile();
            } catch (std::exception &e) {
                // Make a new key pair file
                try {
                    log_warn_printf(auths, "%s\n", e.what());
                    key_pair = authenticator.createKeyPair(config);
                } catch (std::exception &e) {
                    throw(std::runtime_error(pvxs::SB() << "Error creating client key: " << e.what()));
                }
            }

            // Create a certificate creation request using the credentials and
            // key pair
            auto cert_creation_request = authenticator.createCertCreationRequest(credentials, key_pair, cert_usage);

            log_debug_printf(auths, "CCR created for: %s authentication type\n", authenticator.type_.c_str());

            // Attempt to create a certificate with the certificate creation
            // request
            auto p12_pem_string = authenticator.processCertificateCreationRequest(cert_creation_request);

            // If the certificate was created successfully,
            if (!p12_pem_string.empty()) {
                log_debug_printf(auths, "Cert generated by PVACMS and successfully received: %s\n", p12_pem_string.c_str());

                // Attempt to write the certificate and private key
                // to a cert file protected by the configured password
                auto file_factory =
                    CertFileFactory::create(
                      (cert_usage ? config.tls_cert_filename : config.tls_cert_filename), config.tls_cert_password, key_pair, nullptr, nullptr, "certificate", p12_pem_string);
                file_factory->writeIdentityFile();

                log_info_printf(auths, "New Cert File created using %s: %s\n", METHOD_STRING(authenticator.type_).c_str(), config.tls_cert_filename.c_str());
                std::cout << "Certificate created with " << ((authenticator.type_ == PVXS_DEFAULT_AUTH_TYPE) ? "basic" : authenticator.type_)
                          << " credentials and stored in:" << config.tls_cert_filename
                          << (config.tls_private_key_filename.empty() or config.tls_private_key_filename == config.tls_cert_filename ? "" : " and " + config.tls_private_key_filename)
                          << "\n\tNAME:\t" << credentials->name
                          << "\n\tORG:\t" << credentials->organization
                          << "\n\tOU:\t" << credentials->organization_unit
                          << "\n";

                // Create the root certificate if it is not already there so
                // that the user can trust it
                if (file_factory->writeRootPemFile(p12_pem_string)) {
                    return CertAvailability::OK;
                } else {
                    return CertAvailability::ROOT_CERT_INSTALLED;
                }
            }
        }
    } catch (std::exception &e) {
        if (retrieved_credentials) log_warn_printf(auths, "%s\n", e.what());
    }
    return 0;
}
