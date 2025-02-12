/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnldap.h"

#include <cstring>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>

#include <pvxs/config.h>

#include "certstatusfactory.h"
#include "authregistry.h"
#include "certfilefactory.h"
#include "configldap.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"


DEFINE_LOGGER(auth, "pvxs.auth.ldap");

namespace pvxs {
namespace certs {

std::string promptPassword(const std::string &prompt) {
    // getpass() prints the prompt and reads a password from /dev/tty without echo.
    char *pass = getpass(prompt.c_str());
    if (pass == nullptr) {
        throw std::runtime_error("Error reading password");
    }
    return std::string(pass);
}

int readParameters(int argc, char *argv[], ConfigLdap &config, bool &verbose, bool &debug, uint16_t &cert_usage) {
    auto program_name = argv[0];
    bool show_version{false}, help{false};
    std::string usage{"client"};

    CLI::App app{"authnldap - Secure PVAccess with LDAP Authentication"};

    // Define options
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `hybrid`");

    app.add_option("-n,--name", config.name, "Specify the LDAP user name e.g. name e.g. becomes uid=name.  Defaults to logged in username");
    app.add_option("-o,--organization", config.organization, "Specify the organization e.g. epics.org e.g. becomes dc=epics, dc=org.  Defaults to hostname");
    app.add_option("-p,--password", config.ldap_account_password, "Specify the LDAP account password");

    app.add_option("--ldap-host", config.ldap_host, "Specify LDAP host.  Default localhost");
    app.add_option("--ldap-port", config.ldap_port, "Specify LDAP port.  Default 389");

    CLI11_PARSE(app, argc, argv);

    if (help) {
        std::cout << "authnldap - Secure PVAccess with LDAP Authentication\n"
                  << std::endl
                  << "Generates client, server, or hybrid certificates based on the LDAP credentials. \n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options]                          Create certificate in PENDING_APPROVAL state\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "options:\n"
                  << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|hybrid.  Default `client`\n"
                  << "  (-n | --name) <name>                       Specify LDAP username for common name in the certificate.\n"
                  << "                                             e.g. name ==> LDAP: uid=name, ou=People ==> Cert: CN=name\n"
                  << "                                             Default <logged-in-username>\n"
                  << "  (-o | --organization) <organization>      Specify LDAP org for organization in the certificate.\n"
                  << "                                             e.g. epics.org ==> LDAP: dc=epics, dc=org ==> Cert: O=epics.org\n"
                  << "                                             Default <hostname>\n"
                  << "  (-p | --password) <name>                   Specify LDAP password. If not specified will prompt for password\n"
                  << "  (     --ldap-host) <hostname>              LDAP server host\n"
                  << "  (     --ldap-port) <port>                  LDAP serever port\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << "  (-d | --debug)                             Debug mode\n"
                  << std::endl;
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            return 10;
        }
        std::cout << pvxs::version_information;
        exit(0);
    }

    if ( usage == "server" ) {
        cert_usage = pvxs::ssl::kForServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create server certificates" << std::endl;
            return 10;
        }
    } else if ( usage == "client" ) {
        cert_usage = pvxs::ssl::kForClient;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVA_TLS_KEYCHAIN environment variable to create client certificates" << std::endl;
            return 11;
        }
    } else if ( usage == "hybrid" ) {
        cert_usage = pvxs::ssl::kForClientAndServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create hybrid certificates" << std::endl;
            return 12;
        }
    } else {
        std::cerr
            << "Usage must be one of `client`, `server`, or `hybrid`: " << usage << std::endl;
        return 13;
    }

    if (config.ldap_account_password.empty()) {
        config.ldap_account_password = promptPassword(SB() << "Enter password for "<< config.name << "@" << config.organization << ": " );
    }

    return 0;
}
}  // namespace security
}  // namespace pvxs

using namespace pvxs::certs;

/**
 * @brief Main function for the authnldap tool
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return the exit status
 */
int main(int argc, char *argv[]) {
    pvxs::ossl::SSLContext::sslInit();
    pvxs::logger_config_env();
    bool retrieved_credentials{false};

    try {
        auto config = ConfigLdap::fromEnv();

        bool verbose{false}, debug{false};
        uint16_t cert_usage{pvxs::ssl::kForClient};

        auto parse_result = readParameters(argc, argv, config, verbose, debug, cert_usage);
        if (parse_result) exit(parse_result);

        if (verbose) logger_level_set("pvxs.auth.ldap*", pvxs::Level::Info);
        if (debug) logger_level_set("pvxs.auth.ldap*", pvxs::Level::Debug);

        // Standard authenticator
        AuthNLdap authenticator{};

        if (auto credentials = authenticator.getCredentials(config)) {
            std::shared_ptr<KeyPair> key_pair;
            log_debug_printf(auth, "Credentials retrieved for: %s authenticator\n", authenticator.type_.c_str());
            retrieved_credentials = true;

            // Get key pair
            try {
                // Check if the key pair exists
                key_pair = IdFileFactory::create(config.tls_keychain_file, config.tls_keychain_pwd)->getKeyFromFile();
            } catch (std::exception &e) {
                // Make a new key pair file
                try {
                    log_debug_printf(auth, "%s\n", e.what());
                    key_pair = IdFileFactory::createKeyPair();
                } catch (std::exception &new_e) {
                    throw std::runtime_error(pvxs::SB() << "Error creating client key: " << new_e.what());
                }
            }

            // Create a certificate creation request using the credentials and
            // key pair
            auto cert_creation_request = authenticator.createCertCreationRequest(credentials, key_pair, cert_usage);

            log_debug_printf(auth, "CCR created for: %s authentication type\n", authenticator.type_.c_str());

            // Attempt to create a certificate with the certificate creation
            // request
            auto p12_pem_string = authenticator.processCertificateCreationRequest(cert_creation_request, config.request_timeout_specified);

            // If the certificate was created successfully,
            if (!p12_pem_string.empty()) {
                log_debug_printf(auth, "Cert generated by PVACMS and successfully received: %s\n", p12_pem_string.c_str());

                // Attempt to write the certificate and private key
                // to a cert file protected by the configured password
                auto file_factory = IdFileFactory::create(config.tls_keychain_file, config.tls_keychain_pwd,
                                                          key_pair, nullptr, nullptr, p12_pem_string);
                file_factory->writeIdentityFile();

                // Read file back for info
                auto cert_data = IdFileFactory::create(config.tls_keychain_file, config.tls_keychain_pwd)->getCertDataFromFile();
                auto serial_number = CertStatusFactory::getSerialNumber(cert_data.cert);
                auto issuer_id = CertStatus::getIssuerId(cert_data.ca);

                std::string from = std::ctime(&credentials->not_before);
                std::string to = std::ctime(&credentials->not_after);
                log_info_printf(auth, "%s\n", (pvxs::SB() << "CERT_ID: " << issuer_id << ":" << serial_number).str().c_str());
                log_info_printf(auth, "%s\n", (pvxs::SB() << "TYPE: " << authenticator.type_).str().c_str());
                log_info_printf(auth, "%s\n", (pvxs::SB() << "OUTPUT TO: " << config.tls_keychain_file).str().c_str());
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
    } catch (std::exception &e) {
        if (retrieved_credentials) log_warn_printf(auth, "%s\n", e.what());
        else log_err_printf(auth, "%s\n", e.what());
    }
    return 0;
}
