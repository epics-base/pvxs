/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnkrb.h"

#include <cstring>
#include <stdexcept>
#include <string>

#ifdef __APPLE__
#include <GSS/gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#include <CLI/CLI.hpp>

#include <pvxs/config.h>

#include "authregistry.h"
#include "certfilefactory.h"
#include "configkrb.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"
#include "certstatusfactory.h"

DEFINE_LOGGER(auth, "pvxs.auth.krb");

namespace pvxs {
namespace certs {

int readParameters(int argc, char *argv[], ConfigKrb &config, bool &verbose, bool &debug, uint16_t &cert_usage) {
    auto program_name = argv[0];
    bool show_version{false}, help{false};
    std::string usage{"client"};

    CLI::App app{"authnkrb - Secure PVAccess with Kerberos Authentication"};

    // Define options
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `hybrid`");

    app.add_option("-s,--validator-service", config.krb_validator_service, "Specify kerberos validator service.  Default `pvacms`");
    app.add_option("-r,--realm", config.krb_realm, "Specify the kerberos realm.  Default `EPICS.ORG`");

    CLI11_PARSE(app, argc, argv);

    if (help) {
        std::cout << "authnkrb - Secure PVAccess with Kerberos Authentication\n"
                  << std::endl
                  << "Generates client, server, or hybrid certificates based on the kerberos authentication method. \n"
                  << "Uses current kerberos ticket to create certificates with the same validity as the ticket.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options]                          Create certificate\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "options:\n"
                  << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|hybrid.  Default `client`\n"
                  << "  (-s | --validator-service) <service-name>  Specify kerberos validator service.  Default `pvacms`\n"
                  << "  (-r | --realm) <krb-realm>                 Specify the kerberos realm.  Default `EPICS.ORG`\n"
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

    return 0;
}

}  // namespace security
}  // namespace pvxs

using namespace pvxs::certs;

/**
 * @brief Main function for the authnkrb tool
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return the exit status
 */
int main(int argc, char *argv[]) {
    pvxs::logger_config_env();
    bool retrieved_credentials{false};

    try {
        auto config = ConfigKrb::fromEnv();

        bool verbose{false}, debug{false};
        uint16_t cert_usage{pvxs::ssl::kForClient};

        auto parse_result = readParameters(argc, argv, config, verbose, debug, cert_usage);
        if (parse_result) exit(parse_result);

        if (verbose) logger_level_set("pvxs.auth.krb*", pvxs::Level::Info);
        if (debug) logger_level_set("pvxs.auth.krb*", pvxs::Level::Debug);

        // Standard authenticator
        AuthNKrb authenticator{};
        authenticator.init(config);

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
    }
    return 0;
}
