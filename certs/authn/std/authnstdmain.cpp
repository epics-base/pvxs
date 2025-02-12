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

int readParameters(int argc, char *argv[], ConfigStd &config, bool &verbose, bool &debug, uint16_t &cert_usage) {
    auto program_name = argv[0];
    bool show_version{false}, help{false};
    std::string usage{"client"};

    CLI::App app{"authnstd - Secure PVAccess with Standard Authentication"};

    // Define options
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `hybrid`");

    app.add_option("-n,--name", config.name, "Specify CA keychain password file location");
    app.add_option("-o,--organization", config.organization, "Specify the CA's name. Used if we need to create a root certificate");
    app.add_option("--ou", config.organizational_unit, "Specify the CA's Organization. Used if we need to create a root certificate");
    app.add_option("-c,--country", config.country, "Specify the CA's Organization Unit. Used if we need to create a root certificate");

    CLI11_PARSE(app, argc, argv);

    if (help) {
        std::cout << "authnstd - Secure PVAccess with Standard Authentication\n"
                  << std::endl
                  << "Generates client, server, or hybrid certificates based on the standard authentication method. \n"
                  << "Uses specified parameters to create certificates that require administrator APPROVAL before becoming VALID.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options]                          Create certificate in PENDING_APPROVAL state\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "options:\n"
                  << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|hybrid.  Default `client`\n"
                  << "  (-n | --name) <name>                       Specify common name of the certificate. Default <logged-in-username>\n"
                  << "  (-o | --organization) <organization>       Specify organisation name for the certificate. Default <hostname>\n"
                  << "  --ou <org-unit>                            Specify organisational unit for the certificate. Default <blank>\n"
                  << "  (-c | --country) <country>                 Specify country for the certificate. Default locale setting if detectable otherwise `US`\n"
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

}  // namespace certs
}  // namespace pvxs

using namespace pvxs::certs;

/**
 * @brief Main function for the authnstd tool
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
        auto config = ConfigStd::fromEnv();

        bool verbose{false}, debug{false};
        uint16_t cert_usage{pvxs::ssl::kForClient};

        auto parse_result = readParameters(argc, argv, config, verbose, debug, cert_usage);
        if (parse_result) exit(parse_result);

        if (verbose) logger_level_set("pvxs.auth.std*", pvxs::Level::Info);
        if (debug) logger_level_set("pvxs.auth.std*", pvxs::Level::Debug);

        // Standard authenticator
        AuthNStd authenticator{};
        // Add configuration to authenticator
        authenticator.configure(config);
        const std::string tls_keychain_file = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_file : config.tls_keychain_file;
        const std::string tls_keychain_pwd = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_pwd : config.tls_keychain_pwd;

        if (auto credentials = authenticator.getCredentials(config)) {
            std::shared_ptr<KeyPair> key_pair;
            log_debug_printf(auth, "Credentials retrieved for: %s authenticator\n", authenticator.type_.c_str());
            retrieved_credentials = true;

            // Get key pair
            try {
                // Check if the key pair exists
                key_pair = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getKeyFromFile();
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
                auto file_factory = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd,
                                                          key_pair, nullptr, nullptr, p12_pem_string);
                file_factory->writeIdentityFile();

                // Read file back for info
                auto cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
                auto serial_number = CertStatusFactory::getSerialNumber(cert_data.cert);
                auto issuer_id = CertStatus::getIssuerId(cert_data.ca);

                std::string from = std::ctime(&credentials->not_before);
                std::string to = std::ctime(&credentials->not_after);
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
        return 0;
    } catch (std::exception &e) {
        if (retrieved_credentials) log_warn_printf(auth, "%s\n", e.what());
        else log_err_printf(auth, "%s\n", e.what());
    }
    return -1;
}
