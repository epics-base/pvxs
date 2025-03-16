/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstring>
#include <stdexcept>
#include <string>

#include "authnkrb.h"

#ifdef __APPLE__
#include <GSS/gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#include <pvxs/config.h>
#include <pvxs/sslinit.h>

#include <CLI/CLI.hpp>

#include "authregistry.h"
#include "certfilefactory.h"
#include "certstatusfactory.h"
#include "configkrb.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"

DEFINE_LOGGER(auth, "pvxs.auth.krb");

namespace pvxs {
namespace certs {

/*
 * @brief Read the command line parameters
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param cert_usage the certificate usage client, server, or hybrid
 * @return the exit status 0 if successful, non-zero if an error occurs and we should exit
 */
int readParameters(const int argc, char *argv[], ConfigKrb &config, bool &verbose, bool &debug, uint16_t &cert_usage, bool &daemon_mode) {
    const auto program_name = argv[0];
    bool show_version{false}, help{false}, add_config_uri{false};
    std::string usage{"client"};

    CLI::App app{"authnkrb - Secure PVAccess Kerberos Authenticator"};

    // Define options
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");

    app.add_flag("-D,--daemon", daemon_mode, "Daemon mode");
    app.add_flag("--add-config-uri", add_config_uri, "Add a config uri to the generated certificate");
    app.add_option("--config-uri-base", config.config_uri_base, "Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `hybrid`");

    app.add_option("--krb-validator", config.krb_validator, "Specify kerberos validator name.  Default `pvacms`");
    app.add_option("--krb-realm", config.krb_realm, "Specify the kerberos realm.  If not specified we'll take it from the ticket");

    CLI11_PARSE(app, argc, argv);

    // The built-in help from CLI11 is pretty lame, so we'll do our own
    // Make sure we update this help text when options change
    if (help) {
        std::cout << "authnkrb - Secure PVAccess Kerberos Authenticator\n"
                  << std::endl
                  << "Generates client, server, or hybrid certificates based on the kerberos Authenticator. \n"
                  << "Uses current kerberos ticket to create certificates with the same validity as the ticket.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options]                          Create certificate\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "options:\n"
                  << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|hybrid.  Default `client`\n"
                  << "  --krb-validator <service-name>             Specify kerberos validator name.  Default `pvacms`\n"
                  << "  --krb-realm <krb-realm>                    Specify the kerberos realm.  If not specified we'll take it from the ticket\n"
                  << "  (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`\n"
                  << "  --add-config-uri                           Add a config uri to the generated certificate\n"
                  << "  --config-uri-base <config_uri_base>        Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << "  (-d | --debug)                             Debug mode\n"
                  << std::endl;
        exit(0);
    }

    // Show the version and exit
    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            return 10;
        }
        std::cout << version_information;
        exit(0);
    }

    // Set the certificate usage based on the command line parameters
    if (usage == "server") {
        cert_usage = ssl::kForServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create server certificates" << std::endl;
            return 10;
        }
    } else if (usage == "client") {
        cert_usage = ssl::kForClient;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVA_TLS_KEYCHAIN environment variable to create client certificates" << std::endl;
            return 11;
        }
    } else if (usage == "hybrid") {
        cert_usage = ssl::kForClientAndServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create hybrid certificates" << std::endl;
            return 12;
        }
    } else {
        std::cerr << "Usage must be one of `client`, `server`, or `hybrid`: " << usage << std::endl;
        return 13;
    }

    return 0;
}

CertData getCertificate(bool &retrieved_credentials, ConfigKrb config, uint16_t cert_usage, const AuthNKrb &authenticator, const std::string &tls_keychain_file,
                        const std::string &tls_keychain_pwd) {
    CertData cert_data{};

    // Get the kerberos credentials (from the kerberos ticket)
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

        // Create a certificate creation request using the credentials and key pair
        auto cert_creation_request = authenticator.createCertCreationRequest(credentials, key_pair, cert_usage);

        log_debug_printf(auth, "CCR created for: %s Authenticator\n", authenticator.type_.c_str());

        // Attempt to create a certificate with the certificate creation request
        auto p12_pem_string = authenticator.processCertificateCreationRequest(cert_creation_request, config.request_timeout_specified);

        // If the certificate was created successfully,
        if (!p12_pem_string.empty()) {
            log_debug_printf(auth, "Cert generated by PVACMS and successfully received: %s\n", p12_pem_string.c_str());

            // Attempt to write the certificate and private key
            // to a cert file protected by the configured password
            auto file_factory = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd, key_pair, nullptr, nullptr, p12_pem_string);
            file_factory->writeIdentityFile();

            // Read file back for info, and to check that it was written correctly
            cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
            auto serial_number = CertStatusFactory::getSerialNumber(cert_data.cert);
            auto issuer_id = CertStatus::getIssuerId(cert_data.ca);

            // Log the certificate information to console
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
    return cert_data;
}

}  // namespace certs
}  // namespace pvxs

using namespace pvxs::certs;

/**
 * @brief Main function for the authnkrb tool
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return the exit status
 */
int main(const int argc, char *argv[]) {
    pvxs::logger_config_env();
    bool retrieved_credentials{false}, daemon_mode{false};

    try {
        pvxs::ossl::sslInit();

        auto config = ConfigKrb::fromEnv();

        bool verbose{false}, debug{false};
        uint16_t cert_usage{pvxs::ssl::kForClient};

        const auto parse_result = readParameters(argc, argv, config, verbose, debug, cert_usage, daemon_mode);
        if (parse_result) exit(parse_result);

        if (verbose) logger_level_set("pvxs.auth.krb*", pvxs::Level::Info);
        if (debug) logger_level_set("pvxs.auth.krb*", pvxs::Level::Debug);

        // Kerberos authenticator
        AuthNKrb authenticator{};

        // If the realm is not set, use the realm from the kerberos ticket
        if (config.krb_realm.empty()) config.krb_realm = authenticator.getRealm();

        // Add configuration to authenticator
        authenticator.configure(config);

        // Log the effective config
        if (verbose) {
            std::cout << "Effective config\n" << config << std::endl;
        }

        // Get the keychain file and password based on the certificate usage
        const std::string tls_keychain_file = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_file : config.tls_keychain_file;
        const std::string tls_keychain_pwd = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_pwd : config.tls_keychain_pwd;

        // Get the Standard authenticator credentials
        CertData cert_data;
        try {
            if (daemon_mode) {
                auto new_cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
                const auto now = time(nullptr);
                const auto not_after_time = CertFactory::getNotAfterTimeFromCert(new_cert_data.cert);
                if (not_after_time > now) {
                    cert_data = std::move(new_cert_data);
                }
            }
        } catch (std::exception &) {
        }

        if (!cert_data.cert) cert_data = getCertificate(retrieved_credentials, config, cert_usage, authenticator, tls_keychain_file, tls_keychain_pwd);

        if (daemon_mode) {
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
    }
    return -1;
}
