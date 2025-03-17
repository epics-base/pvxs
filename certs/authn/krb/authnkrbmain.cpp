/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <CLI/CLI.hpp>

#include "authnkrb.h"
#include "authregistry.h"
#include "configkrb.h"
#include "openssl.h"
#include "p12filefactory.h"

namespace pvxs {
namespace certs {

/**
 * @brief Define the options for the authnkrb tool
 *
 * This function defines the options for the authnkrb tool.
 *
 * @param app the CLI::App object to add the options to
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param daemon_mode the daemon mode flag to set daemon mode
 * @param show_version the show version flag to show version and exit
 * @param help the help flag to show this help message and exit
 * @param add_config_uri the add config uri flag to add a config uri to the generated certificate
 * @param usage the certificate usage client, server, or hybrid
 */
void defineOptions(CLI::App &app, ConfigKrb &config, bool &verbose, bool &debug, bool &daemon_mode, bool &force, bool &show_version, bool &help, bool &add_config_uri,
                   std::string &usage) {
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");
    app.add_flag("--force", force, "Force overwrite if certificate exists.");

    app.add_flag("-D,--daemon", daemon_mode, "Daemon mode");
    app.add_flag("--add-config-uri", add_config_uri, "Add a config uri to the generated certificate");
    app.add_option("--config-uri-base", config.config_uri_base, "Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `hybrid`");

    app.add_option("--krb-validator", config.krb_validator, "Specify kerberos validator name.  Default `pvacms`");
    app.add_option("--krb-realm", config.krb_realm, "Specify the kerberos realm.  If not specified we'll take it from the ticket");
}

/**
 * @brief Show the help message for the authnkrb tool
 *
 * This function shows the help message for the authnkrb tool.
 *
 * @param program_name the program name
 */
void showHelp(const char *const program_name) {
    std::cout << "authnkrb - Secure PVAccess Kerberos Authenticator\n"
              << std::endl
              << "Generates client, server, or hybrid certificates based on the kerberos Authenticator. \n"
              << "Uses current kerberos ticket to create certificates with the same validity as the ticket.\n"
              << std::endl
              << "usage:\n"
              << "  " << program_name << " [options]                         Create certificate\n"
              << "  " << program_name << " (-h | --help)                     Show this help message and exit\n"
              << "  " << program_name << " (-V | --version)                  Print version and exit\n"
              << std::endl
              << "options:\n"
              << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|hybrid.  Default `client`\n"
              << "        --krb-validator <service-name>       Specify kerberos validator name.  Default `pvacms`\n"
              << "        --krb-realm <krb-realm>              Specify the kerberos realm.  If not specified we'll take it from the ticket\n"
              << "  (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`\n"
              << "        --add-config-uri                     Add a config uri to the generated certificate\n"
              << "        --config-uri-base <config_uri_base>  Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`\n"
              << "        --force                              Force overwrite if certificate exists\n"
              << "  (-v | --verbose)                           Verbose mode\n"
              << "  (-d | --debug)                             Debug mode\n"
              << std::endl;
}

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
int readParameters(const int argc, char *argv[], ConfigKrb &config, bool &verbose, bool &debug, uint16_t &cert_usage, bool &daemon_mode, bool &force) {
    const auto program_name = argv[0];
    bool show_version{false}, help{false}, add_config_uri{false};
    std::string usage{"client"};

    CLI::App app{"authnkrb - Secure PVAccess Kerberos Authenticator"};

    defineOptions(app, config, verbose, debug, daemon_mode, force, show_version, help, add_config_uri, usage);

    CLI11_PARSE(app, argc, argv);

    // The built-in help from CLI11 is pretty lame, so we'll do our own
    // Make sure we update this help text when options change
    if (help) {
        showHelp(program_name);
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
        if (config.tls_keychain_file.empty()) {
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
    return runAuthenticator<ConfigKrb, AuthNKrb>(argc, argv, [](ConfigKrb &config, AuthNKrb &auth) {
        if (config.krb_realm.empty()) {
            config.krb_realm = auth.getRealm();
        }
    });
}
