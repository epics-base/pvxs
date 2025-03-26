/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <CLI/CLI.hpp>

#include "authnstd.h"
#include "authregistry.h"
#include "configstd.h"
#include "openssl.h"
#include "p12filefactory.h"

namespace pvxs {
namespace certs {

/**
 * @brief Define the options for the authnstd tool
 *
 * This function defines the options for the authnstd tool.
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
void defineOptions(CLI::App &app, ConfigStd &config, bool &verbose, bool &debug, bool &daemon_mode, bool &force, bool &show_version, bool &help, bool &add_config_uri,
                   std::string &usage) {
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");
    app.add_flag("--force", force, "Force overwrite if certificate exists.");
    app.add_flag("-s,--no-status", config.no_status, "Request that status checking not be required for this certificate. PVACMS may ignore this request if it is configured to require all certificates to have status checking");

    app.add_flag("-D,--daemon", daemon_mode, "Daemon mode");
    app.add_flag("--add-config-uri", add_config_uri, "Add a config uri to the generated certificate");
    app.add_option("--config-uri-base", config.config_uri_base, "Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`");

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `hybrid`");

    app.add_option("-t,--time", config.cert_validity_mins, "Duration of the certificate in minutes.  Default 30 days");

    app.add_option("-n,--name", config.name, "Specify Certificate's name");
    app.add_option("-o,--organization", config.organization, "Specify the Certificate's Organisation");
    app.add_option("--ou", config.organizational_unit, "Specify the Certificate's Organizational Unit");
    app.add_option("-c,--country", config.country, "Specify the Certificate's Country");
}

/**
 * @brief Show the help message for the authnstd tool
 *
 * This function shows the help message for the authnstd tool.
 *
 * @param program_name the program name
 */
void showHelp(const char *program_name) {
    std::cout << "authnstd - Secure PVAccess Standard Authenticator\n"
              << std::endl
              << "Generates client, server, or hybrid certificates based on the Standard Authenticator. \n"
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
              << "        --ou <org-unit>                      Specify organisational unit for the certificate. Default <blank>\n"
              << "  (-c | --country) <country>                 Specify country for the certificate. Default locale setting if detectable otherwise `US`\n"
              << "  (-t | --time) <minutes>                    Duration of the certificate in minutes\n"
              << "  (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`\n"
              << "        --add-config-uri                     Add a config uri to the generated certificate\n"
              << "        --config-uri-base <config_uri_base>  Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`\n"
              << "        --force                              Force overwrite if certificate exists\n"
              << "  (-s | --no-status)                         Request that status checking not be required for this certificate\n"
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
int readParameters(int argc, char *argv[], ConfigStd &config, bool &verbose, bool &debug, uint16_t &cert_usage, bool &daemon_mode, bool &force) {
    auto program_name = argv[0];
    bool show_version{false}, help{false}, add_config_uri{false};
    std::string usage{"client"};

    CLI::App app{"authnstd - Secure PVAccess Standard Authenticator"};

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
 * @brief Main function for the authnstd tool
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return the exit status
 */
int main(const int argc, char *argv[]) { return runAuthenticator<ConfigStd, AuthNStd>(argc, argv); }
