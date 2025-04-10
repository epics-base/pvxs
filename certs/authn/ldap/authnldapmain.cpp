/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <CLI/CLI.hpp>

#include "authnldap.h"
#include "authregistry.h"
#include "configldap.h"
#include "openssl.h"
#include "p12filefactory.h"

namespace pvxs {
namespace certs {

/**
 * @brief Prompt the user for a password
 *
 * This function prompts the user for a password and returns the password.
 *
 * @param prompt the prompt to display to the user
 */
std::string promptPassword(const std::string &prompt) {
    // getpass() prints the prompt and reads a password from /dev/tty without echo.
    char *pass = getpass(prompt.c_str());
    if (pass == nullptr) {
        throw std::runtime_error("Error reading password");
    }
    return std::string(pass);
}

/**
 * @brief Define the options for the authnldap tool
 *
 * This function defines the options for the authnldap tool.
 *
 * @param app the CLI::App object to add the options to
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param daemon_mode the daemon mode flag to set daemon mode
 * @param show_version the show version flag to show version and exit
 * @param help the help flag to show this help message and exit
 * @param add_config_uri the add config uri flag to add a config uri to the generated certificate
 * @param name the ldap name
 * @param organization the ldap organization
 * @param usage the certificate usage client, server, or hybrid
 */

void defineOptions(CLI::App &app, ConfigLdap &config, bool &verbose, bool &debug, bool &daemon_mode, bool &force, bool &show_version, bool &help, bool &add_config_uri,
                   std::string &usage, std::string &name, std::string &organization) {
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

    app.add_option("-n,--name", name, "Specify the LDAP user name e.g. name e.g. becomes uid=name.  Defaults to logged in username");
    app.add_option("-o,--organization", organization, "Specify the organization e.g. epics.org e.g. becomes dc=epics, dc=org.  Defaults to hostname");
    app.add_option("-p,--password", config.ldap_account_password, "Specify the LDAP account password");

    app.add_option("--ldap-host", config.ldap_host, "Specify LDAP host.  Default localhost");
    app.add_option("--ldap-port", config.ldap_port, "Specify LDAP port.  Default 389");
}

void showHelp(const char * const program_name) {
    std::cout << "authnldap - Secure PVAccess LDAP Authenticator\n"
        << std::endl
        << "Generates client, server, or hybrid certificates based on the LDAP credentials. \n"
        << std::endl
        << "usage:\n"
        << "  " << program_name << " [options]                        Create certificate in PENDING_APPROVAL state\n"
        << "  " << program_name << " (-h | --help)                    Show this help message and exit\n"
        << "  " << program_name << " (-V | --version)                 Print version and exit\n"
        << std::endl
        << "options:\n"
        << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|hybrid.  Default `client`\n"
        << "  (-n | --name) <name>                       Specify LDAP username for common name in the certificate.\n"
        << "                                             e.g. name ==> LDAP: uid=name, ou=People ==> Cert: CN=name\n"
        << "                                             Default <logged-in-username>\n"
        << "  (-o | --organization) <organization>       Specify LDAP org for organization in the certificate.\n"
        << "                                             e.g. epics.org ==> LDAP: dc=epics, dc=org ==> Cert: O=epics.org\n"
        << "                                             Default <hostname>\n"
        << "  (-p | --password) <name>                   Specify LDAP password. If not specified will prompt for password\n"
        << "        --ldap-host <hostname>               LDAP server host\n"
        << "        --ldap-port <port>                   LDAP serever port\n"
        << "  (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`\n"
        << "        --add-config-uri                     Add a config uri to the generated certificate\n"
        << "        --config-uri-base <config_uri_base>  Specifies the config URI base to add to a certificate.  Default `CERT:CONFIG`\n"
        << "        --force                              Force overwrite if certificate exists\n"
        << "  (-s | --no-status)                         Request that status checking not be required for this certificate\n"
        << "  (-v | --verbose)                           Verbose mode\n"
        << "  (-d | --debug)                             Debug mode\n"
        << std::endl;
}

int readParameters(int argc, char *argv[], ConfigLdap &config, bool &verbose, bool &debug, uint16_t &cert_usage, bool &daemon_mode, bool &force) {
    const auto program_name = argv[0];
    bool show_version{false}, help{false}, add_config_uri{false};
    std::string usage{"client"}, name, organization;

    CLI::App app{"authnldap - Secure PVAccess LDAP Authenticator"};

    defineOptions(app, config, verbose, debug, daemon_mode, force, show_version, help, add_config_uri, usage, name, organization);

    CLI11_PARSE(app, argc, argv);

    if (help) {
        showHelp(program_name);
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            return 10;
        }
        std::cout << version_information;
        exit(0);
    }

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

    // Pull out command line args to override config values
    if ( !name.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.name = name; break;
            case ssl::kForServer: config.server_name = name; break;
            default: config.name = config.server_name = name; break;
        }
    }
    if ( !organization.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.organization = organization; break;
            case ssl::kForServer: config.server_organization = organization; break;
            default: config.organization = config.server_organization = organization; break;
        }
    }

    const auto name_to_use = cert_usage == ssl::kForClient ? config.name : config.server_name;
    const auto organization_to_use = cert_usage == ssl::kForClient ? config.organization : config.server_organization;

    if (config.ldap_account_password.empty()) {
        config.ldap_account_password = promptPassword(SB() << "Enter password for " << name_to_use << "@" << organization_to_use << ": ");
    }

    return 0;
}

}  // namespace certs
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
    return runAuthenticator<ConfigLdap, AuthNLdap>(argc, argv);
}
