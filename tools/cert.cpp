/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdlib>
#include <iostream>
#include <list>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <termios.h>
#endif
#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/sslinit.h>

#include <CLI/CLI.hpp>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatusmanager.h"
#include "p12filefactory.h"

using namespace pvxs;

namespace {

DEFINE_LOGGER(certslog, "pvxs.certs.tool");

#if !defined(_WIN32) && !defined(_MSC_VER)
void setEcho(const bool enable) {
    termios tty{};
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}
#endif
}  // namespace

enum CertAction { STATUS, APPROVE, DENY, REVOKE };
std::string actionToString(const CertAction &action) {
    return action == STATUS ? "Get Status" : action == APPROVE ? "Approve" : action == REVOKE ? "Revoke" : "Deny";
}
int readParameters(const int argc, char *argv[], const char *program_name, client::Config &conf, bool &approve, bool &revoke, bool &deny, bool &debug,
                   bool &password_flag, bool &verbose, std::string &cert_file, std::string &issuer_serial_string) {
    bool show_version{false}, help{false};

    // Argument configuration
    CLI::App app{"Certificate Management Utility for PVXS"};
    app.set_help_flag("", "");  // deactivate built-in help

    // Add a positional argument
    app.add_option("cert_id", issuer_serial_string)->required(false);

    // Define flags
    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose);
    app.add_flag("-d,--debug", debug);
    app.add_flag("-p,--password", password_flag);
    app.add_flag("-V,--version", show_version);

    // Define options
    app.add_option("-w,--timeout", conf.request_timeout_specified);
    app.add_option("-f,--file", cert_file, "The keychain file to read if no Certificate ID specified");

    // Action flags in mutually exclusive group
    app.add_flag("-A,--approve", approve);
    app.add_flag("-R,--revoke", revoke);
    app.add_flag("-D,--deny", deny);

    CLI11_PARSE(app, argc, argv);

    if (help) {
        std::cout << "Certificate management utility for PVXS\n"
                  << std::endl
                  << "Gets the STATUS of a certificate, REVOKES a certificate, or APPROVES or DENIES a pending certificate approval.\n"
                  << std::endl
                  << "  Get certificate status from serial number: The certificate ID is specified as <issuer>:<serial>, \n"
                  << "  where <issuer> is the first 8 hex digits of the subject key identifier of the issuer and <serial>\n"
                  << "  is the serial number of the certificate. e.g. 27975e6b:7246297371190731775.\n"
                  << std::endl
                  << "  Get certificate status from keychain file: The keychain file must be a PKCS#12 file.\n"
                  << std::endl
                  << "  APPROVAL and DENIAL of pending certificate approval requests: Can only be made by administrators.\n"
                  << std::endl
                  << "  REVOCATION of a certificate: Can only be made by an administrator.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options] <cert_id> Get certificate status\n"
                  << "  " << program_name << " [file_options] [options] (-f | --file) <cert_file>\n"
                  << "                                             Get certificate information from the specified cert file\n"
                  << "  " << program_name << " [options] (-A | --approve) <cert_id>\n"
                  << "                                             APPROVE pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-D | --deny) <cert_id>  DENY pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-R | --revoke) <cert_id>\n"
                  << "                                             REVOKE certificate (ADMIN ONLY)\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "file_options:\n"
                  << "  (-p | --password)                          Prompt for password\n"
                  << "\n"
                  << "options:\n"
                  << "  (-w | --timeout) <timout_secs>             Operation timeout in seconds.  Default 5.0s\n"
                  << "  (-d | --debug)                             Debug mode: Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\"\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << std::endl;
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            exit(10);
        }
        std::cout << version_information;
        exit(0);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    try {
        ossl::sslInit();
        logger_config_env();
        auto conf = client::Config::fromEnv();
        auto program_name = argv[0];

        // Variables to store options
        CertAction action{STATUS};
        bool approve{false}, revoke{false}, deny{false}, debug{false}, password_flag{false}, verbose{false};
        std::string cert_file, password, issuer_serial_string;

        auto parse_result =
            readParameters(argc, argv, program_name, conf, approve, revoke, deny, debug, password_flag, verbose, cert_file, issuer_serial_string);
        if (parse_result) exit(parse_result);

        if (password_flag && cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 1;
        }

        if (!cert_file.empty() && (approve || revoke || deny)) {
            log_err_printf(certslog, "Error: -I, -A, -R, or -D cannot be used with -f.%s", "\n");
            return 2;
        }

        // Handle the flags after parsing
        if (debug) logger_level_set("pvxs.*", Level::Debug);
        if (password_flag) {
            std::cout << "Enter password: ";
#if !defined(_WIN32) && !defined(_MSC_VER)
            setEcho(false);
#endif
            std::getline(std::cin, password);
#if !defined(_WIN32) && !defined(_MSC_VER)
            setEcho(true);
#endif
            std::cout << std::endl;
        }

        if (approve) {
            action = APPROVE;
        } else if (revoke)
            action = REVOKE;
        else if (deny) {
            action = DENY;
        } else {
            conf.tls_disabled = true;
        }

        auto client = conf.build();

        if (verbose) std::cout << "Effective config\n" << conf;

        std::list<std::shared_ptr<client::Operation>> ops;

        epicsEvent done;

        std::string cert_id;

        if (!cert_file.empty()) {
            try {
                auto cert_data = certs::IdFileFactory::create(cert_file, password)->getCertDataFromFile();
                std::string config_id{};
                try {
                    config_id = certs::CertStatusManager::getConfigPvFromCert(cert_data.cert);
                } catch (...) {
                }

                std::cout << "Certificate Details: " << std::endl
                          << "============================================" << std::endl
                          << ossl::ShowX509{cert_data.cert.get()} << std::endl
                          << (config_id.empty() ? "" : "Config URI     : " + config_id + "\n") << "--------------------------------------------\n"
                          << std::endl;
                cert_id = certs::CertStatusManager::getStatusPvFromCert(cert_data.cert);
            } catch (std::exception &e) {
                std::cout << "Online Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Not configured: " << e.what() << std::endl;
                return 0;
            }
        } else {
            cert_id = "CERT:STATUS:" + issuer_serial_string;
        }

        try {
            if (action != STATUS) {
                std::cout << actionToString(action) << " ==> " << cert_id;
            }
            Value result;
            switch (action) {
                case STATUS:
                    result = client.get(cert_id).exec()->wait(conf.request_timeout_specified);
                    break;
                case APPROVE:
                    result = client.put(cert_id).set("state", "APPROVED").exec()->wait(conf.request_timeout_specified);
                    break;
                case DENY:
                    result = client.put(cert_id).set("state", "DENIED").exec()->wait(conf.request_timeout_specified);
                    break;
                case REVOKE:
                    result = client.put(cert_id).set("state", "REVOKED").exec()->wait(conf.request_timeout_specified);
                    break;
            }
            Indented I(std::cout);
            if (result) {
                std::cout << "Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Certificate ID: " << cert_id.substr(cert_id.rfind(':') - 8) << std::endl
                          << "Status        : " << result["state"].as<std::string>() << std::endl
                          << "Status Issued : " << result["ocsp_status_date"].as<std::string>() << std::endl
                          << "Status Expires: " << result["ocsp_certified_until"].as<std::string>() << std::endl;
                if (result["status.value.index"].as<uint32_t>() == certs::REVOKED) {
                    std::cout << "Revocation Date: " << result["ocsp_revocation_date"].as<std::string>() << std::endl;
                }
                std::cout << "--------------------------------------------\n" << std::endl;
            } else if (action != STATUS)
                std::cout << " ==> Completed Successfully\n";
        } catch (std::exception &e) {
            std::cout << std::endl;
            log_err_printf(certslog, "%s\n", e.what());
            return 4;
        }

    } catch (std::exception &e) {
        log_err_printf(certslog, "Error: %s%s", e.what(), "\n");
        return 5;
    }
}
