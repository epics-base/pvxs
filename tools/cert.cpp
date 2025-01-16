/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <list>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>
#include <termios.h>

#include <pvxs/client.h>
#include <pvxs/log.h>

#include <CLI/CLI.hpp>
#include <cstdlib>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatusmanager.h"
#include "p12filefactory.h"

using namespace pvxs;

namespace {

DEFINE_LOGGER(certslog, "pvxs.certs.tool");

void setEcho(bool enable) {
    struct termios tty {};
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

// Helper function to convert string to enum
Value::Fmt::format_t stringToFormat(const std::string& formatStr) {
    if (formatStr == "delta") {
        return Value::Fmt::Delta;
    } else if (formatStr == "tree") {
        return Value::Fmt::Tree;
    } else {
        throw std::invalid_argument("Invalid format type");
    }
}

}  // namespace

enum CertAction { STATUS, APPROVE, DENY, REVOKE };
std::string actionToString(CertAction& action) {
    return (action == STATUS    ? "Get Status"
            : action == APPROVE ? "Approve"
            : action == REVOKE  ? "Revoke"
                                : "Deny");
}
int readParameters(int argc, char* argv[], const char *program_name, client::Config &conf, CertAction &action, Value::Fmt::format_t &format,
                    bool &approve, bool &revoke, bool &deny, bool &debug, bool &password_flag, bool &verbose,
                    std::string &cert_file, std::string &password, std::string &format_str, std::string &issuer_serial_string,
                    uint64_t &arrLimit) {

    bool show_version{false}, help{false};

    // Argument configuration
    CLI::App app{"Certificate Management Utility for PVXS"};
    app.set_help_flag("", ""); // deactivate built-in help

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
    app.add_option("-#,--limit", arrLimit)->default_val(20);
    app.add_option("-F,--format", format_str);

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
                  <<  "usage:\n"
                  <<  "  " << program_name << " [options] <cert_id>                Get certificate status\n"
                  <<  "  " << program_name << " [options] -f, --file <cert_file>   Get certificate information from the specified cert file\n"
                  <<  "  " << program_name << " [options] -A, --approve <cert_id>  APPROVE pending certificate approval request (ADMIN ONLY)\n"
                  <<  "  " << program_name << " [options] -D, --deny <cert_id>     DENY pending certificate approval request (ADMIN ONLY)\n"
                  <<  "  " << program_name << " [options] -R, --revoke <cert_id>   REVOKE certificate (ADMIN ONLY)\n"
                  <<  "  " << program_name << " -h, --help                         Show this help message and exit\n"
                  <<  "  " << program_name << " -V, --verbose                      Print version and exit\n"
                  << std::endl
                  <<  "options:\n"
                  <<  "  -w, --timeout FLOAT [5]\n"
                  <<  "                                             Operation timeout in seconds.  Default 5.0s\n"
                  <<  "  -p, --password                             Prompt for password\n"
                  <<  "  -F, --format [ delta | tree ]              Output format mode: delta (default), or tree\n"
                  <<  "  -#, --limit <max_elements>                 Maximum number of elements to print for each array field. Set to\n"
                  <<  "                                             zero 0 for unlimited.  Default 20\n"
                  <<  "  -d, --debug                                Debug mode: Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\"\n"
                  <<  "  -v                                         Verbose mode\n"
                  << std::endl;
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            exit(10);
        }
        std::cout << pvxs::version_information;
        exit(0);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    try {
        logger_config_env();  // from $PVXS_LOG
        auto conf = client::Config::fromEnv();
        auto program_name = argv[0];

        // Variables to store options
        CertAction action{STATUS};
        Value::Fmt::format_t format = Value::Fmt::Delta;
        bool approve{false}, revoke{false}, deny{false}, debug{false}, password_flag{false}, verbose{false};
        std::string cert_file, password, format_str, issuer_serial_string;
        uint64_t arrLimit = 20;

        auto parse_result = readParameters(argc, argv, program_name, conf, action, format, approve, revoke, deny, debug, password_flag,
                                           verbose, cert_file, password, format_str, issuer_serial_string, arrLimit);
        if (parse_result) exit(parse_result);


        if (password_flag && cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 1;
        }

        if (!cert_file.empty() && (approve || revoke || deny)) {
            log_err_printf(certslog, "Error: -I, -A, -R, or -D cannot be used with -f.%s", "\n");
            return 2;
        }

        if (!format_str.empty()) {
            format = stringToFormat(format_str);
        }

        // Handle the flags after parsing
        if (debug) logger_level_set("pvxs.*", Level::Debug);
        if (password_flag) {
            std::cout << "Enter password: ";
            setEcho(false);
            std::getline(std::cin, password);
            setEcho(true);
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
                cert_id = certs::CertStatusManager::getStatusPvFromCert(cert_data.cert);
            } catch (std::exception& e) {
                log_err_printf(certslog, "Unable to get cert from cert file: %s\n", e.what());
                return 3;
            }
        } else {
            cert_id = "CERT:STATUS:" + issuer_serial_string;
        }

        try {
            std::cout << actionToString(action) << " ==> " << cert_id << "\n";
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
            if (result)
                std::cout << result.format().format(format).arrayLimit(arrLimit);
            else if (action != STATUS)
                std::cout << "Success\n";
        } catch (std::exception& e) {
            log_err_printf(certslog, "Unable to %s ==> %s\n", actionToString(action).c_str(), cert_id.c_str());
            log_err_printf(certslog, "%s\n", e.what());
            return 4;
        }

    } catch (std::exception& e) {
        log_err_printf(certslog, "Error: %s%s", e.what(), "\n");
        return 5;
    }
}
