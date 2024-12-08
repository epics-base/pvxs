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

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatusmanager.h"
#include "p12filefactory.h"
#include "pemfilefactory.h"

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

enum CertAction { STATUS, INSTALL, APPROVE, DENY, REVOKE };
std::string actionToString(CertAction& action) {
    return (action == STATUS    ? "Get Status"
            : action == INSTALL ? "Install Root Certificate"
            : action == APPROVE ? "Approve"
            : action == REVOKE  ? "Revoke"
                                : "Deny");
}

int main(int argc, char* argv[]) {
    try {
        logger_config_env();  // from $PVXS_LOG

        CLI::App app{"Certificate management utility for PVXS"};

        // Variables to store options
        double timeout{5.0};
        bool verbose{false};
        bool debug{false};
        bool show_version{false};
        bool password_flag{false};
        std::string cert_file, password;
        Value::Fmt::format_t format = Value::Fmt::Delta;
        std::string format_str;
        uint64_t arrLimit = 20;
        CertAction action{STATUS};
        bool install{false}, approve{false}, revoke{false}, deny{false};

        // Add a positional argument
        std::string issuer_serial_string;
        app.add_option("cert_id", issuer_serial_string, "Certificate ID")->required(false);

        // Define options
        app.add_option("-w,--timeout", timeout, "Operation timeout in seconds")->default_val(5.0);
        app.add_flag("-v,--verbose", verbose, "Make more noise");
        app.add_flag("-d,--debug", debug, "Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make a lot of noise.");
        app.add_option("-f,--file", cert_file, "The certificate file to read if no Certificate ID specified");
        app.add_flag("-p,--password", password_flag, "Prompt for password");
        app.add_flag("-V,--version", show_version, "Print version and exit.");
        app.add_option("-#,--limit", arrLimit, "Maximum number of elements to print for each array field. Set to zero 0 for unlimited")->default_val(20);
        app.add_option("-F,--format", format_str, "Output format mode: delta, tree");

        // Action flags in mutually exclusive group
        auto action_group = app.add_option_group("Actions")->required(false);
        action_group->add_flag("-I,--install", install, "Download and install the root certificate");
        action_group->add_flag("-A,--approve", approve, "APPROVE the certificate (ADMIN ONLY)");
        action_group->add_flag("-R,--revoke", revoke, "REVOKE the certificate (ADMIN ONLY)");
        action_group->add_flag("-D,--deny", deny, "DENY the pending certificate (ADMIN ONLY)");

        CLI11_PARSE(app, argc, argv);

        if (show_version) {
            if (argc > 2) {
                std::cerr << "Error: -V option cannot be used with any other options.\n";
                return 1;
            }
            std::cout << pvxs::version_information;
            return 0;
        }

        if (password_flag && cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 1;
        }

        if (!cert_file.empty() && (install || approve || revoke || deny)) {
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

        if (install) action = INSTALL;
        if (approve) action = APPROVE;
        if (revoke) action = REVOKE;
        if (deny) action = DENY;

        auto conf = client::Config::fromEnv();
        conf.request_timeout_specified = timeout;
        auto ctxt = conf.build();

        if (verbose) std::cout << "Effective config\n" << conf;

        std::list<std::shared_ptr<client::Operation>> ops;

        epicsEvent done;

        std::string cert_id, root_id;

        if (!cert_file.empty()) {
            try {
                auto cert_data = certs::IdFileFactory::create(cert_file, password)->getCertDataFromFile();
                cert_id = certs::CertStatusManager::getStatusPvFromCert(cert_data.cert);
            } catch (std::exception& e) {
                log_err_printf(certslog, "Unable to get cert from cert file: %s\n", e.what());
                return 3;
            }
        } else {
            if (action == INSTALL) {
                root_id = "CERT:ROOT";
            } else {
                cert_id = "CERT:STATUS:" + issuer_serial_string;
            }
        }

        try {
            if (action != INSTALL) std::cout << actionToString(action) << " ==> " << ((!root_id.empty()) ? root_id : cert_id) << "\n";
            switch (action) {
                case INSTALL: {
                    ops.push_back(ctxt.get(root_id)
                                      .result([root_id, &done](client::Result&& result) {
                                          Indented I(std::cout);
                                          auto value = result();
                                          uint64_t serial = value["serial"].as<uint64_t>();
                                          auto name = value["name"].as<std::string>();
                                          auto issuer = value["issuer"].as<std::string>();
                                          auto org = value["org"].as<std::string>();
                                          auto org_unit = value["org_unit"].as<std::string>();
                                          auto pem_string = value["cert"].as<std::string>();

                                          std::cout << "Installing Root CA Certificate"
                                                    << "\n\tNAME:\t\t\t" << name << "\n\tORGANIZATION:\t\t" << org << "\n\tORGANIZATIONAL UNIT:\t" << org_unit
                                                    << "\n\tISSUER:\t\t\t" << issuer << "\n\tSERIAL:\t\t\t" << serial << std::endl;

                                          certs::PEMFileFactory::createRootPemFile(pem_string, true);
                                          done.signal();
                                      })
                                      .exec());
                } break;
                case STATUS: {
                    ops.push_back(ctxt.get(cert_id)
                                      .result([cert_id, &done, format, arrLimit](client::Result&& result) {
                                          Indented I(std::cout);
                                          std::cout << result().format().format(format).arrayLimit(arrLimit);
                                          done.signal();
                                      })
                                      .exec());
                } break;
                case APPROVE: {
                    ops.push_back(ctxt.put(cert_id)
                                      .set("state", "APPROVED")
                                      .result([cert_id, &done, format, arrLimit](client::Result&& result) {
                                          Indented I(std::cout);
                                          if (result) std::cout << result().format().format(format).arrayLimit(arrLimit);
                                          done.signal();
                                      })
                                      .exec());
                } break;
                case DENY: {
                    ops.push_back(ctxt.put(cert_id)
                                      .set("state", "DENIED")
                                      .result([cert_id, &done, format, arrLimit](client::Result&& result) {
                                          Indented I(std::cout);
                                          if (result) std::cout << result().format().format(format).arrayLimit(arrLimit);
                                          done.signal();
                                      })
                                      .exec());
                } break;
                case REVOKE: {
                    ops.push_back(ctxt.put(cert_id)
                                      .set("state", "REVOKED")
                                      .result([cert_id, &done, format, arrLimit](client::Result&& result) {
                                          Indented I(std::cout);
                                          if (result) std::cout << result().format().format(format).arrayLimit(arrLimit);
                                          done.signal();
                                      })
                                      .exec());
                } break;
            }
        } catch (std::exception& e) {
            log_err_printf(certslog, "Unable to %s ==> %s %s", actionToString(action).c_str(), cert_id.c_str(), "\n");
            ctxt.close();
            return 3;
        }

        // expedite search after starting all requests
        ctxt.hurryUp();

        SigInt sig([&done]() { done.signal(); });

        bool waited = done.wait(timeout);
        ops.clear();  // implied cancel

        if (!waited) {
            log_err_printf(certslog, "Timeout%s", "\n");
            return 4;

        } else if (issuer_serial_string.empty()) {
            return 0;

        } else {
            if (verbose) log_err_printf(certslog, "Interrupted.%s", "\n");
            return 5;
        }
    } catch (std::exception& e) {
        log_err_printf(certslog, "Error: %s%s", e.what(), "\n");
        return 6;
    }
}
