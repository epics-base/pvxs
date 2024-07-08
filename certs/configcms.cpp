/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <pvxs/log.h>

#include "configcms.h"

DEFINE_LOGGER(_logname, "pvxs.certs.config.cms");

namespace pvxs {
namespace certs {

void ConfigCms::fromCmsEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_KEYCHAIN
    if (pickone({"EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_keychain_filename = pickone.val);

        // EPICS_CA_KEYCHAIN_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_PVACMS_KEYCHAIN") {
            pickone({"EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVAS_KEYCHAIN") {
            pickone({"EPICS_PVACS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            tls_keychain_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname,
                           "error reading password file: %s. %s",
                           password_filename.c_str(),
                           e.what());
        }
    }

    // EPICS_PVAS_TLS_STOP_IF_NO_CERT
    if (pickone({"EPICS_PVACMS_TLS_STOP_IF_NO_CERT"})) {
        tls_stop_if_no_cert = parseTo<bool>(pickone.val);
    }

    // EPICS_CA_ACF
    if (pickone({"EPICS_CA_ACF"})) {
        ensureDirectoryExists(ca_acf_filename = pickone.val);
    }

    // EPICS_CA_DB
    if (pickone({"EPICS_CA_DB"})) {
        ensureDirectoryExists(ca_db_filename = pickone.val);
    }

    // EPICS_CA_KEYCHAIN
    if (pickone({"EPICS_CA_KEYCHAIN", "EPICS_PVACMS_TLS_KEYCHAIN",
                 "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(ca_keychain_filename = pickone.val);

        // EPICS_CA_KEYCHAIN_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_CA_KEYCHAIN") {
            pickone({"EPICS_CA_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVACMS_KEYCHAIN") {
            pickone({"EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVAS_KEYCHAIN") {
            pickone({"EPICS_PVACS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            ca_keychain_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname,
                           "error reading password file: %s. %s",
                           password_filename.c_str(),
                           e.what());
        }
    }

    // EPICS_CA_NAME
    if (pickone({"EPICS_CA_NAME"})) {
        ca_name = pickone.val;
    }

    // EPICS_CA_ORGANIZATION
    if (pickone({"EPICS_CA_ORGANIZATION"})) {
        ca_organization = pickone.val;
    }

    // EPICS_CA_ORGANIZATIONAL_UNIT
    if (pickone({"EPICS_CA_ORGANIZATIONAL_UNIT"})) {
        ca_organizational_unit = pickone.val;
    }

    // EPICS_PVACMS_PRE_EXPIRY_MINS
    if (pickone({"EPICS_PVACMS_PRE_EXPIRY_MINS"})) {
        try {
            cert_pre_expiry_mins = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(_logname,
                           "%s invalid integer : %s",
                           pickone.name.c_str(),
                           e.what());
        }
    }

    // EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"})) {
        cert_client_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_REQUIRE_SERVER_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_SERVER_APPROVAL"})) {
        cert_server_require_approval = parseTo<bool>(pickone.val);
    }
}

} // certs
} // pvxs
