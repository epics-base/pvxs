/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configcms.h"

#include <pvxs/log.h>

DEFINE_LOGGER(_logname, "pvxs.certs.config.cms");

namespace pvxs {
namespace certs {

void ConfigCms::fromCmsEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_KEYCHAIN ( default the private key to use the same file and password )
    if (pickone({"EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_keychain_filename = tls_pkey_filename = pickone.val);

        // EPICS_CA_KEYCHAIN_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_PVACMS_TLS_KEYCHAIN") {
            pickone({"EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVAS_TLS_KEYCHAIN") {
            pickone({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pickone.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            tls_keychain_password = tls_pkey_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    }

    // EPICS_PKEY
    if (pickone({"EPICS_PVACMS_TLS_PKEY", "EPICS_PVAS_TLS_PKEY"})) {
        ensureDirectoryExists(tls_pkey_filename = pickone.val);

        // EPICS_CA_PKEY_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_PVACMS_TLS_PKEY") {
            pickone({"EPICS_PVACMS_TLS_PKEY_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVAS_TLS_PKEY") {
            pickone({"EPICS_PVAS_TLS_PKEY_PWD_FILE"});
            password_filename = pickone.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            tls_pkey_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
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
    if (pickone({"EPICS_CA_KEYCHAIN", "EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(ca_keychain_filename = ca_pkey_filename = pickone.val);

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
            ca_keychain_password = ca_pkey_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    }

    // EPICS_CA_PKEY
    if (pickone({"EPICS_CA_PKEY", "EPICS_PVACMS_TLS_PKEY", "EPICS_PVAS_TLS_PKEY"})) {
        ensureDirectoryExists(ca_pkey_filename = pickone.val);

        // EPICS_CA_PKEY_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_CA_PKEY") {
            pickone({"EPICS_CA_PKEY_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVACMS_PKEY") {
            pickone({"EPICS_PVACMS_TLS_PKEY_PWD_FILE"});
            password_filename = pickone.val;
        } else if (pickone.name == "EPICS_PVAS_PKEY") {
            pickone({"EPICS_PVACS_TLS_PKEY_PWD_FILE"});
            password_filename = pickone.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            ca_pkey_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
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
            log_err_printf(_logname, "%s invalid integer : %s", pickone.name.c_str(), e.what());
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

}  // namespace certs
}  // namespace pvxs
