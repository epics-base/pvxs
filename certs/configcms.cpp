/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configcms.h"

#include <pvxs/log.h>

DEFINE_LOGGER(_logname, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigCms::fromCmsEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};
    PickOne pick_another_one{defs, true};

    // EPICS_KEYCHAIN ( default the private key to use the same file and password )
    if (pickone({"EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_cert_filename = pickone.val);

        // EPICS_CA_KEYCHAIN_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_PVACMS_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pick_another_one.val;
        } else if (pickone.name == "EPICS_PVAS_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pick_another_one.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            tls_cert_password = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    }

    // EPICS_PVAS_TLS_STOP_IF_NO_CERT
    if (pickone({"EPICS_PVACMS_TLS_STOP_IF_NO_CERT", "EPICS_PVAS_TLS_STOP_IF_NO_CERT"})) {
        tls_stop_if_no_cert = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_ACF
    if (pickone({"EPICS_PVACMS_ACF"})) {
        ensureDirectoryExists(ca_acf_filename = pickone.val);
    }

    // EPICS_PVACMS_DB
    if (pickone({"EPICS_PVACMS_DB"})) {
        ensureDirectoryExists(ca_db_filename = pickone.val);
    }

    // EPICS_CA_KEYCHAIN
    if (pickone({"EPICS_CA_KEYCHAIN"})) {
        ensureDirectoryExists(ca_cert_filename = pickone.val);

        // EPICS_CA_KEYCHAIN_PWD_FILE
        if (pickone.name == "EPICS_CA_KEYCHAIN") {
            pick_another_one({"EPICS_CA_KEYCHAIN_PWD_FILE"});
            std::string password_filename = pick_another_one.val;
            ensureDirectoryExists(password_filename);
            try {
                ca_cert_password = getFileContents(password_filename);
            } catch (std::exception &e) {
                log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
            }
        }
    }

    // EPICS_ADMIN_TLS_KEYCHAIN
    if (pickone({"EPICS_ADMIN_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(admin_cert_filename = pickone.val);

        // EPICS_CA_KEYCHAIN_PWD_FILE
        if (pickone.name == "EPICS_ADMIN_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_ADMIN_TLS_KEYCHAIN_PWD_FILE"});
            std::string password_filename = pick_another_one.val;
            ensureDirectoryExists(password_filename);
            try {
                ca_cert_password = getFileContents(password_filename);
            } catch (std::exception &e) {
                log_err_printf(_logname, "error reading password file: %s. %s", password_filename.c_str(), e.what());
            }
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

    // EPICS_CA_COUNTRY
    if (pickone({"EPICS_CA_COUNTRY"})) {
        ca_country = pickone.val;
    }

    // EPICS_PVACMS_CERT STATUS VALIDITY MINS
    if (pickone({"EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS"})) {
        try {
            cert_status_validity_mins = parseTo<uint64_t>(pickone.val);
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

    // EPICS_PVACMS_REQUIRE_SERVER_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_GATEWAY_APPROVAL", "EPICS_PVACMS_REQUIRE_SERVER_APPROVAL", "EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"})) {
        cert_gateway_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION
    if (pickone({"EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION"})) {
        cert_status_subscription = parseTo<bool>(pickone.val);
    }
}

}  // namespace certs
}  // namespace pvxs
