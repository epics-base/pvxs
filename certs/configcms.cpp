/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configcms.h"

#include <authregistry.h>

#include <pvxs/log.h>

DEFINE_LOGGER(cert_cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigCms::fromCmsEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};
    PickOne pick_another_one{defs, true};

    // EPICS_PVACMS_TLS_KEYCHAIN ( default the private key to use the same file and password )
    if (pickone({"EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_keychain_file = pickone.val);

        // EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE
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
            tls_keychain_pwd = getFileContents(password_filename);
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "pvacms.p12";
        ensureDirectoryExists(tls_keychain_file = filename);
    }

    // EPICS_PVAS_TLS_STOP_IF_NO_CERT
    if (pickone({"EPICS_PVACMS_TLS_STOP_IF_NO_CERT", "EPICS_PVAS_TLS_STOP_IF_NO_CERT"})) {
        tls_stop_if_no_cert = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_ACF
    if (pickone({"EPICS_PVACMS_ACF"})) {
        ensureDirectoryExists(pvacms_acf_filename = pickone.val);
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "pvacms.acf";
        ensureDirectoryExists(pvacms_acf_filename = filename);
    }

    // EPICS_PVACMS_DB
    if (pickone({"EPICS_PVACMS_DB"})) {
        ensureDirectoryExists(certs_db_filename = pickone.val);
    } else {
        std::string filename = SB() << data_home << OSI_PATH_SEPARATOR << "certs.db";
        ensureDirectoryExists(filename);
        certs_db_filename = filename;
    }

    // EPICS_CERT_AUTH_TLS_KEYCHAIN

    if (pickone({"EPICS_CERT_AUTH_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(cert_auth_keychain_file = pickone.val);

        // EPICS_CERT_AUTH_TLS_KEYCHAIN_PWD_FILE
        if (pickone.name == "EPICS_CERT_AUTH_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_CERT_AUTH_TLS_KEYCHAIN_PWD_FILE"});
            std::string password_filename = pick_another_one.val;
            ensureDirectoryExists(password_filename);
            try {
                cert_auth_keychain_pwd = getFileContents(password_filename);
            } catch (std::exception &e) {
                log_err_printf(cert_cfg, "error reading password file: %s. %s", password_filename.c_str(), e.what());
            }
        }
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "cert_auth.p12";
        ensureDirectoryExists(cert_auth_keychain_file = filename);
    }
    // EPICS_ADMIN_TLS_KEYCHAIN
    if (pickone({"EPICS_ADMIN_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(admin_keychain_file = pickone.val);

        // EPICS_ADMIN_TLS_KEYCHAIN_PWD_FILE
        if (pickone.name == "EPICS_ADMIN_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_ADMIN_TLS_KEYCHAIN_PWD_FILE"});
            std::string password_filename = pick_another_one.val;
            ensureDirectoryExists(password_filename);
            try {
                admin_keychain_pwd = getFileContents(password_filename);
            } catch (std::exception &e) {
                log_err_printf(cert_cfg, "error reading password file: %s. %s", password_filename.c_str(), e.what());
            }
        }
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "admin.p12";
        ensureDirectoryExists(admin_keychain_file = filename);
    }

    // EPICS_CERT_AUTH_NAME
    if (pickone({"EPICS_CERT_AUTH_NAME"})) {
        cert_auth_name = pickone.val;
    }

    // EPICS_CERT_AUTH_ORGANIZATION
    if (pickone({"EPICS_CERT_AUTH_ORGANIZATION", "EPICS_PVAS_AUTH_ORGANIZATION", "EPICS_PVA_AUTH_ORGANIZATION"})) {
        cert_auth_organization = pickone.val;
    }

    // EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT
    if (pickone({"EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT", "EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT", "EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"})) {
        cert_auth_organizational_unit = pickone.val;
    }

    // EPICS_CERT_AUTH_COUNTRY
    if (pickone({"EPICS_CERT_AUTH_COUNTRY", "EPICS_PVAS_AUTH_COUNTRY", "EPICS_PVA_AUTH_COUNTRY"})) {
        cert_auth_country = pickone.val;
    }

    // EPICS_PVACMS_CERT STATUS VALIDITY MINS
    if (pickone({"EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS"})) {
        try {
            cert_status_validity_mins = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid integer : %s", pickone.name.c_str(), e.what());
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

    // EPICS_PVACMS_REQUIRE_HYBRID_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_HYBRID_APPROVAL", "EPICS_PVACMS_REQUIRE_SERVER_APPROVAL", "EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"})) {
        cert_hybrid_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION
    if (pickone({"EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION"})) {
        cert_status_subscription = parseTo<bool>(pickone.val);
    }
}

/**
 * Update the definitions with the PVACMS specific definitions.
 *
 * This function is called from PVACMS to update the definitions with the PVACMS specific definitions.
 * It updates the definitions with the TLS stop if no cert, the ACF file, the certs database file, the certificate authority keychain file,
 * the admin keychain file, the certificate authority name, the certificate authority organization, the certificate authority organizational unit,
 * the certificate authority country, the certificate validity minutes, the client require approval, the server require approval,
 * the hybrid require approval, and the certificate status subscription.
 *
 * It also adds any defs for any registered authn methods
 *
 * @param defs the definitions to update with the PVACMS specific definitions
 */
void ConfigCms::updateDefs(defs_t &defs) const {
    Config::updateDefs(defs);
    defs["EPICS_PVACMS_TLS_STOP_IF_NO_CERT"] = tls_stop_if_no_cert ? "YES" : "NO";
    defs["EPICS_PVACMS_ACF"] = pvacms_acf_filename;
    defs["EPICS_PVACMS_DB"] = certs_db_filename;
    defs["EPICS_CERT_AUTH_TLS_KEYCHAIN"] = cert_auth_keychain_file;
    defs["EPICS_ADMIN_TLS_KEYCHAIN"] = admin_keychain_file;
    defs["EPICS_CERT_AUTH_NAME"] = cert_auth_name;
    defs["EPICS_CERT_AUTH_ORGANIZATION"] = defs["EPICS_PVAS_AUTH_ORGANIZATION"] = defs["EPICS_PVA_AUTH_ORGANIZATION"] = cert_auth_organization;
    defs["EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT"] = defs["EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT"] = defs["EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"] =
        cert_auth_organizational_unit;
    defs["EPICS_CERT_AUTH_COUNTRY"] = defs["EPICS_PVAS_AUTH_COUNTRY"] = defs["EPICS_PVAS_AUTH_COUNTRY"] = cert_auth_country;
    defs["EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS"] = std::to_string(cert_status_validity_mins);
    defs["EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"] = cert_client_require_approval ? "YES" : "NO";
    defs["EPICS_PVACMS_REQUIRE_SERVER_APPROVAL"] = cert_server_require_approval ? "YES" : "NO";
    defs["EPICS_PVACMS_REQUIRE_HYBRID_APPROVAL"] = cert_hybrid_require_approval ? "YES" : "NO";
    defs["EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION"] = cert_status_subscription ? "YES" : "NO";

    // Add any defs for any registered authn methods
    for (auto &authn_entry : AuthRegistry::getRegistry()) authn_entry.second->updateDefs(defs);
}

}  // namespace certs
}  // namespace pvxs
