/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configcms.h"

std::unique_ptr<ConfigFactoryInterface> getConfigFactory() {
    struct ConfigCmsFactory : public ConfigFactoryInterface {
        std::unique_ptr<Config> create() override {
            // EPICS_PVAS_TLS_KEYCHAIN
            if (pickone({"EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN", "EPICS_PVA_TLS_KEYCHAIN"})) {
                self.ensureDirectoryExists(self.tls_keychain_filename = pickone.val);
                // EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE
                std::string password_filename;
                if (pickone.name == "EPICS_PVACMS_TLS_KEYCHAIN") {
                    pickone({"EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"});
                    password_filename = pickone.val;
                } else if (pickone.name == "EPICS_PVAS_TLS_KEYCHAIN") {
                    pickone({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"});
                    password_filename = pickone.val;
                } else {
                    pickone({"EPICS_PVA_TLS_KEYCHAIN_PWD_FILE"});
                    password_filename = pickone.val;
                }
                self.ensureDirectoryExists(password_filename);
                try {
                    self.tls_keychain_password = self.getFileContents(password_filename);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "error reading password file: %s. %s", password_filename.c_str(), e.what());
                }
            }

            // EPICS_PVAS_TLS_OPTIONS
            if (pickone({"EPICS_PVACMS_TLS_OPTIONS", "EPICS_PVAS_TLS_OPTIONS", "EPICS_PVA_TLS_OPTIONS"})) {
                parseTLSOptions(self, pickone.val);
            }

            // EPICS_PVAS_TLS_PORT
            if (pickone({"EPICS_PVACMS_TLS_PORT", "EPICS_PVAS_TLS_PORT", "EPICS_PVA_TLS_PORT"})) {
                try {
                    self.tls_port = parseTo<uint64_t>(pickone.val);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
                }
            }

            // EPICS_PVAS_TLS_STOP_IF_NO_CERT
            if (pickone({"EPICS_PVACMS_TLS_STOP_IF_NO_CERT"})) {
                self.tls_stop_if_no_cert = parseTo<bool>(pickone.val);
            }

            // EPICS_CA_ACF
            if (pickone({"EPICS_CA_ACF"})) {
                self.ensureDirectoryExists(self.ca_acf_filename = pickone.val);
            }

            // EPICS_CA_DB
            if (pickone({"EPICS_CA_DB"})) {
                self.ensureDirectoryExists(self.ca_db_filename = pickone.val);
            }

            // EPICS_CA_KEYCHAIN
            if (pickone({"EPICS_CA_KEYCHAIN", "EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
                self.ensureDirectoryExists(self.ca_keychain_filename = pickone.val);

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
                self.ensureDirectoryExists(password_filename);
                try {
                    self.ca_keychain_password = self.getFileContents(password_filename);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "error reading password file: %s. %s", password_filename.c_str(), e.what());
                }
            }

            // EPICS_CA_NAME
            if (pickone({"EPICS_CA_NAME"})) {
                self.ca_name = pickone.val;
            }

            // EPICS_CA_ORGANIZATION
            if (pickone({"EPICS_CA_ORGANIZATION"})) {
                self.ca_organization = pickone.val;
            }

            // EPICS_CA_ORGANIZATIONAL_UNIT
            if (pickone({"EPICS_CA_ORGANIZATIONAL_UNIT"})) {
                self.ca_organizational_unit = pickone.val;
            }

            // EPICS_PVAS_CERT_VALIDITY_MINS
            if (pickone({"EPICS_PVAS_CERT_VALIDITY_MINS", "EPICS_PVA_CERT_VALIDITY_MINS"})) {
                try {
                    self.cert_validity_mins = parseTo<uint64_t>(pickone.val);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "%s invalid validity minutes : %s", pickone.name.c_str(), e.what());
                }
            }

            // EPICS_PVACMS_PRE_EXPIRY_MINS
            if (pickone({"EPICS_PVACMS_PRE_EXPIRY_MINS"})) {
                try {
                    self.cert_pre_expiry_mins = parseTo<uint64_t>(pickone.val);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
                }
            }

            // EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL
            if (pickone({"EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"})) {
                self.cert_client_require_approval = parseTo<bool>(pickone.val);
            }

            // EPICS_PVACMS_REQUIRE_SERVER_APPROVAL
            if (pickone({"EPICS_PVACMS_REQUIRE_SERVER_APPROVAL"})) {
                self.cert_server_require_approval = parseTo<bool>(pickone.val);
            }


            return std::make_unique<ConfigCms>();
        }
    };

    return std::make_unique<ConfigCmsFactory>();
}
