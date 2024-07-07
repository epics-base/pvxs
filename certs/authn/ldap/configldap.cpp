/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configldap.h"

std::unique_ptr<ConfigFactoryInterface> getConfigFactory() {
    struct ConfigCmsFactory : public ConfigFactoryInterface {
        std::unique_ptr<Config> create() override {
            // EPICS_AUTH_LDAP_ACCOUNT
            if (pickone({"EPICS_AUTH_LDAP_ACCOUNT"})) {
                self.ldap_account = pickone.val;
            }

            // EPICS_AUTH_LDAP_ACCOUNT_PWD_FILE
            if (pickone({"EPICS_AUTH_LDAP_ACCOUNT_PWD_FILE"})) {
                auto filepath = pickone.val;
                self.ensureDirectoryExists(filepath);
                try {
                    self.ldap_account_password = self.getFileContents(filepath);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "error reading password file: %s. %s", filepath.c_str(), e.what());
                }
            }

            // EPICS_AUTH_LDAP_HOST
            if (pickone({"EPICS_AUTH_LDAP_HOST"})) {
                self.ldap_host = pickone.val;
            }

            // EPICS_AUTH_LDAP_PORT
            if (pickone({"EPICS_AUTH_LDAP_PORT"})) {
                try {
                    self.ldap_port = parseTo<uint64_t>(pickone.val);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
                }
            }

            // EPICS_AUTH_LDAP_SEARCH_ROOT
            if (pickone({"EPICS_AUTH_LDAP_SEARCH_ROOT"})) {
                self.ldap_search_root = pickone.val;
            }

            return std::make_unique<ConfigCms>();
        }
    };

    return std::make_unique<ConfigCmsFactory>();
}
