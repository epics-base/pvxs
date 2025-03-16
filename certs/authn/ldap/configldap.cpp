/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configldap.h"

DEFINE_LOGGER(cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigLdap::fromLdapEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_LDAP_ACCOUNT_PWD_FILE
    if (pickone({"EPICS_AUTH_LDAP_ACCOUNT_PWD_FILE"})) {
        auto filepath = pickone.val;
        ensureDirectoryExists(filepath);
        try {
            ldap_account_password = getFileContents(filepath);
        } catch (std::exception &e) {
            log_err_printf(cfg, "error reading password file: %s. %s", filepath.c_str(), e.what());
        }
    }

    // EPICS_AUTH_LDAP_HOST
    if (pickone({"EPICS_AUTH_LDAP_HOST"})) {
        ldap_host = pickone.val;
    }

    // EPICS_AUTH_LDAP_PORT
    if (pickone({"EPICS_AUTH_LDAP_PORT"})) {
        try {
            ldap_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(cfg, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }
}

/**
 * Update the definitions with the LDAP authenticator specific definitions.
 *
 * This function is called from authnldapmain to update the definitions with the LDAP authenticator specific definitions.
 * It updates the definitions with the LDAP account password, the LDAP host, and the LDAP port.
 *
 * @param defs the definitions to update with the LDAP authenticator specific definitions
 */
void ConfigLdap::updateDefs(defs_t &defs) const {
    ConfigAuthN::updateDefs(defs);
    if (!ldap_account_password.empty()) defs["EPICS_AUTH_LDAP_ACCOUNT_PWD_FILE"] = "<password read>";
    defs["EPICS_AUTH_LDAP_HOST"] = ldap_host;
    defs["EPICS_AUTH_LDAP_PORT"] = SB() << ldap_port;
}

}  // namespace certs
}  // namespace pvxs
