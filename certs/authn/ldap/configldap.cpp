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

    // EPICS_AUTH_LDAP_ACCOUNT
    if (pickone({"EPICS_AUTH_LDAP_ACCOUNT"})) {
        ldap_account = pickone.val;
    }

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

    // EPICS_AUTH_LDAP_SEARCH_ROOT
    if (pickone({"EPICS_AUTH_LDAP_SEARCH_ROOT"})) {
        ldap_search_root = pickone.val;
    }
}

}  // namespace certs
}  // namespace pvxs
