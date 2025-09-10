/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configkrb.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

void ConfigKrb::fromKrbEnv(const std::map<std::string, std::string>& defs) {
    PickOne pickone{defs, true};

    // KRB5_KTNAME
    // This is the environment variable defined by krb5
    if (pickone({"KRB5_KTNAME", "KRB5_CLIENT_KTNAME"})) {
        krb_keytab = pickone.val;
    }

    // EPICS_AUTH_KRB_REALM
    if (pickone({"EPICS_AUTH_KRB_VALIDATOR_SERVICE"})) {
        krb_validator = pickone.val;
    }

    // EPICS_AUTH_KRB_REALM
    if (pickone({"EPICS_AUTH_KRB_REALM"})) {
        krb_realm = pickone.val;
    }
}

/**
 * Update the definitions with the kerberos authenticator specific definitions.
 *
 * This function is called from authnkrbmain to update the definitions with the kerberos authenticator specific definitions.
 * It updates the definitions with the kerberos keytab file, the kerberos client keytab file,
 * the kerberos validator service name, and the kerberos realm.
 *
 * @param defs the definitions to update with the kerberos authenticator-specific definitions
 */
void ConfigKrb::updateDefs(defs_t& defs) const {
    ConfigAuthN::updateDefs(defs);
    defs["KRB5_KTNAME"] = krb_keytab;
    defs["KRB5_CLIENT_KTNAME"] = krb_keytab;
    defs["EPICS_AUTH_KRB_VALIDATOR_SERVICE"] = krb_validator;
    defs["EPICS_AUTH_KRB_REALM"] = krb_realm;
}

}  // namespace certs
}  // namespace pvxs
