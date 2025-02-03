/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configkrb.h"

namespace pvxs {
namespace certs {

void ConfigKrb::fromKrbEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // KRB5_KTNAME
    // This is the environment variable defined by krb5
    if (pickone({"KRB5_KTNAME", "KRB5_CLIENT_KTNAME"})) {
        krb_keytab = pickone.val;
    }

    // EPICS_AUTH_KRB_REALM
    if (pickone({"EPICS_AUTH_KRB_VALIDATOR_SERVICE"})) {
        krb_validator_service = pickone.val;
    }

    // EPICS_AUTH_KRB_REALM
    if (pickone({"EPICS_AUTH_KRB_REALM"})) {
        krb_realm = pickone.val;
    }

}

}  // namespace certs
}  // namespace pvxs
