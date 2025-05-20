/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configstd.h"

#include <pvxs/log.h>

#include "utilpvt.h"

DEFINE_LOGGER(cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigStd::fromStdEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_CERT_VALIDITY_MINS
    if (pickone({"EPICS_AUTH_CERT_VALIDITY_MINS"})) {
        try {
            cert_validity_mins = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(cfg, "%s invalid validity minutes : %s", pickone.name.c_str(), e.what());
        }
    }
}

/**
 * Update the definitions with the standard authenticator specific definitions.
 *
 * This function is called from authnstdmain to update the definitions with the standard authenticator specific definitions.
 * It updates the definitions with the certificate validity minutes.
 *
 * @param defs the definitions to update with the standard authenticator specific definitions
 */
void ConfigStd::updateDefs(defs_t &defs) const {
    ConfigAuthN::updateDefs(defs);
    defs["EPICS_AUTH_CERT_VALIDITY_MINS"] = std::to_string(cert_validity_mins);
}

}  // namespace certs
}  // namespace pvxs
