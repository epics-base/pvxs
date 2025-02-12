/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configstd.h"

DEFINE_LOGGER(cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigStd::fromStdEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_STD_CERT_VALIDITY_MINS
    if (pickone({"EPICS_AUTH_STD_CERT_VALIDITY_MINS"})) {
        try {
            cert_validity_mins = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(cfg, "%s invalid validity minutes : %s", pickone.name.c_str(), e.what());
        }
    }
}

}  // namespace certs
}  // namespace pvxs
