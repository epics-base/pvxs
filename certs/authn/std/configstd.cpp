/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configstd.h"

#include <pvxs/log.h>

#include "utilpvt.h"

namespace pvxs {
namespace certs {

void ConfigStd::fromStdEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};
}

void ConfigStd::updateDefs(defs_t &defs) const {
    ConfigAuthN::updateDefs(defs);
}

}  // namespace certs
}  // namespace pvxs
