/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configjwt.h"

DEFINE_LOGGER(cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigJwt::fromJwtEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_JWT_REQUEST_FORMAT
    if (pickone({"EPICS_AUTH_JWT_REQUEST_FORMAT"})) {
        jwt_request_format = pickone.val;
    }

    // EPICS_AUTH_JWT_REQUEST_METHOD
    if (pickone({"EPICS_AUTH_JWT_REQUEST_METHOD"})) {
        jwt_request_method = pickone.val;
    }

    // EPICS_AUTH_JWT_RESPONSE_FORMAT
    if (pickone({"EPICS_AUTH_JWT_RESPONSE_FORMAT"})) {
        jwt_response_format = pickone.val;
    }

    // EPICS_AUTH_JWT_TRUSTED_URI
    if (pickone({"EPICS_AUTH_JWT_TRUSTED_URI"})) {
        jwt_trusted_uri = pickone.val;
    }

    // EPICS_AUTH_JWT_USE_RESPONSE_CODE
    if (pickone({"EPICS_AUTH_JWT_USE_RESPONSE_CODE"})) {
        jwt_use_response_code = parseTo<bool>(pickone.val);
    }
}

} // certs
} // pvxs
