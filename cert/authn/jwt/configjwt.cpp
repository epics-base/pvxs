/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configjwt.h"

std::unique_ptr<ConfigFactoryInterface> getConfigFactory() {
    struct ConfigCmsFactory : public ConfigFactoryInterface {
        std::unique_ptr<Config> create() override {
            // EPICS_AUTH_JWT_REQUEST_FORMAT
            if (pickone({"EPICS_AUTH_JWT_REQUEST_FORMAT"})) {
                self.jwt_request_format = pickone.val;
            }

            // EPICS_AUTH_JWT_REQUEST_METHOD
            if (pickone({"EPICS_AUTH_JWT_REQUEST_METHOD"})) {
                self.jwt_request_method = pickone.val == "POST" ? Config::POST : Config::GET;
            }

            // EPICS_AUTH_JWT_RESPONSE_FORMAT
            if (pickone({"EPICS_AUTH_JWT_RESPONSE_FORMAT"})) {
                self.jwt_response_format = pickone.val;
            }

            // EPICS_AUTH_JWT_TRUSTED_URI
            if (pickone({"EPICS_AUTH_JWT_TRUSTED_URI"})) {
                self.jwt_trusted_uri = pickone.val;
            }

            // EPICS_AUTH_JWT_USE_RESPONSE_CODE
            if (pickone({"EPICS_AUTH_JWT_USE_RESPONSE_CODE"})) {
                self.jwt_use_response_code = parseTo<bool>(pickone.val);
            }

            return std::make_unique<ConfigCms>();
        }
    };

    return std::make_unique<ConfigCmsFactory>();
}
