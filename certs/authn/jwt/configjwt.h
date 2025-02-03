/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGJWT_H_
#define PVXS_CONFIGJWT_H_

#include <pvxs/config.h>
#include <pvxs/client.h>
#include "configauthn.h"

namespace pvxs {
namespace certs {

class ConfigJwt : public ConfigAuthN {
  public:
    ConfigJwt& applyEnv() {
        Config::applyEnv(true, CLIENT);
        return *this;
    }

    static ConfigJwt fromEnv() {
        auto config = ConfigJwt{}.applyEnv();
        auto defs = std::map<std::string, std::string>();
        config.fromAuthNEnv(defs);
        config.fromJwtEnv(defs);
        return config;
    }


    /**
     * @brief The JWT token
     */
    std::string jwt_token{};
    std::string jwt_request_format{};
    std::string jwt_request_method{};
    std::string jwt_response_format{};
    std::string jwt_trusted_uri{};
    bool jwt_use_response_code{false};

    void fromJwtEnv(const std::map<std::string, std::string> &defs);
};

}  // namespace certs
}  // namespace pvxs

#endif //PVXS_CONFIGJWT_H_
