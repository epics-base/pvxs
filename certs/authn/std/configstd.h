/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGSTD_H_
#define PVXS_CONFIGSTD_H_

#include <pvxs/config.h>
#include <pvxs/client.h>

#include "configauthn.h"

namespace pvxs {
namespace certs {

class ConfigStd : public ConfigAuthN {
   public:
    ConfigStd& applyEnv() {
        Config::applyEnv(true, CLIENT);
        return *this;
    }

    static ConfigStd fromEnv() {
        auto config = ConfigStd{}.applyEnv();
        auto defs = std::map<std::string, std::string>();
        config.fromAuthNEnv(defs);
        config.fromStdEnv(defs);
        return config;
    }

    /**
     * @brief The number of minutes from now after which the new certificate being created should expire.
     *
     * Use this to set the default validity for certificates
     * generated from basic credentials.
     */
    uint32_t cert_validity_mins = 43200;

    std::string name{};
    std::string organization{};
    std::string organizational_unit{};
    std::string country{"US"};

    std::string server_name{};
    std::string server_organization{};
    std::string server_organizational_unit{};
    std::string server_country{"US"};

    void fromStdEnv(const std::map<std::string, std::string>& defs);
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGSTD_H_
