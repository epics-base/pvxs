/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGSTD_H_
#define PVXS_CONFIGSTD_H_

#include <pvxs/client.h>
#include <pvxs/config.h>

#include "configauthn.h"

namespace pvxs {
namespace certs {

class ConfigStd final : public ConfigAuthN {
   public:
    ConfigStd& applyEnv() {
        Config::applyEnv(true, CLIENT);
        return *this;
    }

    /**
     * @brief Create a ConfigStd object from the environment
     *
     * This static method creates a ConfigStd object from the environment.
     *
     * It applies the generic client config environment to the ConfigStd object, then
     * the generic authenticator environment, and finally it extracts the standard
     * certificate validity minutes from the environment and adds it to the ConfigStd object.
     *
     * @return A ConfigStd object initialised from the environment
     */
    static ConfigStd fromEnv() {
        auto config = ConfigStd{}.applyEnv();
        const auto defs = std::map<std::string, std::string>();
        config.fromAuthEnv(defs);
        config.fromStdEnv(defs);
        return config;
    }

    /**
     * @brief The number of minutes from now after which the new certificate being created should expire.
     *
     * Use this to set the default validity for certificates
     * generated from basic credentials.
     */
    uint32_t cert_validity_mins = 30 * 24 * 60;  // Default to 30 days

    void fromStdEnv(const std::map<std::string, std::string>& defs);
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGSTD_H_
