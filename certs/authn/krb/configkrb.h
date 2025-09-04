/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGKRB_H_
#define PVXS_CONFIGKRB_H_

#include <pvxs/client.h>
#include <pvxs/config.h>

#include "configauthn.h"

#define PVXS_KRB_DEFAULT_VALIDATOR_SERVICE "pvacms"
#define PVXS_KRB_DEFAULT_VALIDATOR_CLUSTER_PART "/cluster@"
#define PVXS_KRB_DEFAULT_VALIDATOR_REALM "EPICS.ORG"
#define PVXS_KRB_DEFAULT_VALIDATOR_SERVICE_NAME PVXS_KRB_DEFAULT_VALIDATOR_SERVICE PVXS_KRB_DEFAULT_VALIDATOR_CLUSTER_PART PVXS_KRB_DEFAULT_VALIDATOR_REALM

namespace pvxs {
namespace certs {

/**
 * @brief Configuration for the Kerberos authenticator
 *
 * This class (a subclass of the generic ConfigAuthN) is used to configure the Kerberos authenticator.
 *
 * It adds the kerberos validator service name, realm for use in the authn CCR creation
 * and keytab file for use in the PVACMS CCR verification.
 */
class ConfigKrb final : public ConfigAuthN {
   public:
    ConfigKrb& applyEnv() override {
        Config::applyEnv();
        tls_disabled = true;
        return *this;
    }

    /**
     * @brief Create a ConfigKrb object from the environment
     *
     * This static method creates a ConfigKrb object from the environment.
     *
     * It applies the generic client config environment to the ConfigKrb object, then
     * the generic authenticator environment, and finally it extracts the kerberos
     * validator service name, realm and keytab file from the environment and adds them
     * to the ConfigKrb object.
     *
     * @return A ConfigKrb object initialised from the environment
     */
    static ConfigKrb fromEnv() {
        auto config = ConfigKrb{}.applyEnv();
        const auto defs = std::map<std::string, std::string>();
        config.fromAuthEnv(defs);
        config.fromKrbEnv(defs);
        return config;
    }

    std::string krb_validator{PVXS_KRB_DEFAULT_VALIDATOR_SERVICE};
    std::string krb_realm{};
    std::string krb_keytab{};

    void fromKrbEnv(const std::map<std::string, std::string>& defs);

    void updateDefs(defs_t &defs) const override;

};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CONFIGKRB_H_
