/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGLDAP_H_
#define PVXS_CONFIGLDAP_H_

#include <pvxs/client.h>
#include <pvxs/config.h>

#include "configauthn.h"

namespace pvxs {
namespace certs {

class ConfigLdap final : public ConfigAuthN {
   public:
    ConfigLdap& applyEnv() {
        Config::applyEnv(true, CLIENT);
        return *this;
    }

    static ConfigLdap fromEnv() {
        auto config = ConfigLdap{}.applyEnv();
        const auto defs = std::map<std::string, std::string>();
        config.fromAuthEnv(defs);
        config.fromLdapEnv(defs);
        return config;
    }

    std::string ldap_account_password{};
    std::string ldap_host{"localhost"};
    unsigned short ldap_port{389};

    void fromLdapEnv(const std::map<std::string, std::string>& defs);

    void updateDefs(defs_t &defs) const override;

};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CONFIGLDAP_H_
