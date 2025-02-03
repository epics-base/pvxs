/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGKRB_H_
#define PVXS_CONFIGKRB_H_

#include <pvxs/config.h>
#include <pvxs/client.h>
#include "configauthn.h"

namespace pvxs {
namespace certs {

class ConfigKrb : public ConfigAuthN {
  public:
    ConfigKrb& applyEnv() {
        Config::applyEnv(true, CLIENT);
        return *this;
    }

    static ConfigKrb fromEnv() {
        auto config = ConfigKrb{}.applyEnv();
        auto defs = std::map<std::string, std::string>();
        config.fromAuthNEnv(defs);
        config.fromKrbEnv(defs);
        return config;
    }

    std::string krb_validator_service{"pvacms"};
    std::string krb_realm{"EPICS.ORG"};
    std::string krb_keytab{};

    void fromKrbEnv(const std::map<std::string, std::string>& defs);
};

}  // namespace certs
}  // namespace pvxs

#endif //PVXS_CONFIGKRB_H_
