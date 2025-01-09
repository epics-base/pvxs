/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGSTD_H_
#define PVXS_CONFIGSTD_H_

#include <memory>

#include <pvxs/config.h>
#include <pvxs/server.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

class ConfigStd : public pvxs::client::Config {
   public:
    ConfigStd& applyEnv() {
        pvxs::client::Config::applyEnv(true, CLIENT);
        return *this;
    }

    static inline ConfigStd fromEnv() {
        auto config = ConfigStd{}.applyEnv();
        config.fromStdEnv(std::map<std::string, std::string>());
        return config;
    }

    /**
     * @brief The number of minutes from now after which the new certificate being created should expire.
     *
     * Use this to set the default validity for certificates
     * generated from basic credentials.
     */
    uint32_t cert_validity_mins = 43200;

    /**
     * @brief Value will be used as the device name when an EPICS agent
     * is determining basic credentials instead of the hostname as
     * the principal
     */
    std::string name;
    std::string organization;
    std::string organizational_unit;
    std::string country;

    std::string server_name;
    std::string server_organization;
    std::string server_organizational_unit;
    std::string server_country;

    std::string tls_srv_keychain_file;
    std::string tls_srv_keychain_pwd;

    void fromStdEnv(const std::map<std::string, std::string>& defs);
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGSTD_H_
