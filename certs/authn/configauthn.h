/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGAUTHN_H_
#define PVXS_CONFIGAUTHN_H_

#include <pvxs/client.h>
#include <pvxs/config.h>

namespace pvxs {
namespace certs {

class ConfigAuthN : public client::Config {
   public:
    std::string name{};
    std::string organization{};
    std::string organizational_unit{};
    std::string country{"US"};
    bool no_status{false};
    std::string issuer_id{};

    std::string server_name{};
    std::string server_organization{};
    std::string server_organizational_unit{};
    std::string server_country{"US"};

    std::string tls_srv_keychain_file{};
    std::string tls_srv_keychain_pwd{};

    void fromAuthEnv(const std::map<std::string, std::string>& defs);
    static std::string getIPAddress();
    void updateDefs(defs_t& defs) const override;
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGAUTHN_H_
