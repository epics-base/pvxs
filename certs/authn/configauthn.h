/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGAUTHN_H_
#define PVXS_CONFIGAUTHN_H_

#include <pvxs/config.h>
#include <pvxs/client.h>

namespace pvxs {
namespace certs {

class ConfigAuthN : public client::Config {
   public:
    std::string name{};
    std::string organization{};
    std::string tls_srv_keychain_file{};
    std::string tls_srv_keychain_pwd{};

    void fromAuthNEnv(const std::map<std::string, std::string>& defs);
    std::string getIPAddress();

};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGAUTHN_H_
