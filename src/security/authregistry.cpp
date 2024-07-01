/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authregistry.h"

#include <memory>
#include <unordered_set>

#include "auth.h"

namespace pvxs {
namespace security {

std::unordered_map<std::string, std::unique_ptr<Auth>> AuthRegistry::auths_;

const std::unique_ptr<Auth> PVXS_API &AuthRegistry::getAuth(const std::string &name) {
    // Check if `name` exists to avoid undefined behavior
    if (auths_.find(name) == auths_.end()) {
        throw std::runtime_error("Authenticator with name '" + name + "' not found");
    }

    // We're sure `name` exists in map
    return auths_.at(name);
}

}  // namespace security
}  // namespace pvxs
