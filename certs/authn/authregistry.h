/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef AUTHREGISTRY_H
#define AUTHREGISTRY_H

#include <map>
#include <string>

#include "auth.h"

namespace pvxs {
namespace certs {

/**
 * @brief The AuthRegistry class is a singleton that manages the registration of Authenticatora.
 *
 * This class is a singleton that manages the registration of Authenticators.
 * It is used to register Authenticator with a unique name and a pointer to the Authenticator.
 * It is used to get an Authenticator by name.
 */
class AuthRegistry {
   public:
    /**
     * @brief Get the singleton instance of the AuthRegistry.
     *
     * This function returns the singleton instance of the AuthRegistry.
     * It is a singleton that manages the registration of Authenticators.
     *
     * @return The singleton instance of the AuthRegistry.
     */
    static AuthRegistry& instance() {
        static AuthRegistry registry;
        return registry;
    }

    /**
     * @brief Register an Authenticator.
     *
     * This function registers an Authenticator with a unique name and a pointer to the Authenticator.
     *
     */
    void registerAuth(const std::string& name, std::unique_ptr<Auth> auth) { registry[name] = std::move(auth); }

    /**
     * @brief Get a pointer to an Authenticator by name.
     *
     * This function returns a pointer to an Authenticator by name.
     *
     * @param name The name of the Authenticator.
     * @return A pointer to the Authenticator.
     */
    Auth* getAuth(const std::string& name) const {
        const auto it = registry.find(name);
        if (it != registry.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    /**
     * @brief Get a reference to the registry of Authenticators.
     *
     * This function returns a reference to the registry of Authenticators.
     *
     * @return A reference to the registry of Authenticators.
     */
    static const std::map<std::string, std::unique_ptr<Auth>>& getRegistry() { return instance().registry; }

   private:
    AuthRegistry() = default;
    std::map<std::string, std::unique_ptr<Auth>> registry;
};
}  // namespace certs
}  // namespace pvxs

#endif  // AUTHREGISTRY_H
