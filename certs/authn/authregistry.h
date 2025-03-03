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
 * @brief The AuthRegistry class is a singleton that manages the registration of authentication methods.
 *
 * This class is a singleton that manages the registration of authentication methods.
 * It is used to register authentication methods with a unique name and a pointer to the authentication method.
 * It is used to get an authentication method by name.
 */
class AuthRegistry {
   public:
    /**
     * @brief Get the singleton instance of the AuthRegistry.
     *
     * This function returns the singleton instance of the AuthRegistry.
     * It is a singleton that manages the registration of authentication methods.
     *
     * @return The singleton instance of the AuthRegistry.
     */
    static AuthRegistry& instance() {
        static AuthRegistry registry;
        return registry;
    }

    /**
     * @brief Register an authentication method.
     *
     * This function registers an authentication method with a unique name and a pointer to the authentication method.
     *
     */
    void registerAuth(const std::string& name, std::unique_ptr<Auth> auth) { registry[name] = std::move(auth); }

    /**
     * @brief Get a pointer to an authentication method by name.
     *
     * This function returns a pointer to an authentication method by name.
     *
     * @param name The name of the authentication method.
     * @return A pointer to the authentication method.
     */
    Auth* getAuth(const std::string& name) const {
        const auto it = registry.find(name);
        if (it != registry.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    /**
     * @brief Get a reference to the registry of authentication methods.
     *
     * This function returns a reference to the registry of authentication methods.
     *
     * @return A reference to the registry of authentication methods.
     */
    static const std::map<std::string, std::unique_ptr<Auth>>& getRegistry() { return instance().registry; }

   private:
    AuthRegistry() = default;
    std::map<std::string, std::unique_ptr<Auth>> registry;
};
}  // namespace certs
}  // namespace pvxs

#endif  // AUTHREGISTRY_H
