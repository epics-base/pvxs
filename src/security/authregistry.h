/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_REGISTRY_H
#define PVXS_AUTH_REGISTRY_H

#include <unordered_set>

#include <cxxabi.h>

#include <pvxs/log.h>

#include "auth.h"

namespace pvxs {
namespace security {

DEFINE_LOGGER(auth_registry, "pvxs.security.auth.registry");

/**
 * Automatically Register the enclosing Class as an Auth.  This means
 * that it will be automatically checked to see if it's implementation is
 * available and registered if it is. Once registered, it will be used by the
 * framework to check whether the client is logged in using this authentication
 * method, to obtain client credentials, and create signed certificates.
 */
#define REGISTER_AUTHENTICATOR() \
    const bool autoRegister() const { return Registrar<decltype(*this)>::registered; };

/**
 * @class AuthRegistrar
 *
 * @brief Manages certificates and associated operations.
 *
 * This class manages a map of authenticators for different types of
 * authentication methods.
 *
 * This map is automatically populated by the mere existence of Auth classes
 * in the code base as long as that authenticator uses the
 * REGISTER_AUTHENTICATOR() macro in its definition, and is derived from the
 * Auth class.
 *
 * Inclusion of authenticator source in the dependencies depends on specific
 * macros that enable each authenticator. The following Makefile macros are
 * used: `PVXS_KERBEROS_AUTH_ENABLED`, `PVXS_JWT_AUTH_ENABLED`, and
 * `PVXS_LDAP_AUTH_ENABLED`
 * and the following compile time macros:
 * `PVXS_ENABLE_KERBEROS_AUTH`, `PVXS_ENABLE_JWT_AUTH`, and
 * `PVXS_ENABLE_LDAP_AUTH`
 */
class AuthRegistry {
   public:
    // Don't allow this class to be instantiated
    AuthRegistry() = delete;

    AuthRegistry(const AuthRegistry &) = delete;

    AuthRegistry &operator=(const AuthRegistry &) = delete;

    static const std::unique_ptr<Auth> PVXS_API &getAuth(const std::string &name);

    /**
     * @brief This function is responsible for auto registering authenticators.
     *
     * This function automatically registers an authenticator by adding an
     * instance to the global list of authenticators.
     *
     * @tparam T The class of the Auth to be registered
     *
     * @return true if the authenticator was successfully registered
     */
    template <typename T>
    static bool autoRegister() {
        // Remove reference with typename keyword
        using DerefAuth = typename std::remove_reference<T>::type;
        // Remove const with typename keyword
        using NonConstAuth = typename std::remove_const<DerefAuth>::type;

        // Demangle class name for log
        int status;
        char *raw_realname = abi::__cxa_demangle(typeid(NonConstAuth).name(), nullptr, nullptr, &status);
        std::string realname = std::string(raw_realname);
        free(raw_realname);

        // Create an instance of the authenticator
        auto auth = std::unique_ptr<NonConstAuth>(new NonConstAuth());
        auths_.insert({auth->type_, std::move(auth)});

        log_debug_printf(auth_registry, "Registering Authentication Class: %s\n", realname.c_str());

        return true;
    };

    // Set to hold all authenticators except the default one
    static std::unordered_map<std::string, std::unique_ptr<Auth>> auths_;
};

template <typename T>
struct Registrar {
    static const bool registered;
};

template <typename T>
const bool Registrar<T>::registered = AuthRegistry::autoRegister<T>();

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_AUTH_REGISTRY_H
