// Created on 31/01/2025.
//

#ifndef AUTHREGISTRY_H
#define AUTHREGISTRY_H

#include <map>
#include <string>

#include "auth.h"

namespace pvxs {
namespace certs {

class AuthRegistry {
    public:
    static AuthRegistry& instance() {
        static AuthRegistry registry;
        return registry;
    }

    void registerAuth(const std::string& name, std::unique_ptr<Auth> auth) {
        registry[name] = std::move(auth);
    }

    Auth* getAuth(const std::string& name) const {
        auto it = registry.find(name);
        if (it != registry.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    static const std::map<std::string, std::unique_ptr<Auth>>& getRegistry() {
        return instance().registry;
    }

    private:
    AuthRegistry() = default;
    std::map<std::string, std::unique_ptr<Auth>> registry;
};
} // certs
} // pvxs

#endif //AUTHREGISTRY_H
