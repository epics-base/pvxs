/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_LDAP_H
#define PVXS_AUTH_LDAP_H

#include <configldap.h>
#include <functional>
#include <memory>
#include <string>

#include <pvxs/config.h>
#include <pvxs/data.h>
#include <pvxs/version.h>

#include "auth.h"
#include "certfactory.h"
#include "security.h"

#define PVXS_LDAP_AUTH_TYPE "ldap"

namespace pvxs {
namespace certs {

struct LdapId {
    int i;  // TODO placeholder
};

/**
 * The subclass of Credentials that contains the AuthNLdap specific
 * identification object
 */
struct LdapCredentials : Credentials {
    LdapId id;  // LDAP ID
};

class AuthNLdap : public Auth {
   public:

    // Constructor
    AuthNLdap() : Auth(PVXS_LDAP_AUTH_TYPE, {}) {};
    ~AuthNLdap() override = default;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                   const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify(
        const Value ccr,
        std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const override;

    client::Config fromEnv() {
        return static_cast<client::Config>(ConfigLdap::fromEnv());
    };

    std::string getOptionsText() {return " [ldap options]";}
    std::string getParameterHelpText() {return  "\n"
                                              "ldap options\n"
                                              "        --ldap-admin-account <name>          LDAP Admin account name\n"
                                              "        --ldap-admin-pwd <file>              LDAP Admin account's password file\n"
                                              "        --ldap-host <host>                   LDAP Host.  Default localhost\n"
                                              "        --ldap-port <port>                   LDAP port.  Default 389\n"
                                              "        --ldap-search-root <root>            LDAP search root.  Default dc=epics,dc=org\n";}

    void addParameters(CLI::App & app, const std::map<const std::string, client::Config> & authn_config_map) {
        auto &config = authn_config_map.at(PVXS_LDAP_AUTH_TYPE);
        auto config_ldap = static_cast<const ConfigLdap&>(config);
        app.add_option("--ldap-admin-account", config_ldap.ldap_account, "Specify LDAP account name");
        app.add_option("--ldap-admin-pwd", config_ldap.ldap_account_password, "Specify LDAP account's password file");
        app.add_option("--ldap-host", config_ldap.ldap_host, "Specify LDAP hostname or IP address");
        app.add_option("--ldap-port", config_ldap.ldap_port, "Specify LDAP port number");
        app.add_option("--ldap-search-root", config_ldap.ldap_search_root, "Specify LDAP search root");
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_LDAP_H
