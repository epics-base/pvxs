/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_LDAP_H
#define PVXS_AUTH_LDAP_H

#include <functional>
#include <memory>
#include <string>

#include <configldap.h>

#include <pvxs/config.h>
#include <pvxs/data.h>
#include <pvxs/version.h>

#include "auth.h"
#include "certfactory.h"
#include "security.h"

#define PVXS_LDAP_AUTH_TYPE "ldap"
#define PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE "epicsPublicKey"
#define PVXS_LDAP_AUTH_PEOPLE_GROUP "People"

namespace pvxs {
namespace certs {

/**
 * The subclass of Credentials that contains the AuthNLdap specific
 * identification object
 */
struct LdapCredentials final : Credentials {
    std::string password{};
    std::string ldap_server{};
    unsigned short ldap_port = 389;
};

class AuthNLdap final : public Auth {
   public:
    // Constructor
    AuthNLdap() : Auth(PVXS_LDAP_AUTH_TYPE, {Member(TypeCode::String, "signature")}) {};
    ~AuthNLdap() override = default;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config, bool for_client) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                 const std::shared_ptr<KeyPair> &key_pair,
                                                                 const uint16_t &usage,
                                                                 const ConfigAuthN &config) const override;

    bool verify(Value &ccr, time_t &authenticated_expiration_date) const override;

    void fromEnv(std::unique_ptr<client::Config> &config) override { config.reset(new ConfigLdap(ConfigLdap::fromEnv())); };

    void configure(const client::Config &config) override {
        auto &config_ldap = dynamic_cast<const ConfigLdap &>(config);
        ldap_server = config_ldap.ldap_host;
        ldap_port = config_ldap.ldap_port;
    };

    /**
     * @brief Update the definitions with the LDAP authenticator specific definitions.
     *
     * This function is called from PVACMS to update the definitions with the LDAP authenticator specific definitions.
     * It updates the definitions with the LDAP host and port.
     *
     * @param defs the definitions to update with the LDAP authenticator specific definitions
     */
    void updateDefs(client::Config::defs_t &defs) const override {
        defs["EPICS_AUTH_LDAP_HOST"] = ldap_server;
        defs["EPICS_AUTH_LDAP_PORT"] = std::to_string(ldap_port);
    }

    std::string getOptionsPlaceholderText() override { return " [ldap options]"; }
    std::string getOptionsHelpText() override {
        return "\n"
               "ldap options\n"
               "        --ldap-host <host>                   LDAP Host.  Default localhost\n"
               "        --ldap-port <port>                   LDAP port.  Default 389\n";
    }

    void addOptions(CLI::App &app, std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map) override {
        auto &config = authn_config_map.at(PVXS_LDAP_AUTH_TYPE);
        auto config_ldap = dynamic_cast<const ConfigLdap &>(*config);
        app.add_option("--ldap-host", config_ldap.ldap_host, "Specify LDAP hostname or IP address");
        app.add_option("--ldap-port", config_ldap.ldap_port, "Specify LDAP port number");
    }

   private:
    std::string ldap_server{"localhost"};
    unsigned short ldap_port = 389;

    static std::string getDn(const std::string &uid, const std::string &organization);
    static std::vector<std::string> split(const std::string &s, char delimiter);
    static std::string getPublicKeyFromLDAP(const std::string &ldap_server, int ldap_port, const std::string &uid, const std::string &organization);
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_LDAP_H
