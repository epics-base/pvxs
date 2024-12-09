/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGLDAP_H_
#define PVXS_CONFIGLDAP_H_

#include <memory>

#include "ownedptr.h"

#include "certconfig.h"

class ConfigLdap : public Config {
  public:
    std::string ldap_account;
    std::string ldap_account_password;
    std::string ldap_host;
    unsigned short ldap_port;
    std::string ldap_search_root;
};

class ConfigLdapFactory : public ConfigFactoryInterface {
  public:
    std::unique_ptr<Config> create() override {
        return std::make_unique<ConfigLdap>();
    }
};

#endif //PVXS_CONFIGLDAP_H_
