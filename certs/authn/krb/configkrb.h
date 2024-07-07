/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGKRB_H_
#define PVXS_CONFIGKRB_H_

#include <memory>

#include "ownedptr.h"

#include "certconfig.h"

class ConfigKrb : public Config {
  public:
    /**
     * @brief This is the string to which PVACMS/CLUSTER is prepended to
     * create the service principal to be added to the Kerberos KDC to
     * enable Kerberos ticket verification by the PVACMS.
     *
     * It is used in an EPICS agent when creating a GSSAPI context to
     * create a token to send to the PVACMS to be validated, and used by
     * the PVACMS to create another GSSAPI context to decode the token
     * and validate the CCR.
     *
     * There is no default so this value *must* be
     * specified if Kerberos support is configured.
     *
     * The KDC will share a keytab file containing the secret key
     * for the PVACMS/CLUSTER service and it will be made available to
     * all members of the cluster but protected so no other processes
     * or users can access it.
     */
    std::string krb_realm;
};

class ConfigKrbFactory : public ConfigFactoryInterface {
  public:
    std::unique_ptr<Config> create() override {
        return std::make_unique<ConfigKrb>();
    }
};

#endif //PVXS_CONFIGKRB_H_
