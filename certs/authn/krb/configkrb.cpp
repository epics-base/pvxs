/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configkrb.h"

std::unique_ptr<ConfigFactoryInterface> getConfigFactory() {
    struct ConfigCmsFactory : public ConfigFactoryInterface {
        std::unique_ptr<Config> create() override {
            // EPICS_AUTH_KRB_KEYTAB
            if (pickone({"EPICS_AUTH_KRB_KEYTAB"})) {
                self.krb_keytab = pickone.val;
            }

            // EPICS_AUTH_KRB_REALM
            if (pickone({"EPICS_AUTH_KRB_REALM"})) {
                self.krb_realm = pickone.val;
            }

            return std::make_unique<ConfigCms>();
        }
    };

    return std::make_unique<ConfigCmsFactory>();
}
