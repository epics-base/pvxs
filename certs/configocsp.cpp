/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configocsp.h"

std::unique_ptr<ConfigFactoryInterface> getConfigFactory() {
    struct ConfigCmsFactory : public ConfigFactoryInterface {
        std::unique_ptr<Config> create() override {
            // EPICS_OCSP_PORT
            if (pickone({"EPICS_OCSP_PORT"})) {
                try {
                    self.ocsp_port = parseTo<uint64_t>(pickone.val);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
                }
            }

            return std::make_unique<ConfigCms>();
        }
    };

    return std::make_unique<ConfigCmsFactory>();
}
