/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configstd.h"

std::unique_ptr<ConfigFactoryInterface> getConfigFactory() {
    struct ConfigStdFactory : public ConfigFactoryInterface {
        std::unique_ptr<Config> create() override {
            // EPICS_PVA_CERT_VALIDITY_MINS
            if (pickone({"EPICS_PVA_CERT_VALIDITY_MINS"})) {
                try {
                    self.cert_validity_mins = parseTo<uint64_t>(pickone.val);
                } catch (std::exception &e) {
                    log_err_printf(serversetup, "%s invalid validity minutes : %s", pickone.name.c_str(), e.what());
                }
            }

            // EPICS_PVAS_AUTH_DEVICE_NAME
            if (pickone({"EPICS_PVAS_AUTH_DEVICE_NAME", "EPICS_PVA_AUTH_DEVICE_NAME"})) {
                self.device_name = pickone.val;
            }

            // EPICS_PVAS_AUTH_PROCESS_NAME
            if (pickone({"EPICS_PVAS_AUTH_PROCESS_NAME", "EPICS_PVA_AUTH_PROCESS_NAME"})) {
                self.process_name = pickone.val;
            }

            // EPICS_PVAS_AUTH_USE_PROCESS_NAME
            if (pickone({"EPICS_PVAS_AUTH_USE_PROCESS_NAME", "EPICS_PVA_AUTH_USE_PROCESS_NAME"})) {
                self.use_process_name = parseTo<bool>(pickone.val);
            }


            return std::make_unique<ConfigStd>();
        }
    };

    return std::make_unique<ConfigStdFactory>();
}
