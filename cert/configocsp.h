/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCMS_H_
#define PVXS_CONFIGCMS_H_

#include <memory>

#include "ownedptr.h"

#include "certconfig.h"

class ConfigCms : public Config {
  public:
    /**
     * @brief The port for the OCSP server to listen on.
     */
    unsigned short ocsp_port = 8080;

};

class ConfigCmsFactory : public ConfigFactoryInterface {
  public:
    std::unique_ptr<Config> create() override {
        return std::make_unique<ConfigCms>();
    }
};

#endif //PVXS_CONFIGCMS_H_
