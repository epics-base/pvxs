/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGJWT_H_
#define PVXS_CONFIGJWT_H_

#include <memory>

#include "ownedptr.h"

#include "certconfig.h"

class ConfigJwt : public Config {
  public:
    /**
     * @brief The JWT token
     */
    std::string jwt_token;
};

class ConfigJwtFactory : public ConfigFactoryInterface {
  public:
    std::unique_ptr<Config> create() override {
        return std::make_unique<ConfigJwt>();
    }
};

#endif //PVXS_CONFIGJWT_H_
