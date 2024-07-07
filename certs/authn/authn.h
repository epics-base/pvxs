/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTHN_H_
#define PVXS_AUTHN_H_

class Config {
  public:
};

// Interface to create Config objects
class ConfigFactoryInterface {
  public:
    virtual Config* create() = 0;
};

#endif //PVXS_AUTHN_H_
