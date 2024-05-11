/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUPCONFIG_H
#define PVXS_GROUPCONFIG_H

#include <string>

#include "fieldconfig.h"

namespace pvxs {
namespace ioc {
/**
 * Class to store the group configuration as it is read in.  It is subsequently
 * read into the Group Definition class, for intermediate use, before finally Group for runtime use
 *  Initialise:   GroupConfig ==> GroupDefinition ==> Group   :Running
 */
class GroupConfig {
public:
    bool atomic, atomicIsSet;
    std::string structureId;
    std::map<std::string, FieldConfig> fieldConfigMap;
    GroupConfig()
            :atomic(true), atomicIsSet(false) {
    }
};

} // pvxs
} // ioc

#endif //PVXS_GROUPCONFIG_H
