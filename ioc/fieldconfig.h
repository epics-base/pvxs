/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_FIELDCONFIG_H
#define PVXS_FIELDCONFIG_H

#include <string>
#include <map>

namespace pvxs {
namespace ioc {

/**
 * Class to read the group field configuration into during initialization.
 * It is subsequently read into GroupChannelField for runtime use
 */
class FieldConfig {
public:
    std::string type, channel, trigger, structureId;
    int64_t putOrder;
};

typedef std::map<std::string, FieldConfig> FieldConfigMap;

} // pvxs
} // ioc

#endif //PVXS_FIELDCONFIG_H
