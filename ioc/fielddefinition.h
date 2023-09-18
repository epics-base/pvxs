/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_FIELDDEFINITION_H
#define PVXS_FIELDDEFINITION_H

#include <set>
#include <string>
#include <vector>

#include <epicsTypes.h>

#include "fieldconfig.h"

namespace pvxs {
namespace ioc {

typedef std::set<std::string> TriggerNames;

/**
 * Class to store group fields definitions while they are being processed after being read from files into FieldConfig.
 */
class FieldDefinition : public FieldConfig {
public:
    std::string name;                       // Field's name
    TriggerNames triggerNames;                  // Fields in this group which are posted on events from channel

    FieldDefinition(const FieldConfig& fieldConfig, const std::string& fieldName);

    bool operator<(const FieldDefinition& o) const = delete;
};

} // pvxs
} // ioc
#endif //PVXS_FIELDDEFINITION_H
