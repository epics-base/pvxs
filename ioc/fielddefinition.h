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
class FieldDefinition {
public:
    std::string name;                       // Field's name
    std::string channel;                    // Database record name aka channel
    std::string structureId;                // Field's Normative Type structure ID or any other arbitrary string if not a normative type
    std::string type;                       // Database field type
    TriggerNames triggerNames;                  // Fields in this group which are posted on events from channel
    int64_t putOrder;                       // Order to serialise the field for put operations

    FieldDefinition(const FieldConfig& fieldConfig, const std::string& fieldName);

    bool operator<(const FieldDefinition& o) const {
        return putOrder < o.putOrder;
    }
};

typedef std::vector<FieldDefinition> FieldDefinitions;
typedef std::map<std::string, size_t> FieldDefinitionMap;

} // pvxs
} // ioc
#endif //PVXS_FIELDDEFINITION_H
