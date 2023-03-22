/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUPDEFINITION_H
#define PVXS_GROUPDEFINITION_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include "fielddefinition.h"
#include "typeutils.h"

namespace pvxs {
namespace ioc {

/**
 * channel trigger map, maps field name to set of related field it is triggered by
 */
typedef std::map<std::string, TriggerNames> FieldTriggerMap;

/**
 * A Group PV
 * This class represents a group PV.  It contains a set of channels
 * `GroupPvChannels` that link the group to regular db channels.  Each of these channels
 * define fields that are scalar, array or processing placeholders
 */
class GroupDefinition {
public:
    std::string structureId;            // The Normative Type structure ID or any other arbitrary string if not a normative type
    bool hasTriggers{ false };
    TriState atomic{ Unset };
    FieldDefinitions fields;            // The group's fields
    FieldDefinitionMap fieldMap;        // The field map, mapping field order
    FieldTriggerMap fieldTriggerMap;    // The trigger map, mapping fields to related triggering fields

    GroupDefinition() = default;
    virtual ~GroupDefinition() = default;
};

// A map of group name to GroupPv
typedef std::map<std::string, GroupDefinition> GroupDefinitionMap;

} // pvxs
} // ioc

#endif //PVXS_GROUPDEFINITION_H
