/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_FIELD_H
#define PVXS_FIELD_H

#include <string>
#include <map>
#include <vector>
#include <set>

#include <pvxs/nt.h>

#include "dblocker.h"
#include "channel.h"
#include "dbmanylocker.h"
#include "fielddefinition.h"
#include "fieldname.h"

namespace pvxs {
namespace ioc {

class Field {
private:
public:
    std::string id;     // For structure functionality
    std::string name;
    FieldName fieldName;
    std::string fullName;
    MappingInfo info;
    bool isArray = false;
    Channel value;
    Channel properties;
    DBManyLock lock;
    // reference to the fields that are triggered by this field during subscriptions
    // points to storage in containing Group::fields
    std::vector<Field*> triggers;

    // only for Meta mapping.  type inferred from dbChannelFinalFieldType()
    Value anyType;

    Field(const FieldDefinition& def);
    Field(const Field&) = delete;
    Field(Field&&) = default;
    Value findIn(Value valueTarget) const;
};

} // pvxs
} // ioc

#endif //PVXS_FIELD_H
