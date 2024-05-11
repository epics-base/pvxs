/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <sstream>
#include <utility>

#include "field.h"
#include "typeutils.h"

namespace pvxs {
namespace ioc {

Field::Field(const FieldDefinition &def)
    :id(def.structureId)
    ,fieldName(def.name)
    ,info(def.info)
{
    if(!def.channel.empty()) {
        value = Channel(def.channel);
        properties = Channel(def.channel);
        info.updateNsecMask(dbChannelRecord(value));
    }
    if (!fieldName.fieldNameComponents.empty()) {
        name = fieldName.fieldNameComponents[0].name;
        fullName = fieldName.to_string();

        if (fieldName.fieldNameComponents[fieldName.fieldNameComponents.size() - 1].isArray()) {
            isArray = true;
        }

    }
    if(info.type == MappingInfo::Any) {
        // pre-compute the type which will be stored in the Any field
        auto type = fromDbrType(dbChannelFinalFieldType(value));
        if (dbChannelFinalElements(value) != 1) {
            type = type.arrayOf();
        }
        anyType = TypeDef(type).create();
    }
}

/**
 * Using the field components configured in this Field, walk down from the given value,
 * to arrive at the part of the value referenced by this field.
 *
 * @param valueTarget the given value to search in
 * @return the Value referenced by this field within the given value
 */
Value Field::findIn(Value valueTarget) const {
    if (!fieldName.empty()) {
        for (const auto& component: fieldName.fieldNameComponents) {
            valueTarget = valueTarget[component.name];
            if (component.isArray()) {
                // Get required array capacity
                auto index = component.index;
                auto constValueArray = valueTarget.as<shared_array<const Value>>();
                valueTarget = shared_array<const Value>();
                shared_array<Value> valueArray(constValueArray.thaw());
                auto size = valueArray.size();
                if ((index + 1) > size) {
                    valueArray.resize(index + 1);
                }

                // Put new data into array
                auto newElement = valueArray[index];
                if (!newElement) {
                    // Only allocate new member if it is not already allocated
                    valueArray[index] = newElement = valueTarget.allocMember();
                }
                valueTarget = valueArray.freeze();
                valueTarget = newElement;
            }
        }
    }
    return valueTarget;
}

} // pvxs
} // ioc
