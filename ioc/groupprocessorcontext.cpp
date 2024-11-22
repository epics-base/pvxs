/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */
#include <string>

#include "groupprocessorcontext.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {

/**
 * Assign the given value appropriately given the current context.
 * The context holds the current field, key, depth, etc.
 *
 * @param value the value to assign
 */
void GroupProcessorContext::assign(const Value& value) {
    canAssign();
    auto& groupPvConfig = groupConfigProcessor->groupConfigMap[groupName];

    if (depth == 2) {
        if (field == "+atomic") {
            groupPvConfig.atomic = value.as<bool>();
            groupPvConfig.atomicIsSet = true;

        } else if (field == "+id") {
            groupPvConfig.structureId = value.as<std::string>();

        } else {
            groupConfigProcessor->groupProcessingWarnings += SB()<<"Unknown group option: \""<<field<<"\"\n";
        }
        field.clear();

    } else if (depth == 3) {
        auto& groupField = groupPvConfig.fieldConfigMap[field];

        if (key == "+type") {
            auto tname = value.as<std::string>();
            MappingInfo::type_t type = groupField.info.type;
            if(tname == "scalar") {
                type = MappingInfo::Scalar;
            } else if(tname == "plain") {
                type = MappingInfo::Plain;
            } else if(tname == "any") {
                type = MappingInfo::Any;
            } else if(tname == "meta") {
                type = MappingInfo::Meta;
            } else if(tname == "proc") {
                type = MappingInfo::Proc;
            } else if(tname == "structure") {
                type = MappingInfo::Structure;
            } else if(tname == "const") {
                type = MappingInfo::Const;
            } else {
                groupConfigProcessor->groupProcessingWarnings += SB()<<"Unknown mapping +type:\""<<tname<<"\" ignored\n";
            }
            groupField.info.type = type;

        } else if (key == "+channel") {
            groupField.channel = channelPrefix + value.as<std::string>();

        } else if (key == "+id") {
            groupField.structureId = value.as<std::string>();

        } else if (key == "+trigger") {
            groupField.trigger = value.as<std::string>();

        } else if (key == "+putorder") {
            auto po(value.as<int64_t>());
            if(po==std::numeric_limits<int64_t>::min())
                po += 1;
            groupField.info.putOrder = po;

        } else if (key == "+const") {
            groupField.info.cval = value;

        } else {
            groupConfigProcessor->groupProcessingWarnings += SB()<<"Unknown group field option: \""<<field<<":"<<key<<"\"\n";
        }
        key.clear();
    }
}

} // pvxs
} // ioc
