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
            groupConfigProcessor->groupProcessingWarnings += "Unknown group option ";
            groupConfigProcessor->groupProcessingWarnings += field;
        }
        field.clear();

    } else if (depth == 3) {
        auto& groupField = groupPvConfig.fieldConfigMap[field];

        if (key == "+type") {
            groupField.type = value.as<std::string>();

        } else if (key == "+channel") {
            groupField.channel = channelPrefix + value.as<std::string>();

        } else if (key == "+id") {
            groupField.structureId = value.as<std::string>();

        } else if (key == "+trigger") {
            groupField.trigger = value.as<std::string>();

        } else if (key == "+putorder") {
            groupField.putOrder = value.as<int64_t>();

        } else {
            groupConfigProcessor->groupProcessingWarnings += "Unknown group field option ";
            groupConfigProcessor->groupProcessingWarnings += field + ":" + key;
        }
        key.clear();
    }
}

} // pvxs
} // ioc
