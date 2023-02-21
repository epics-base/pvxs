/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUPPROCESSORCONTEXT_H
#define PVXS_GROUPPROCESSORCONTEXT_H

#include <string>
#include <utility>

#include "groupconfigprocessor.h"

namespace pvxs {
namespace ioc {

/**
 * Object to store contextual information while parsing the group configuration
 */
class GroupProcessorContext {
    const std::string channelPrefix;
    GroupConfigProcessor* groupConfigProcessor;

public:
    std::string groupName, field, key;
    unsigned depth; // number of '{'s
    std::string errorMessage;

    GroupProcessorContext(std::string& channelPrefix, GroupConfigProcessor* groupConfigProcessor)
            :channelPrefix(channelPrefix), groupConfigProcessor(groupConfigProcessor), depth(0u) {
    }

/**
 * Check whether anything can be assigned at the current depth within the json stream being processed.
 * Throw an exception if not
 */
    void canAssign() const {
        if (depth < 2 || depth > 3) {
            throw std::runtime_error("Can't assign value in this context");
        }
    }

    void assign(const Value& value);

};

} // pvxs
} // ioc

#endif //PVXS_GROUPPROCESSORCONTEXT_H
