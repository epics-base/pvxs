/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>

#include <string.h>

#include "fielddefinition.h"

namespace pvxs {
namespace ioc {

/**
 * Part of the second pass group configuration processing. This is the constructor for a group field configuration
 * object.
 *
 * @param fieldConfig the first stage field configuration object it will be based on
 * @param fieldName the name of the field
 */
FieldDefinition::FieldDefinition(const FieldConfig& fieldConfig, const std::string& fieldName)
        :FieldConfig(fieldConfig)
        ,name(fieldName)
{}

}
}
