/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>
#include <sstream>

#include "group.h"

namespace pvxs {
namespace ioc {

/**
 * Show details for this group.
 * This displays information to the terminal and is to be used by the IOC command shell
 *
 * @param level the level of detail to show.
 *   0 group names only,
 *   1 group names and top level information,
 *   2 everything
 */
void Group::show(int level) const {
    // no locking as we only print things which are const after initialization

    // Group field information
    printf("  Atomic Get/Put:%s Atomic Monitor:%s Members:%ld\n",
            (atomicPutGet ? "yes" : "no"),
            (atomicMonitor ? "yes" : "no"),
            fields.size());

    // If we need to show detailed information then iterate through all fields showing details
    if (level > 1) {
        if (!fields.empty()) {
            for (auto& field: fields) {
                if (!field.id.empty()) {
                    std::string suffix;
                    printf("    ");
                    suffix = "<id>";
                    field.fieldName.show(suffix);
                    printf(" <-> \"%s\"\n", field.id.c_str());
                }

                if (field.value.channel) {
                    printf("    ");
                    std::string suffix;
                    if (field.isMeta) {
                        suffix = "<meta>";
                    } else if (field.allowProc) {
                        suffix = "<proc>";
                    }
                    field.fieldName.show(suffix);
                    if (field.value.channel) {
                        printf(" <-> %s\n", dbChannelName(field.value.channel));
                    }
                }
            }
        }
    }
}

/**
 * De-reference the field in the current group by providing the field name.
 *
 * @param fieldName of the field to be de-referenced
 * @return the de-referenced field from the set of fields
 */
Field& Group::operator[](const std::string& fieldName) {
    auto foundField = std::find_if(fields.begin(), fields.end(), [fieldName](Field& field) {
        return fieldName == field.fullName;
    });

    if (foundField == fields.end()) {
        std::ostringstream fileNameStream;
        fileNameStream << "field not found in group: \"" << fieldName << "\"";
        throw std::logic_error(fileNameStream.str());
    };

    return *foundField;
}

} // pvxs
} // ioc
