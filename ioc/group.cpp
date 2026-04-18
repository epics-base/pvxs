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

#include <epicsThread.h>
#include <cantProceed.h>

#include "group.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {

static
IOCGroupConfig* configInstance;

static
void onceConfigInstance()
{
    try {
        configInstance = new IOCGroupConfig;
    } catch (std::exception& e) {
        cantProceed("ERROR %s : %s\n", __func__, e.what());
    }
}

IOCGroupConfig& IOCGroupConfig::instance()
{
    threadOnce<&onceConfigInstance>();
    return *configInstance;
}

void IOCGroupConfigCleanup()
{
    if(configInstance) {
        epicsGuard<epicsMutex> G(configInstance->groupMapMutex);
        configInstance->groupMap.clear();
        configInstance->groupConfigFiles.clear();
    }
}

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
    printf("  Atomic Get/Put:%s Atomic Members:%ld\n",
            (atomicPutGet ? "yes" : "no"),
            fields.size());

    // If we need to show detailed information then iterate through all fields showing details
    if (level > 1) {
        for (auto& field: fields) {
            // "  grp.fld <meta> id=foo chan=pv:name.VAL\n"
            printf("  %s\t<%s>%s%s%s%s%s\n",
                   field.fieldName.to_string().c_str(),
                   MappingInfo::name(field.info.type),
                   field.id.empty() ? "" : " id=",
                   field.id.empty() ? "" : field.id.c_str(),
                   field.value ? " chan=" : "",
                   field.value ? dbChannelName(field.value) : "",
                   field.triggers.empty() ? "" : " has triggers");

            if(level > 2) {
                for(auto& trig : field.triggers) {
                    bool found = false;
                    for(auto& field2 : fields) {
                        found |= &field2 == trig; // cross-check pointer validity
                    }
                    if(!found)
                        printf("ERROR inconsistent field triggers!!!\n");
                    printf("    %s\n", trig->fieldName.to_string().c_str());
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
    for(auto& field : fields) {
        if(field.fullName == fieldName)
            return field;
    }
    throw std::logic_error(SB()<<"field not found in group: \"" << fieldName << "\"");
}

} // pvxs
} // ioc
