/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <vector>

#include <epicsExport.h>
#include <epicsString.h>

#include <initHooks.h>

#include <pvxs/source.h>
#include <pvxs/iochooks.h>

#include "groupsource.h"
#include "groupconfigprocessor.h"
#include "iocshcommand.h"

// must include after log.h has been included to avoid clash with printf macro
#include <epicsStdio.h>
namespace pvxs {
namespace ioc {

/**
 * IOC command wrapper for dbLoadGroup function
 *
 * @param jsonFileName
 */
void dbLoadGroupCmd(const char* jsonFileName) {
    (void)dbLoadGroup(jsonFileName);
    auto gp = GroupConfigProcessor();
    gp.loadConfigFiles();
}

/**
 * List group db record/field names that are registered with the pvxs IOC server.
 * With no arguments this will list all the group record names.
 *
 * @param level optional depth to show details for
 * @param pattern optionally only show records matching the regex pattern
 */
void pvxsgl(int level, const char* pattern) {
    runOnPvxsServer(([level, &pattern](IOCServer* pPvxsServer) {
        try {
            // Default pattern to match everything
            if (!pattern) {
                pattern = "";
            }

            {
                epicsGuard<epicsMutex> G(pPvxsServer->groupMapMutex);

                // For each group
                for (auto& mapEntry: pPvxsServer->groupMap) {
                    auto& groupName = mapEntry.first;
                    auto& group = mapEntry.second;
                    // if no pattern specified or the pattern matches
                    if (!pattern[0] || !!epicsStrGlobMatch(groupName.c_str(), pattern)) {
                        // Print the group name
                        printf("%s\n", groupName.c_str());
                        // print sub-levels if required
                        if (level > 0) {
                            group.show(level);
                        }
                    }
                }
            }
        } catch (std::exception& e) {
            fprintf(stderr, "%s\n", e.what());
        }
    }));
}

/**
 * Load JSON group definition file.
 * This function does not actually parse the given file, but adds it to the list of files to be loaded,
 * at the appropriate time in the startup process.
 *
* @param jsonFilename the json file containing the group definitions.  If filename is a dash or a dash then star, the list of
 * files is cleared. If it starts with a dash followed by a filename then file is removed from the list.  Otherwise
 * the filename is added to the list of files to be loaded.
 * @return 0 for success, 1 for failure
 */
long dbLoadGroup(const char* jsonFilename) {
    try {
        if (!jsonFilename || !jsonFilename[0]) {
            printf("dbLoadGroup(\"file.json\")\n"
                   "Load additional DB group definitions from file.\n");
            fprintf(stderr, "Missing filename\n");
            return 1;
        }

        runOnPvxsServer([&jsonFilename](IOCServer* pPvxsServer) {
            if (jsonFilename[0] == '-') {
                jsonFilename++;
                if (jsonFilename[0] == '*' && jsonFilename[1] == '\0') {
                    pPvxsServer->groupConfigFiles.clear();
                } else {
                    pPvxsServer->groupConfigFiles.remove(jsonFilename);
                }
            } else {
                pPvxsServer->groupConfigFiles.remove(jsonFilename);
                pPvxsServer->groupConfigFiles.emplace_back(jsonFilename);
            }
        });
        return 0;
    } catch (std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

}
} // namespace pvxs::ioc

using namespace pvxs::ioc;

namespace {
using namespace pvxs;

/**
 * Initialise qsrv database group records by adding them as sources in our running pvxs server instance
 *
 * @param theInitHookState the initHook state - we only want to trigger on the initHookAfterIocBuilt state - ignore all others
 */
void qsrvGroupSourceInit(initHookState theInitHookState) {
    if (theInitHookState == initHookAfterInitDatabase) {
        GroupConfigProcessor processor;
        // Parse all info(Q:Group... records to configure groups
        processor.loadConfigFromDb();

        // Load group configuration files
        processor.loadConfigFiles();

        // Configure groups
        processor.defineGroups();

        // Resolve triggers
        processor.resolveTriggerReferences();

        // Create Server Groups
        processor.createGroups();
    } else if (theInitHookState == initHookAfterIocBuilt) {
        // Load group configuration from parsed groups in iocServer
        pvxs::ioc::iocServer().addSource("qsrvGroup", std::make_shared<pvxs::ioc::GroupSource>(), 1);
    }
}

/**
 * IOC pvxs Group Source registrar.  This implements the required registrar function that is called by xxxx_registerRecordDeviceDriver,
 * the auto-generated stub created for all IOC implementations.
 *<p>
 * It is registered by using the `epicsExportRegistrar()` macro.
 *<p>
 * 1. Register your hook handler to handle any state hooks that you want to implement.  Here we install
 * an `initHookState` handler connected to the `initHookAfterIocBuilt` state.  It  will add all of the
 * group record type sources defined so far.  Note that you can define sources up until the `iocInit()` call,
 * after which point the `initHookAfterIocBuilt` handlers are called and will register all the defined records.
 */
void pvxsGroupSourceRegistrar() {
    // Register commands to be available in the IOC shell
    IOCShCommand<int, const char*>("pvxsgl", "[level, [pattern]]", "Group Sources list.\n"
                                                                   "List record/field names.\n"
                                                                   "If `level` is set then show only down to that level.\n"
                                                                   "If `pattern` is set then show records that match the pattern.")
            .implementation<&pvxsgl>();

    IOCShCommand<const char*>("dbLoadGroup", "jsonDefinitionFile", "Load Group Record Definition from given file.\n"
                                                                   "'-' or '-*' to remove previous files.\n"
                                                                   "'-<jsonDefinitionFile>' to remove the file from the list.\n"
                                                                   "otherwise add the file to the list of files to load.\n")
            .implementation<&dbLoadGroupCmd>();

    initHookRegister(&qsrvGroupSourceInit);
}

} // namespace

// in .dbd file
//registrar(pvxsGroupSourceRegistrar)
extern "C" {
epicsExportRegistrar(pvxsGroupSourceRegistrar);
}
