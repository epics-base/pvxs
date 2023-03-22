/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>
#include <vector>

#include <initHooks.h>
#include <epicsExport.h>

#include <pvxs/source.h>

#include "iocshcommand.h"
#include "singlesource.h"

// must include after log.h has been included to avoid clash with printf macro
#include <epicsStdio.h>

namespace pvxs {
namespace ioc {
/**
 * List single db record/field names that are registered with the pvxs IOC server
 * With no arguments this will list all the single record names.
 * With the optional showDetails arguments it will additionally display detailed information.
 *
 * @param pShowDetails if "yes", "YES", "true","TRUE", "1" then show details, otherwise don't show details
 */
void pvxsl(const char* pShowDetails) {
    runOnPvxsServer([&pShowDetails](IOCServer* pPvxsServer) {
        auto showDetails = false;

        if (pShowDetails) {
            std::string showDetailsValue(pShowDetails);
            std::transform(showDetailsValue.begin(), showDetailsValue.end(), showDetailsValue.begin(),
                    [](unsigned char c) { return std::tolower(c); });
            if (showDetailsValue == "yes" || showDetailsValue == "true" || showDetailsValue == "1") {
                showDetails = true;
            }
        }

        // For each registered source/IOID pair print a line of either detailed or regular information
        for (auto& pair: pPvxsServer->listSource()) {
            auto& record = pair.first;
            auto& ioId = pair.second;

            auto source = pPvxsServer->getSource(record, ioId);
            if (!source) {
                // if the source is not yet available in the server then we're in a race condition
                // silently skip source
                continue;
            }

            auto list = source->onList();

            if (list.names && !list.names->empty()) {
                if (showDetails) {
                    printf("------------------\n");
                    printf("SOURCE: %s@%d%s\n", record.c_str(), pair.second, (list.dynamic ? " [dynamic]" : ""));
                    printf("------------------\n");
                    printf("RECORDS: \n");
                }
                for (auto& name: *list.names) {
                    if (showDetails) {
                        printf("  ");
                    }
                    printf("%s\n", name.c_str());
                }
            }
        }
    });
}

}
} // namespace pvxs::ioc

using namespace pvxs::ioc;

namespace {

/**
 * Initialise qsrv database single records by adding them as sources in our running pvxs server instance
 *
 * @param theInitHookState the initHook state - we only want to trigger on the initHookAfterIocBuilt state - ignore all others
 */
void qsrvSingleSourceInit(initHookState theInitHookState) {
    if (theInitHookState == initHookAfterIocBuilt) {
        pvxs::ioc::iocServer().addSource("qsrvSingle", std::make_shared<pvxs::ioc::SingleSource>(), 0);
    }
}

/**
 * IOC pvxs Single Source registrar.  This implements the required registrar function that is called by xxxx_registerRecordDeviceDriver,
 * the auto-generated stub created for all IOC implementations.
 *
 * It is registered by using the `epicsExportRegistrar()` macro.
 *
 * 1. Specify here all of the commands that you want to be registered and available in the IOC shell.
 * 2. Register your hook handler to handle any state hooks that you want to implement.  Here we install
 * an `initHookState` handler connected to the `initHookAfterIocBuilt` state.  It  will add all of the
 * single record type sources defined so far.  Note that you can define sources up until the `iocInit()` call,
 * after which point the `initHookAfterIocBuilt` handlers are called and will register all the defined records.
 */
void pvxsSingleSourceRegistrar() {
    // Register commands to be available in the IOC shell
    IOCShCommand<const char*>("pvxsl", "[show_detailed_information?]", "Single Sources list.\n"
                                                                       "List record/field names.\n"
                                                                       "If `show_detailed_information?` flag is `yes`, `true` or `1` then show detailed information.\n")
            .implementation<&pvxsl>();

    initHookRegister(&qsrvSingleSourceInit);
}

} // namespace

// in .dbd file
//registrar(pvxsSingleSourceRegistrar)
extern "C" {
epicsExportRegistrar(pvxsSingleSourceRegistrar);
}

