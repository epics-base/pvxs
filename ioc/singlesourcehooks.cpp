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
#include <dbServer.h>
#include <epicsExport.h>

#define PVXS_ENABLE_EXPERT_API

#include <pvxs/util.h>
#include <pvxs/source.h>
#include <pvxs/server.h>
#include <pvxs/iochooks.h>

#include "iocshcommand.h"
#include "singlesource.h"

// include last to avoid clash of #define printf with other headers
#include <epicsStdio.h>

namespace pvxs {
namespace ioc {
void pvxsl(int detail) {
    if (auto srv = ioc::server()) {
        // For each registered source/IOID pair print a line of either detailed or regular information
        for (auto& pair: srv.listSource()) {
            auto& record = pair.first;
            auto& ioId = pair.second;

            auto source = srv.getSource(record, ioId);
            if (!source) {
                // if the source is not yet available in the server then we're in a race condition
                // silently skip source
                continue;
            }

            auto list = source->onList();

            if (list.names && !list.names->empty()) {
                if (detail) {
                    printf("------------------\n");
                    printf("SOURCE: %s@%d%s\n", record.c_str(), pair.second, (list.dynamic ? " [dynamic]" : ""));
                    printf("------------------\n");
                    printf("RECORDS: \n");
                }
                for (auto& name: *list.names) {
                    if (detail) {
                        printf("  ");
                    }
                    printf("%s\n", name.c_str());
                }
            }
        }
    }
}

}
} // namespace pvxs::ioc

using namespace pvxs;
using namespace pvxs::ioc;

namespace {

void qReport(unsigned level) noexcept {
    try{
        if (auto srv = ioc::server()) {
            std::ostringstream strm;
            Detailed D(strm, (int)level);
            strm << srv;
            printf("%s", strm.str().c_str());
        }
    }catch(std::exception& e){
        fprintf(stderr, "Error in %s: %s\n", __func__, e.what());
    }
}

void qStats(unsigned *channels, unsigned *clients) noexcept {
    try{
        if (auto srv = ioc::server()) {
            auto report(srv.report(false));
            if(clients) {
                *clients = report.connections.size();
            }
            if(channels) {
                size_t nchan = 0u;
                for(auto& conn : report.connections) {
                    nchan += conn.channels.size();
                }
                *channels = nchan;
            }
        }
    }catch(std::exception& e){
        fprintf(stderr, "Error in %s: %s\n", __func__, e.what());
    }
}

int qClient(char *pBuf, size_t bufSize) noexcept {
    try {
        if(auto op = CurrentOp::current()) {
            auto& peer(op->peerName());
            const auto& cred(op->credentials());

            if(cred->method=="ca") {
                (void)epicsSnprintf(pBuf, bufSize, "q2:%s@%s",
                                    cred->account.c_str(),
                                    peer.c_str());
            } else {
                (void)epicsSnprintf(pBuf, bufSize, "q2:%s/%s@%s",
                                    cred->method.c_str(),
                                    cred->account.c_str(),
                                    peer.c_str());
            }
            return 0;
        }
    }catch(std::exception& e){
        // shouldn't really happen, but if it does once then it will probably
        // happen a lot.  So limit noise.
        static bool shown = false;
        if(!shown) {
            shown = true;
            errlogPrintf("Unexpected exception in %s: %s\n", __func__, e.what());
        }
    }
    return -1;
}

dbServer qsrv2Server = {
    ELLNODE_INIT,
    "qsrv2",
    qReport,
    qStats,
    qClient,
};

/**
 * Initialise qsrv database single records by adding them as sources in our running pvxs server instance
 *
 * @param theInitHookState the initHook state - we only want to trigger on the initHookAfterIocBuilt state - ignore all others
 */
void qsrvSingleSourceInit(initHookState theInitHookState) {
    if(!IOCSource::enabled())
        return;
    if (theInitHookState == initHookAtBeginning) {
        (void)dbRegisterServer(&qsrv2Server);
    } else
    if (theInitHookState == initHookAfterIocBuilt) {
        pvxs::ioc::server().addSource("qsrvSingle", std::make_shared<pvxs::ioc::SingleSource>(), 0);
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
    IOCShCommand<int>("pvxsl", "details",
                      "List PV names.\n")
            .implementation<&pvxsl>();

    initHookRegister(&qsrvSingleSourceInit);
}

} // namespace

// in .dbd file
//registrar(pvxsSingleSourceRegistrar)
extern "C" {
epicsExportRegistrar(pvxsSingleSourceRegistrar);
}

