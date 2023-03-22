/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

/**
 * This source file defines the pvxs IOC server instance and also defines a few high level IOC shell commands from PVXS
 * It does not register any database sources defined in any user DB file or user group file, that is
 * handled in records.cpp and groups.cpp respectively.
 */
#include <atomic>
#include <memory>
#include <stdexcept>

#include <epicsExport.h>
#include <initHooks.h>
#include <iocsh.h>

#include <pvxs/iochooks.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/source.h>

#include "iocserver.h"
#include "iocshcommand.h"

// must include after log.h has been included to avoid clash with printf macro
#include <epicsStdio.h>

#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 4, 0)
#  define USE_DEINIT_HOOKS
#endif

namespace pvxs {
namespace ioc {

DEFINE_LOGGER(_logname, "pvxs.ioc");

// The pvxs server singleton
std::atomic<IOCServer*> pvxsServer{};

/**
 * Get the plain pvxs server instance
 *
 * @return the pvxs server instance
 */
server::Server& server() {
    return iocServer();
}

/**
 * Get the pvxs server instance
 *
 * @return the pvxs server instance
 */
IOCServer& iocServer() {
    if (auto pPvxsServer = pvxsServer.load()) {
        return *pPvxsServer;
    } else {
        throw std::logic_error("No Instance");
    }
}

/**
 * Get the pvxs server and execute the given function against it
 *
 * @param function the function to call
 * @param method the string method from which this is called.  Use the __func__ macro by default
 * @param context the activity being attempted when the error occurred
 */
void
runOnServer(const std::function<void(IOCServer*)>& function, const char* method, const char* context) {
    try {
        if (auto pPvxsServer = pvxsServer.load()) {
            function(pPvxsServer);
        }
    } catch (std::exception& e) {
        if (context) {
            fprintf(stderr, "%s: ", context);
        }
        if (method) {
            fprintf(stderr, "Error in %s: ", method);
        }
        fprintf(stderr, "%s\n", e.what());
        throw e;
    }
}

/**
 * The function to call when we exit the IOC process.  This is only installed as the callback function
 * after the database has been initialized.  This function will stop the pvxs server instance and destroy the
 * object.
 *
 * @param pep - The pointer to the exit parameter list - unused
 */
void pvxsAtExit(void* pep) {
    runOnPvxsServerWhile_("In IOC exit event handler", [](IOCServer* pPvxsServer) {
        if (pvxsServer.compare_exchange_strong(pPvxsServer, nullptr)) {
            // take ownership
            std::unique_ptr<IOCServer> serverInstance(pPvxsServer);
            serverInstance->stop();
            log_debug_printf(_logname, "Stopped Server%s", "\n");
        }
    });
}

////////////////////////////////////
// Two ioc shell commands for pvxs
////////////////////////////////////

/**
 * Show the PVXS server report.
 * The server report is a short list of the EPICS PVA environment variables and
 * a list of registered sources with their IOIDs.
 *
 * @param detail
 */
void pvxsr(int detail) {
    runOnPvxsServer([&detail](IOCServer* pPvxsServer) {
        std::ostringstream strm;
        Detailed D(strm, detail);
        strm << *pPvxsServer;
        printf("%s", strm.str().c_str());
    });
}

/**
 * Show information about the PVXS host.
 *
 * Includes:
 *  - OS,
 *  - build toolchain,
 *  - library versions,
 *  - runtime environment information including:
 *    - network address and
 *    - thread count, and
 *  - EPICS PVA environment variable settings
 */
void pvxsi() {
    try {
        std::ostringstream capture;
        target_information(capture);
        printf("%s", capture.str().c_str());
    } catch (std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

/**
 * Initialise and control state of pvxs ioc server instance in response to iocInitHook events.
 * Installed on the initHookState hook this function will respond to the following events:
 *  - initHookAfterInitDatabase: 		Set the exit callback only when we have initialized the database
 *  - initHookAfterCaServerRunning: 	Start the pvxs server instance after the CA server starts running
 *  - initHookAfterCaServerPaused: 		Pause the pvxs server instance if the CA server pauses
 *
 * @param theInitHookState the initHook state to respond to
 */
void pvxsInitHook(initHookState theInitHookState) {
    // iocBuild()
    if (theInitHookState == initHookAfterInitDatabase) {
        // function to run before exitDatabase
#ifndef USE_DEINIT_HOOKS
        epicsAtExit(&pvxsAtExit, nullptr);
#endif
    } else
        // iocRun()
    if (theInitHookState == initHookAfterCaServerRunning || theInitHookState == initHookAfterIocRunning) {
        runOnPvxsServer([](IOCServer* pPvxsServer) {
            pPvxsServer->start();
            log_debug_printf(_logname, "Started Server %p", pPvxsServer);
        });
    } else
        // iocPause()
    if (theInitHookState == initHookAfterCaServerPaused) {
        runOnPvxsServer([](IOCServer* pPvxsServer) {
            pPvxsServer->stop();
            log_debug_printf(_logname, "Stopped Server %p", pPvxsServer);
        });
    } else

#ifdef USE_DEINIT_HOOKS
        // iocShutdown()  (called from exitDatabase() at exit, and testIocShutdownOk() )
    if (theInitHookState == initHookAtShutdown) {
        pvxsAtExit(nullptr);
    }
#endif
}

}
} // namespace pvxs::ioc

using namespace pvxs::ioc;

namespace {

// Initialise the pvxs server instance
void initialisePvxsServer();

// Register callback functions to be used in the IOC shell and also during initialization.
void pvxsBaseRegistrar();

/**
 * Create the pvxs server instance.  We use the global pvxsServer atomic
 */
void initialisePvxsServer() {
    using namespace pvxs::server;
    auto serv = pvxsServer.load();
    if (!serv) {
        std::unique_ptr<IOCServer> temp(new IOCServer(Config::from_env()));

        if (pvxsServer.compare_exchange_strong(serv, temp.get())) {
            log_debug_printf(_logname, "Installing Server %p\n", temp.get());
            (void)temp.release();
        } else {
            log_crit_printf(_logname, "Race installing Server? %p\n", serv);
        }
    } else {
        log_err_printf(_logname, "Stale Server? %p\n", serv);
    }
}

/**
 * IOC pvxs base registrar.  This implements the required registrar function that is called by xxxx_registerRecordDeviceDriver,
 * the auto-generated stub created for all IOC implementations.
 *
 * It is registered by using the `epicsExportRegistrar()` macro.
 *
 * 1. Specify here all of the commands that you want to be registered and available in the IOC shell.
 * 2. Also make sure that you initialize your server implementation - PVXS in our case - so that it will be available for the shell.
 * 3. Lastly register your hook handler to handle any state hooks that you want to implement
 */
void pvxsBaseRegistrar() {
    try {
        pvxs::logger_config_env();

        IOCShCommand<int>("pvxsr", "[show_detailed_information?]", "PVXS Server Report.  "
                                                                   "Shows information about server config (level==0)\n"
                                                                   "or about connected clients (level>0).\n")
                .implementation<&pvxsr>();
        IOCShCommand<>("pvxsi", "Show detailed server information\n").implementation<&pvxsi>();

        // Initialise the PVXS Server
        initialisePvxsServer();

        // Register our hook handler to intercept certain state changes
        initHookRegister(&pvxsInitHook);
    } catch (std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}
} // namespace

extern "C" {
epicsExportRegistrar(pvxsBaseRegistrar);
}
