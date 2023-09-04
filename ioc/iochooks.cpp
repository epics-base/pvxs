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
#include <epicsExit.h>
#include <initHooks.h>
#include <iocsh.h>

#include <pvxs/iochooks.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/source.h>

#include "iocshcommand.h"
#include "utilpvt.h"

// include last to avoid clash of #define printf with other headers
#include <epicsStdio.h>

#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 4, 0)
#  define USE_DEINIT_HOOKS
#endif

namespace pvxs {
namespace ioc {

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

DEFINE_LOGGER(_logname, "pvxs.ioc");

void printIOCShError(const std::exception& e)
{
    fprintf(stderr, "Error: %s\n", e.what());
}

namespace {
// The pvxs server singleton
struct pvxServer_t {
    epicsMutex lock;
    server::Server srv;
} *pvxServer;

void pvxServerInit() {
    pvxServer = new pvxServer_t();
}
} // namespace

/**
 * Get the plain pvxs server instance
 *
 * @return the pvxs server instance
 */
server::Server server() {
    threadOnce<&pvxServerInit>();
    Guard (pvxServer->lock);
    if(pvxServer->srv)
        return pvxServer->srv;
    else
        throw std::logic_error("No Instance");
}

static
void initialisePvxsServer() {
    using namespace pvxs::server;

    Config conf = ::pvxs::impl::inUnitTest() ? Config::isolated() : Config::from_env();
    Server newsrv(conf);

    threadOnce<&pvxServerInit>();
    Guard G(pvxServer->lock);
    if(pvxServer->srv)
        throw std::logic_error(SB()<<__func__<<" found existing server?!?");

    pvxServer->srv = std::move(newsrv);
}

/**
 * The function to call when we exit the IOC process.  This is only installed as the callback function
 * after the database has been initialized.  This function will stop the pvxs server instance and destroy the
 * object.
 *
 * @param pep - The pointer to the exit parameter list - unused
 */
static
void pvxsAtExit(void*) noexcept {
    try {
        Guard (pvxServer->lock);
        if(auto srv = std::move(pvxServer->srv)) {
            pvxServer->srv = server::Server();
            srv.stop();
            IOCGroupConfigCleanup();
            log_debug_printf(_logname, "Stopped Server%s", "\n");
        }
    } catch(std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

void testPrepare()
{
    if(pvxServer)
        initialisePvxsServer(); // re-create server for next test cycle
}

void testShutdown()
{
#ifndef USE_DEINIT_HOOKS
    pvxsAtExit(nullptr);
#endif
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
static
void pvxsr(int detail) {
    if (auto srv = server()) {
        std::ostringstream strm;
        Detailed D(strm, detail);
        strm << srv;
        printf("%s", strm.str().c_str());
    }
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
static
void pvxsi() {
    std::ostringstream capture;
    target_information(capture);
    printf("%s", capture.str().c_str());
}

namespace {

void pvxrefshow() {
    auto refs(instanceSnapshot());
    for(auto& pair : refs) {
        if(pair.second>0u)
            printf("%s\t= %zu\n", pair.first.c_str(), pair.second);
    }
}

struct RefTrack {
    epicsMutex lock;
    std::map<std::string, size_t> refs;
} *refTrack;

void refSavedInit() {
    refTrack = new RefTrack();
}

void pvxrefsave() {
    threadOnce<&refSavedInit>();
    epicsGuard<epicsMutex> G(refTrack->lock);
    refTrack->refs = instanceSnapshot();
}

void pvxrefdiff() {
    auto cur(instanceSnapshot());
    std::map<std::string, int64_t> diff;

    threadOnce<&refSavedInit>();
    {
        epicsGuard<epicsMutex> G(refTrack->lock);

        auto& prev(refTrack->refs);

        // Both std::map will iterate in the same order.  So co-iterate.
        // Some keys may appear in one but not the other.
        auto itC = cur.begin();
        auto itP = prev.begin();
        while(true) {
            bool haveC = itC!=cur.end();
            bool haveP = itP!=prev.end();
            int ord = haveC && haveP ? itC->first.compare(itP->first) : 0;

            if(haveC && haveP && ord==0) {
                diff[itC->first] = int64_t(itC->second) - int64_t(itP->second);
                ++itC;
                ++itP;

            } else if(haveP && (!haveC || ord > 0)) { // !cur || cur > prev
                diff[itP->first] = -int64_t(itP->second);
                ++itP;

            } else if(haveC && (!haveP || ord < 0)) { // !prev || cur < prev
                diff[itC->first] = int64_t(itC->second);
                ++itC;

            } else {
                break;
            }
        }
    }

    for(auto& pair : diff) {
        if(pair.second!=0u)
            printf("%s\t= %lld\n", pair.first.c_str(), (long long)pair.second);
    }
}

} // namespace

/**
 * Initialise and control state of pvxs ioc server instance in response to iocInitHook events.
 * Installed on the initHookState hook this function will respond to the following events:
 *  - initHookAfterInitDatabase: 		Set the exit callback only when we have initialized the database
 *  - initHookAfterCaServerRunning: 	Start the pvxs server instance after the CA server starts running
 *  - initHookAfterCaServerPaused: 		Pause the pvxs server instance if the CA server pauses
 *
 * @param theInitHookState the initHook state to respond to
 */
static
void pvxsInitHook(initHookState theInitHookState) {
    switch(theInitHookState) {
    case initHookAfterInitDatabase:
        // when de-init hooks not available, register for later cleanup via atexit()
        // function to run before exitDatabase
#ifndef USE_DEINIT_HOOKS
        epicsAtExit(&pvxsAtExit, nullptr);
#endif
        break;
    case initHookAfterCaServerRunning:
    case initHookAfterIocRunning:
        if(auto srv = server()) {
            srv.start();
            log_debug_printf(_logname, "Started Server%s", "\n");
        }
        break;
    case initHookAfterCaServerPaused:
        if(auto srv = server()) {
            srv.stop();
            log_debug_printf(_logname, "Stopped Server%s", "\n");
        }
        break;
#ifdef USE_DEINIT_HOOKS
    // use de-init hook when available
    case initHookAtShutdown:
        pvxsAtExit(nullptr);
        break;
#endif
    default:
        break;
    }
}

}
} // namespace pvxs::ioc

using namespace pvxs::ioc;

namespace {

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

        pvxServer = new pvxServer_t();

        IOCShCommand<int>("pvxsr", "[show_detailed_information?]", "PVXS Server Report.  "
                                                                   "Shows information about server config (level==0)\n"
                                                                   "or about connected clients (level>0).\n")
                .implementation<&pvxsr>();
        IOCShCommand<>("pvxsi", "Show detailed server information\n").implementation<&pvxsi>();

        IOCShCommand<>("pvxrefshow",
                       "Show instance counts for various internal data structures.\n").implementation<&pvxrefshow>();
        IOCShCommand<>("pvxrefsave",
                       "Save the current set of instance counters for reference by later pvxrefdiff.\n").implementation<&pvxrefsave>();
        IOCShCommand<>("pvxrefdiff",
                       "Show different of current instance counts with those when pvxrefsave was called.\n").implementation<&pvxrefdiff>();

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
