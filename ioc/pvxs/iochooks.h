/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_IOCHOOKS_H
#define PVXS_IOCHOOKS_H

#include <pvxs/version.h>

#if defined(_WIN32) || defined(__CYGWIN__)

#  if defined(PVXS_IOC_API_BUILDING) && defined(EPICS_BUILD_DLL)
/* building library as dll */
#    define PVXS_IOC_API __declspec(dllexport)
#  elif !defined(PVXS_IOC_API_BUILDING) && defined(EPICS_CALL_DLL)
/* calling library in dll form */
#    define PVXS_IOC_API __declspec(dllimport)
#  endif

#elif __GNUC__ >= 4
#  define PVXS_IOC_API __attribute__ ((visibility("default")))
#endif

#ifndef PVXS_IOC_API
#  define PVXS_IOC_API
#endif

namespace pvxs {
namespace server {
class Server;
}
namespace ioc {

/** Return the singleton Server instance which is setup
 *  for use in an IOC process.
 *
 *  This Server instance is created during a registrar function,
 *  started by the initHookAfterCaServerRunning phase of iocInit().
 *  It is stopped and destroyed during an epicsAtExit() hook added
 *  during an initHookAfterInitDatabase hook..
 *
 *  Any configuration changes via. epicsEnvSet() must be made before registrars are run
 *  by \*_registerRecordDeviceDriver(pdbbase).
 *
 *  server::SharedPV and server::Source added before iocInit() will be available immediately.
 *  Others may be added (or removed) later.
 *
 *  @throws std::logic_error if called before instance is created, or after instance is destroyed.
 *
 * @code
 * static void myinitHook(initHookState state) {
 *     if(state!=initHookAfterIocBuilt)
 *         return;
 *
 *     server::SharedPV mypv(...);
 *     ioc::server()
 *           .addPV("my:pv:name", mypv);
 * }
 * static void myregistrar() {
 *     initHookRegister(&myinitHook);
 * }
 * extern "C" {
 *      // needs matching "registrar(myregistrar)" in .dbd
 *     epicsExportRegistrar(myregistrar);
 * }
 * @endcode
 */
PVXS_IOC_API
server::Server server();

/**
 * Load JSON group definition file.
 * This function does not actually parse the given file, but adds it to the list of files to be loaded,
 * at the appropriate time in the startup process.
 *
 * @param jsonFilename the json file containing the group definitions
 * @param macros NULL, or a comma separated list of macro definitions.  eg. "KEY=VAL,OTHER=SECOND"
 * @return 0 for success, 1 for failure
 * @since 1.2.0
 */
PVXS_IOC_API
long dbLoadGroup(const char* jsonFilename, const char* macros=nullptr);

/** Call just after testdbPrepare()
 *
 *  Prepare QSRV for re-test.  Optional if testdbPrepare() called only once.
 *  Required after subsequent calls.
 *  @since 1.2.3
 */
PVXS_IOC_API
void testPrepare();

/** Call just before testIocShutdownOk()
 *
 *  Shutdown QSRV.  Only needed with Base <= 7.0.4 .
 *  Since 7.0.4, QSRV shutdown occurs during testIocShutdownOk() .
 *  @since 1.2.0
 */
PVXS_IOC_API
void testShutdown();

}} // namespace pvxs::ioc
#endif // PVXS_IOCHOOKS_H
