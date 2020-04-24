/**
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
 *  This Server instance is created during in a registrar function,
 *  started by the initHookAfterCaServerRunning phase of iocInit(),
 *  and stopped and destroyed via an epicsAtExit() hook.
 *
 *  Any configuration changes via. epicsEnvSet() must be made before registrars are run
 *  by \*_registerRecordDeviceDriver(pdbbase).
 *
 *  server::SharedPV and server::Source added before iocInit() will be available immediately.
 *  Others may be added (or removed) later.
 *
 *  @throws std::logic_error if called before instance is created, or after instance is destroyed.
 */
PVXS_IOC_API
server::Server server();

}} // namespace pvxs::ioc

#endif // PVXS_IOCHOOKS_H
