/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_VERSION_H
#define PVXS_VERSION_H

#if defined(_WIN32) || defined(__CYGWIN__)

#  if defined(PVXS_API_BUILDING) && defined(EPICS_BUILD_DLL)
/* building library as dll */
#    define PVXS_API __declspec(dllexport)
#  elif !defined(PVXS_API_BUILDING) && defined(EPICS_CALL_DLL)
/* calling library in dll form */
#    define PVXS_API __declspec(dllimport)
#  endif

#elif __GNUC__ >= 4
#  define PVXS_API __attribute__ ((visibility("default")))
#endif

#ifndef PVXS_API
#  define PVXS_API
#endif

#include <pvxs/versionNum.h>

#ifndef VERSION_INT
#  define VERSION_INT(V,R,M,P) ( ((V)<<24) | ((R)<<16) | ((M)<<8) | (P))
#endif

#define PVXS_VERSION VERSION_INT(PVXS_MAJOR_VERSION, PVXS_MINOR_VERSION, PVXS_MAINTENANCE_VERSION, 0)

#ifdef __GNUC__
#  define GCC_VERSION VERSION_INT(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__, 0)
#endif

namespace pvxs {

//! Library version as a string
PVXS_API
const char *version_str();

//! Value of PVXS_VERSION captured at library compile time
PVXS_API
unsigned long version_int();

/** Free some internal global allocations to avoid false positives in
 *  valgrind (or similar) tools looking for memory leaks.
 *
 * @warning Use with caution!
 *
 * @pre Release all resources explicitly allocated through PVXS.
 * @post Invalidates internal state.
 *       Use of __any__ API functions afterwards is undefined!
 */
PVXS_API
void cleanup_for_valgrind();

}

#endif // PVXS_VERSION_H
