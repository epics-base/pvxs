/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_VERSION_H
#define PVXS_VERSION_H

#include <epicsVersion.h>

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

// this will fail if PVXS_MAJOR_VERSION expands to an empty string
#if PVXS_MAJOR_VERSION<0
#  error Problem loading pvxs/versionNum.h
#endif

#ifndef VERSION_INT
//! Construct version number constant.
#  define VERSION_INT(V,R,M,P) ( ((V)<<24) | ((R)<<16) | ((M)<<8) | (P))
#endif

#ifndef EPICS_VERSION_INT
#  define EPICS_VERSION_INT VERSION_INT(EPICS_VERSION, EPICS_REVISION, EPICS_MODIFICATION, EPICS_PATCH_LEVEL)
#endif

//! Current library version
#define PVXS_VERSION VERSION_INT(PVXS_MAJOR_VERSION, PVXS_MINOR_VERSION, PVXS_MAINTENANCE_VERSION, 0)

//! Current library ABI version
//! @since 0.1.1
#define PVXS_ABI_VERSION VERSION_INT(PVXS_MAJOR_VERSION, PVXS_MINOR_VERSION, 0, 0)

#ifdef __GNUC__
#  define GCC_VERSION VERSION_INT(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__, 0)
#endif

// See https://mdavidsaver.github.io/pvxs/details.html#expertapi
#if defined(PVXS_EXPERT_API_ENABLED)
#  error Define PVXS_ENABLE_EXPERT_API to enable usage of Expert API.  See https://mdavidsaver.github.io/pvxs/details.html#expert-apis
#elif defined(PVXS_ENABLE_EXPERT_API)
#  define PVXS_EXPERT_API_ENABLED
#endif

namespace pvxs {

//! Library version as a string.  eg. "PVXS 1.2.3"
PVXS_API
const char *version_str();

//! @returns PVXS_VERSION captured at library compile time
PVXS_API
unsigned long version_int();

//! @returns PVXS_ABI_VERSION captured at library compile time
//! @since 0.1.1
PVXS_API
unsigned long version_abi_int();

/** Runtime ABI check.
 *
 * This test is only meaningful if it is preformed prior to any
 * other library calls.
 *
 * It is guaranteed that the library has no global constructors.
 *
 * @returns true if the header and library ABI versions match,
 *               and if the header version is not newer than the library version.
 *
 * @since 0.1.1
 */
static inline
bool version_abi_check() {
    return PVXS_ABI_VERSION==version_abi_int() && PVXS_VERSION<=version_int();
}

}

#endif // PVXS_VERSION_H
