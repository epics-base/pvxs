/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef SSLINIT_H
#define SSLINIT_H

#include <epicsMutex.h>

#include "version.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

// TODO Register these unassigned OIDs for EPICS
// "1.3.6.1.4.1" OID prefix for custom OIDs
// EPICS OID for "SPvaCertConfigURI" extension: "37427" DTMF for "EPICS" :)
#define NID_SPvaCertStatusURIID "1.3.6.1.4.1.37427.1"
#define SN_SPvaCertStatusURI "ASN.1 - SPvaCertStatusURI"
#define LN_SPvaCertStatusURI "EPICS SPVA Certificate Status URI"
// EPICS OID for "SPvaCertConfigURI" extension: "72473" DTMF for "SCIPE" :)
#define NID_SPvaCertConfigURIID "1.3.6.1.4.1.72473.1"
#define SN_SPvaCertConfigURI "ASN.1 - SPvaCertConfigURI"
#define LN_SPvaCertConfigURI "EPICS SPVA Certificate Config URI"
// EPICS OID for "SPvaRenewByDate" extension: "73639" DTMF for "RENEW" :)
#define NID_SPvaRenewByDateID "1.3.6.1.4.1.73639.1"
#define SN_SPvaRenewByDate "ASN.1 - SPvaRenewByDate"
#define LN_SPvaRenewByDate "EPICS SPVA Renew By Date"

namespace pvxs {
namespace ossl {

// Custom OIDs
extern PVXS_API int NID_SPvaCertStatusURI;
extern PVXS_API int NID_SPvaCertConfigURI;
extern PVXS_API int NID_SPvaRenewByDate;

// SSL library initialization lock
extern epicsMutex ssl_init_lock;

// Initialize the SSL library and set up the custom certificate status and config URI OIDs
extern PVXS_API void sslInit();

}  // namespace ossl
}  // namespace pvxs

#endif  // SSLINIT_H
