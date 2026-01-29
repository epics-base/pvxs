/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_OPENSSL_GBL_H
#define PVXS_OPENSSL_GBL_H

#include <fstream>

#include "ownedptr.h"

namespace pvxs {
namespace ossl {

struct OSSLGbl {
    bool tls_disabled {false};
    ossl_ptr<OSSL_LIB_CTX> libctx;
    int SSL_CTX_ex_idx;
#ifdef PVXS_ENABLE_SSLKEYLOGFILE
    file_ptr keylog;
    epicsMutex keylock;
#endif
};

PVXS_API extern OSSLGbl* ossl_gbl;

// Custom OIDs
// TODO Register these unassigned OIDs for EPICS

// "1.3.6.1.4.1" OID prefix for custom OIDs

// EPICS OID for "SPvaCertStatusURI" extension: "37427" DTMF for "EPICS" :)
#define NID_SPvaCertStatusURIID "1.3.6.1.4.1.37427.1"
#define SN_SPvaCertStatusURI "ASN.1 - SPvaCertStatusURI"
#define LN_SPvaCertStatusURI "EPICS SPVA Certificate Status URI"

// EPICS OID for "SPvaCertConfigURI" extension: "72473" DTMF for "SCIPE" :)
#define NID_SPvaCertConfigURIID "1.3.6.1.4.1.72473.1"
#define SN_SPvaCertConfigURI "ASN.1 - SPvaCertConfigURI"
#define LN_SPvaCertConfigURI "EPICS SPVA Certificate Config URI"

PVXS_API extern void osslInit();

PVXS_API extern int NID_SPvaCertStatusURI;
PVXS_API extern int NID_SPvaCertConfigURI;

}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_OPENSSL_GBL_H
