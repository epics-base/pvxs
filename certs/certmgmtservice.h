/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERT_MGMT_SERVICE_H
#define PVXS_CERT_MGMT_SERVICE_H

#include <pvxs/config.h>
#include <pvxs/nt.h>

#include "security.h"

namespace pvxs {
namespace certs {

// Certificate management
#define RPC_CERT_CREATE "CERT:CREATE"
#define RPC_CERT_ROTATE_PV "CERT:ROTATE"
#define RPC_CERT_REVOKE_PV "CERT:REVOKE:????????:*"
#define GET_MONITOR_CERT_STATUS_PV "CERT:STATUS:????????:*"

// All certificate statuses
#define CERT_STATUS_LIST  \
    X_IT(UNKNOWN)            \
    X_IT(VALID)              \
    X_IT(EXPIRED)            \
    X_IT(REVOKED)            \
    X_IT(PENDING_APPROVAL)   \
    X_IT(PENDING)

// Define the enum
#define X_IT(name) name,
enum CertStatus { CERT_STATUS_LIST };
#undef X_IT

// String initializer list
#define X_IT(name) #name,
#define CERT_STATES { CERT_STATUS_LIST }
#define OCSP_CERT_STATES { "OCSP_CERTSTATUS_GOOD", "OCSP_CERTSTATUS_REVOKED", "OCSP_CERTSTATUS_UNKNOWN" }

// Gets status name based on index
#define CERT_STATE(index) ( (const char*[]) CERT_STATES[ (index) ] )
#define OCSP_CERT_STATE(index) ( (const char*[]) OCSP_CERT_STATES[ (index) ] )

/**
 * @class CertMgmtService
 *
 * Represents the interface to the PVACMS (Certificate Management System).
 * Call methods here to communicate with the PVSCMS to sign certificate requests
 * to create certificates, to check certificate validity, and install new
 * certificates. This class will also subscribe to certificate status events all
 * certificates that it manages so that it will receive invalidation, and
 * revocation events in realtime.
 */
class CertMgmtService {
   public:
    /**
     * @brief Checks if the Certificate Management System (CMS) is available and
     * can be accessed.
     *
     * @return true if the CMS is available, false otherwise.
     */
    inline bool isCmsAvailable() const { return true; };

    std::string createAndSignCertificate(const std::shared_ptr<CertCreationRequest> &ccr) const;
};

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_CERT_MGMT_SERVICE_H
