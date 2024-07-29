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

enum CertificateStatus { PENDING_VALIDATION, VALID, EXPIRED, REVOKED };
const char* certificateStatusToString(CertificateStatus status) {
    switch (status) {
        case PENDING_VALIDATION: return "PENDING VALIDATION";
        case VALID: return "VALID";
        case EXPIRED: return "EXPIRED";
        case REVOKED: return "REVOKED";
        default: return "UNKNOWN";
    }
}
#define RPC_SERVER_TIMEOUT 3

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
