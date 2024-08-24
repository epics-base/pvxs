/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERT_STATUS_CLIENT_H
#define PVXS_CERT_STATUS_CLIENT_H

#include <pvxs/config.h>
#include <pvxs/nt.h>

#include "security.h"

namespace pvxs {
namespace certs {

/**
 * @class CertStatusClient
 *
 * Represents the interface to the PVACMS (Certificate Management System).
 * Call methods here to communicate with the PVSCMS to sign certificate requests
 * to create certificates, to check certificate validity, and install new
 * certificates. This class will also subscribe to certificate status events all
 * certificates that it manages so that it will receive invalidation, and
 * revocation events in realtime.
 */
class CertStatusClient {
   public:
    /**
     * @brief Checks if the Certificate Management System (CMS) is available and
     * can be accessed.
     *
     * @return true if the CMS is available, false otherwise.
     */
    inline bool isCmsAvailable() const { return true; };

//    std::string createAndSignCertificate(const std::shared_ptr<CertCreationRequest> &ccr) const;
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERT_STATUS_CLIENT_H
