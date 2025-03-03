/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CCRMANAGER_H_
#define PVXS_CCRMANAGER_H_

#include "security.h"

namespace pvxs {
namespace certs {

class CCRManager {
   public:
    static std::string createCertificate(const std::shared_ptr<CertCreationRequest>& cert_creation_request, double timeout);
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CCRMANAGER_H_
