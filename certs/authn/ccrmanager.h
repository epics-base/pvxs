// Created on 19/09/2024.
//

#ifndef PVXS_CCRMANAGER_H_
#define PVXS_CCRMANAGER_H_

#include "security.h"

namespace pvxs {
namespace certs {

class CCRManager {
   public:
    std::string createCertificate(const std::shared_ptr<CertCreationRequest>& cert_creation_request, double timeout) const;
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CCRMANAGER_H_
