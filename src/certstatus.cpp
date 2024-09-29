/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate status functions
 *
 *   certstatus.cpp
 *
 */

#include "certstatus.h"

#include "certstatusmanager.h"

namespace pvxs {
namespace certs {

OCSPStatus::OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, StatusDate status_date, StatusDate status_valid_until_time,
                       StatusDate revocation_time)
    : ocsp_bytes(ocsp_bytes),
      ocsp_status(ocsp_status),
      status_date(status_date),
      status_valid_until_date(status_valid_until_time),
      revocation_date(revocation_time) {};

void OCSPStatus::init() {
    if (ocsp_bytes.empty()) {
        ocsp_status = (OCSPCertStatus)OCSP_CERTSTATUS_UNKNOWN;
        status_date = time(nullptr);
    } else {
        auto parsed_status = CertStatusManager::parse(ocsp_bytes);
        ocsp_status = std::move(parsed_status.ocsp_status);
        status_date = std::move(parsed_status.status_date);
        status_valid_until_date = std::move(parsed_status.status_valid_until_date);
        revocation_date = std::move(parsed_status.revocation_date);
    }
}

PVACertificateStatus::operator CertificateStatus() const noexcept { return (status==UNKNOWN) ? (CertificateStatus)UncertifiedCertificateStatus{} : CertifiedCertificateStatus{*this}; }

}  // namespace certs
}  // namespace pvxs
