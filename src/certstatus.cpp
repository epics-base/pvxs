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

/**
 * @brief Constructor for the OCSPStatus class
 *
 * @param ocsp_status the OCSP status
 * @param ocsp_bytes the OCSP response bytes
 * @param status_date the date of the OCSP certificate status
 * @param status_valid_until_time the valid-until date of the OCSP certificate status
 * @param revocation_time the revocation date of the certificate if it is revoked
 */
OCSPStatus::OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t> &ocsp_bytes, StatusDate status_date, StatusDate status_valid_until_time,
                       StatusDate revocation_time)
    : ocsp_bytes(ocsp_bytes),
      ocsp_status(ocsp_status),
      status_date(status_date),
      status_valid_until_date(status_valid_until_time),
      revocation_date(revocation_time) {};

/**
 * @brief Initialise the OCSPStatus object
 *
 * @param trusted_store_ptr the trusted store to use for parsing the OCSP response
 */
void OCSPStatus::init(X509_STORE *trusted_store_ptr) {
    if (ocsp_bytes.empty()) {
        ocsp_status = (OCSPCertStatus)OCSP_CERTSTATUS_UNKNOWN;
        status_date = time(nullptr);
    } else {
        auto parsed_status = CertStatusManager::parse(ocsp_bytes, trusted_store_ptr);
        ocsp_status = std::move(parsed_status.ocsp_status);
        status_date = std::move(parsed_status.status_date);
        status_valid_until_date = std::move(parsed_status.status_valid_until_date);
        revocation_date = std::move(parsed_status.revocation_date);
    }
}

/**
 * @brief Convert a PVACertificateStatus to a CertificateStatus
 *
 * @param rhs The PVACertificateStatus to convert
 * @return CertificateStatus The converted CertificateStatus
 */
PVACertificateStatus::operator CertificateStatus() const noexcept {
    return (status == UNKNOWN) ? (CertificateStatus)UnknownCertificateStatus{} : CertifiedCertificateStatus{*this};
}

/**
 * @brief Convert an OCSPStatus to a CertificateStatus
 *
 * @param rhs The OCSPStatus to convert
 * @return CertificateStatus The converted CertificateStatus
 */
OCSPStatus::operator CertificateStatus() const noexcept {
    return (ocsp_status == OCSP_CERTSTATUS_UNKNOWN) ? (CertificateStatus)UnknownCertificateStatus{} : CertifiedCertificateStatus{*this};
}

/**
 * @brief Compare an OCSPStatus with a CertificateStatus
 *
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the CertificateStatus, false otherwise
 */
bool OCSPStatus::operator==(const CertificateStatus &rhs) const {
    return this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date && this->status_valid_until_date == rhs.status_valid_until_date &&
           this->revocation_date == rhs.revocation_date;
}

/**
 * @brief Compare an OCSPStatus with a PVACertificateStatus
 *
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the PVACertificateStatus, false otherwise
 */
bool OCSPStatus::operator==(const PVACertificateStatus &rhs) const { return (CertificateStatus) * this == rhs; }

/**
 * @brief Compare a PVACertificateStatus with a CertificateStatus
 *
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the PVACertificateStatus is equal to the CertificateStatus, false otherwise
 */
bool PVACertificateStatus::operator==(const CertificateStatus &rhs) const {
    return this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
           this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
}

/**
 * @brief Compare an OCSPStatus with a PVACertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the PVACertificateStatus, false otherwise
 */
bool operator==(ocspcertstatus_t &lhs, PVACertificateStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare an OCSPStatus with a PVACertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the OCSPStatus is not equal to the PVACertificateStatus, false otherwise
 */
bool operator!=(ocspcertstatus_t &lhs, PVACertificateStatus &rhs) { return rhs != lhs; };

/**
 * @brief Compare a CertificateStatus with a PVACertificateStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the CertificateStatus is equal to the PVACertificateStatus, false otherwise
 */
bool operator==(certstatus_t &lhs, PVACertificateStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare a CertificateStatus with a PVACertificateStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The PVACertificateStatus to compare with
 * @return bool True if the CertificateStatus is not equal to the PVACertificateStatus, false otherwise
 */
bool operator!=(certstatus_t &lhs, PVACertificateStatus &rhs) { return rhs != lhs; };

/**
 * @brief Compare an OCSPStatus with a CertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the OCSPStatus is equal to the CertificateStatus, false otherwise
 */
bool operator==(ocspcertstatus_t &lhs, OCSPStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare an OCSPStatus with a CertificateStatus
 *
 * @param lhs The OCSPStatus to compare with
 * @param rhs The CertificateStatus to compare with
 * @return bool True if the OCSPStatus is not equal to the CertificateStatus, false otherwise
 */
bool operator!=(ocspcertstatus_t &lhs, OCSPStatus &rhs) { return rhs != lhs; };

/**
 * @brief Compare a CertificateStatus with an OCSPStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The OCSPStatus to compare with
 * @return bool True if the CertificateStatus is equal to the OCSPStatus, false otherwise
 */
bool operator==(certstatus_t &lhs, OCSPStatus &rhs) { return rhs == lhs; };

/**
 * @brief Compare a CertificateStatus with an OCSPStatus
 *
 * @param lhs The CertificateStatus to compare with
 * @param rhs The OCSPStatus to compare with
 * @return bool True if the CertificateStatus is not equal to the OCSPStatus, false otherwise
 */
bool operator!=(certstatus_t &lhs, OCSPStatus &rhs) { return rhs != lhs; };

CertificateStatus ParsedOCSPStatus::status() {
    return {true, (PVACertStatus)(ocsp_status == OCSP_CERTSTATUS_GOOD ? VALID : UNKNOWN), ocsp_status, status_date, status_valid_until_date, revocation_date};
}
}  // namespace certs
}  // namespace pvxs
