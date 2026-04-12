/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate status functions
 *
 *   certstatus.h
 *
 */
#ifndef PVXS_CERTSTATUS_H_
#define PVXS_CERTSTATUS_H_

#include <iomanip>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>
#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/sharedArray.h>

#include "certdate.h"
#include "evhelper.h"
#include "ownedptr.h"

#define CERT_TIME_FORMAT "%a %b %d %H:%M:%S %Y UTC"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

DEFINE_LOGGER(status_setup, "pvxs.certs.status");
DEFINE_LOGGER(status, "pvxs.certs.status");

// Define permanently valid status time
#if defined(__TIME_T_MAX__)
#define PERMANENTLY_VALID_STATUS __TIME_T_MAX__
#elif defined(__INT_MAX__)
#define PERMANENTLY_VALID_STATUS (time_t)(__INT_MAX__)
#else
PERMANENTLY_VALID_STATUS(time_t)
((~(unsigned long long)0) >> 1)
#endif

namespace pvxs {
namespace certs {

///////////// OCSP RESPONSE ERRORS
class OCSPParseException final : public std::runtime_error {
   public:
    explicit OCSPParseException(const std::string& message) : std::runtime_error(message) {}
};

class CertStatusException : public std::runtime_error {
   public:
    explicit CertStatusException(const std::string& message) : std::runtime_error(message) {}
};

class CertStatusNoExtensionException final : public CertStatusException {
   public:
    explicit CertStatusNoExtensionException(const std::string& message) : CertStatusException(message) {}
};

class CertStatusSubscriptionException final : public CertStatusException {
   public:
    explicit CertStatusSubscriptionException(const std::string& message) : CertStatusException(message) {}
};

// All certificate statuses
#define CERT_STATUS_LIST   \
    X_IT(UNKNOWN)          \
    X_IT(VALID)            \
    X_IT(PENDING)          \
    X_IT(PENDING_APPROVAL) \
    X_IT(PENDING_RENEWAL)  \
    X_IT(EXPIRED)          \
    X_IT(REVOKED)

// All OCSP certificate statuses
#define OCSP_CERT_STATUS_LIST     \
    O_IT(OCSP_CERTSTATUS_GOOD)    \
    O_IT(OCSP_CERTSTATUS_REVOKED) \
    O_IT(OCSP_CERTSTATUS_UNKNOWN)

// Define the enum
#define X_IT(name) name,
#define O_IT(name) name = V_##name,
enum certstatus_t { CERT_STATUS_LIST };
enum ocspcertstatus_t { OCSP_CERT_STATUS_LIST };
#undef X_IT
#undef O_IT

// String initializer list
#define X_IT(name) #name,
#define O_IT(name) #name,
#define CERT_STATES {CERT_STATUS_LIST}
#define OCSP_CERT_STATES {OCSP_CERT_STATUS_LIST}

// Gets status name based on index
#define CERT_STATE(index) ((const char*[])CERT_STATES[(index)])
#define OCSP_CERT_STATE(index) ((const char*[])OCSP_CERT_STATES[(index)])

// Certificate status classes
//
// Note: This is a classification of certstatus_t values into a smaller set
// used by connection logic (eg. allow/deny/defer).
//
// Must be scoped to avoid collision with certstatus_t enumerators (eg. UNKNOWN).
enum class cert_status_class_t : int {
    BAD = -1,
    UNKNOWN = 0,
    GOOD = 1,
};

// Forward declarations
struct PVACertStatus;
struct OCSPCertStatus;

/**
 * @brief Base class for Certificate status values.  Contains the enum index `i`
 * and the string representation `s` of the value for logging and comparison
 *
 * @note This class is not intended to be instantiated directly.
 * It is used as a base class for PVACertStatus and OCSPCertStatus
 */
struct CertStatus {
    // enum value of the status
    uint32_t i{0};
    // string representation of the status
    std::string s{};
    // Default constructor
    CertStatus() = default;
    CertStatus(const CertStatus&) = default;
    CertStatus& operator=(const CertStatus&) = default;

    // Move comparison operators to protected
    bool operator==(const CertStatus& rhs) const { return i == rhs.i; }
    bool operator!=(const CertStatus& rhs) const { return !(*this == rhs); }

    /**
     * @brief  Get the first 8 hex digits of the hex SKID (subject key identifier)
     *
     * Note that the given cert must contain the SKID extension in the first place
     *
     * @param cert  the cert from which to get the subject key identifier extension
     * @return first 8 hex digits of the hex SKID (subject key identifier)
     */
    static std::string getSkId(const ossl_ptr<X509>& cert) { return getSkId(cert.get()); }

    /**
     * @brief Get the first 8 hex digits of the hex SKID (subject key identifier)
     *
     * Note that the given cert must contain the SKID extension in the first place
     *
     * @param cert_ptr the cert pointer from which to get the subject key identifier extension
     * @return first 8 hex digits of the hex SKID (subject key identifier)
     */
    static std::string getSkId(const X509* cert_ptr) {
        const ossl_ptr<ASN1_OCTET_STRING> skid(static_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(cert_ptr, NID_subject_key_identifier, nullptr, nullptr)),
                                               false);
        if (!skid) {
            throw std::runtime_error("Failed to get Subject Key Identifier.");
        }

        // Convert the first 8 chars to hex
        const auto buf = skid->data;
        std::stringstream ss;
        for (int i = 0; i < skid->length && ss.tellp() < 8; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
        }

        return ss.str();
    }

   protected:
    /**
     * @brief Constructor for CertStatus only to be used by PVACertStatus and OCSPCertStatus
     *
     * @param status the enum index of the status
     * @param status_string the string representation of the status
     */
    explicit CertStatus(const uint32_t status, std::string  status_string) : i(status), s(std::move(status_string)) {}

    // Friend declarations to allow cross-comparisons only between specific types
    friend struct PVACertStatus;
    friend struct OCSPCertStatus;
};

// Forward declarations of certificate status structures
struct CertificateStatus;
struct PVACertificateStatus;

/**
 * @brief PVA Certificate status values enum and string
 */
struct PVACertStatus : CertStatus {
    /**
     * @brief Constructor for PVACertStatus
     *
     * @param status the enum index of the status
     */
    explicit PVACertStatus(const certstatus_t& status) : CertStatus(status, toString(status)) {}

    // Define the comparison operators
    bool operator==(const PVACertStatus& rhs) const { return this->i == rhs.i; }
    bool operator==(const certstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(const PVACertStatus& rhs) const { return this->i != rhs.i; }
    bool operator!=(const certstatus_t rhs) const { return this->i != rhs; }

   protected:
    friend struct PVACertificateStatus;
    PVACertStatus() = default;

   private:
    /**
     * @brief Convert the enum index to the string representation of the status.  Internal use only
     *
     * @param status the enum index of the status
     * @return the string representation of the status
     */
    static std::string toString(const certstatus_t status) { return CERT_STATE(status); }
};

/**
 * @brief OCSP Certificate status values enum and string
 */
struct OCSPCertStatus : CertStatus {
    // Default constructor
    OCSPCertStatus() = default;

    /**
     * @brief Constructor for OCSPCertStatus
     *
     * @param status the enum index of the status
     */
    explicit OCSPCertStatus(const ocspcertstatus_t& status) : CertStatus(static_cast<uint32_t>(status), toString(status)) {}

    // Define the comparison operators
    bool operator==(const OCSPCertStatus& rhs) const { return this->i == rhs.i; }
    bool operator==(const ocspcertstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(const OCSPCertStatus& rhs) const { return this->i != rhs.i; }
    bool operator!=(const ocspcertstatus_t rhs) const { return this->i != rhs; }

   private:
    /**
     * @brief Convert the enum index to the string representation of the status.  Internal use only
     *
     * @param status the enum index of the status
     * @return the string representation of the status
     */
    static std::string toString(const ocspcertstatus_t& status) { return OCSP_CERT_STATE(status); }
};

/**
 * @brief To store OCSP status value - parsed out of an OCSP response.
 *
 * This struct is used to store the parsed OCSP status value.  It is used
 * to store the serial number, the OCSP status, the status date, the status
 * valid-until date, and the revocation date.
 */
struct ParsedOCSPStatus {
    // serial number of the certificate
    const uint64_t serial;
    // OCSP status of the certificate
    const OCSPCertStatus ocsp_status;
    // date of the OCSP certificate status
    const CertDate status_date;
    // valid-until date of the OCSP certificate status
    const CertDate status_valid_until_date;
    // revocation date of the certificate if it is revoked
    const CertDate revocation_date;

    /**
     * @brief Constructor for ParsedOCSPStatus
     *
     * @param serial the serial number of the certificate
     * @param ocsp_status the OCSP status of the certificate
     * @param status_date the status date of the certificate
     * @param status_valid_until_date the status `valid-until` date of the certificate
     * @param revocation_date the revocation date of the certificate if it is revoked
     */
    ParsedOCSPStatus(const uint64_t& serial, OCSPCertStatus ocsp_status, CertDate  status_date, CertDate  status_valid_until_date,
                     CertDate  revocation_date)
        : serial(serial),
          ocsp_status(std::move(ocsp_status)),
          status_date(std::move(status_date)),
          status_valid_until_date(std::move(status_valid_until_date)),
          revocation_date(std::move(revocation_date)) {}

    CertificateStatus status();
};

// Forward declarations of the certificate status structures
struct CertifiedCertificateStatus;
struct UnknownCertificateStatus;
struct UnCertifiedCertificateStatus;

/**
 * @brief Structure representing OCSP status.
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked, then there is also a
 * revocation date.  The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct OCSPStatus {
    // raw OCSP response bytes
    shared_array<const uint8_t> ocsp_bytes{};
    // OCSP status of the certificate
    OCSPCertStatus ocsp_status{OCSP_CERTSTATUS_UNKNOWN};
    // date of the OCSP certificate status
    CertDate status_date{};
    // valid-until date of the OCSP certificate status
    CertDate status_valid_until_date{static_cast<time_t>(0)};
    // revocation date of the certificate if it is revoked
    CertDate revocation_date{};

    // Constructor from a PKCS#7 OCSP response that must be signed by the given trusted store.
    explicit OCSPStatus(const shared_array<const uint8_t>& ocsp_bytes_param, X509_STORE* trusted_store_ptr, const std::string& cert_id)
        : ocsp_bytes(ocsp_bytes_param) {
        if (!trusted_store_ptr) {
            throw std::invalid_argument("Trusted store pointer is null");
        }
        init(trusted_store_ptr, cert_id);
    }

    explicit OCSPStatus(const uint8_t* ocsp_bytes_ptr, const size_t ocsp_bytes_len, X509_STORE* trusted_store_ptr, const std::string& cert_id)
        : ocsp_bytes(ocsp_bytes_ptr, ocsp_bytes_len) {
        if (!trusted_store_ptr) {
            throw std::invalid_argument("Trusted store pointer is null");
        }
        init(trusted_store_ptr, cert_id);
    }

    explicit OCSPStatus(const shared_array<const uint8_t>& ocsp_bytes_param, X509_STORE* trusted_store_ptr,
                        const std::string& issuer_id, const uint64_t serial)
        : ocsp_bytes(ocsp_bytes_param) {
        if (!trusted_store_ptr) {
            throw std::invalid_argument("Trusted store pointer is null");
        }
        init(trusted_store_ptr, issuer_id, serial);
    }

    explicit OCSPStatus(const uint8_t* ocsp_bytes_ptr, const size_t ocsp_bytes_len, X509_STORE* trusted_store_ptr,
                        const std::string& issuer_id, const uint64_t serial)
        : ocsp_bytes(ocsp_bytes_ptr, ocsp_bytes_len) {
        if (!trusted_store_ptr) {
            throw std::invalid_argument("Trusted store pointer is null");
        }
        init(trusted_store_ptr, issuer_id, serial);
    }

    // To set an OCSP UNKNOWN status to indicate errors
    OCSPStatus() = default;
    virtual ~OCSPStatus() = default;

    virtual bool operator==(const OCSPStatus& rhs) const {
        return this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date && this->status_valid_until_date == rhs.status_valid_until_date &&
               this->revocation_date == rhs.revocation_date;
    }
    virtual bool operator!=(const OCSPStatus& rhs) const { return !(*this == rhs); }
    virtual bool operator==(const CertificateStatus& rhs) const;
    virtual bool operator!=(const CertificateStatus& rhs) const { return !(*this == rhs); }
    virtual bool operator==(const PVACertificateStatus& rhs) const;
    virtual bool operator!=(const PVACertificateStatus& rhs) const { return !(*this == rhs); }
    virtual bool operator==(ocspcertstatus_t& rhs) const { return this->ocsp_status == rhs; }
    virtual bool operator!=(ocspcertstatus_t& rhs) const { return !(*this == rhs); }
    virtual bool operator==(certstatus_t& rhs) const {
        return (rhs == VALID && this->ocsp_status == OCSP_CERTSTATUS_GOOD) || (rhs == REVOKED && this->ocsp_status == OCSP_CERTSTATUS_REVOKED);
    }
    virtual bool operator!=(certstatus_t& rhs) const { return !(*this == rhs); }

    /**
     * @brief Check whether this OCSP *status result* is still current
     *
     * This checks the status validity period (status_valid_until_date), not whether
     * the associated certificate is in the VALID vs EXPIRED/REVOKED/etc. state.
     *
     * @return true if the OCSP status validity period has not expired
     */
    bool isStatusCurrent() const noexcept { // NOLINT(*-convert-member-functions-to-static)
        const auto now(std::time(nullptr));
        return status_valid_until_date.t > now;
    }

    /**
     * @brief Check if the status is permanent
     *
     * @return true if the status is permanent, false otherwise
     */
    bool isPermanent() const noexcept { return status_valid_until_date.t == PERMANENTLY_VALID_STATUS; }

    /**
     * @brief Check if the status is GOOD
     *
     * @return true if the status is GOOD, false otherwise
     */
    bool isGood() const noexcept { return isStatusCurrent() && ocsp_status == OCSP_CERTSTATUS_GOOD; }

    virtual explicit operator CertificateStatus() const noexcept;

   private:
    friend struct PVACertificateStatus;
    explicit OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, CertDate status_date, CertDate status_valid_until_time,
                        CertDate revocation_time);

    void init(X509_STORE* trusted_store_ptr, const std::string& cert_id);
    void init(X509_STORE* trusted_store_ptr, const std::string& issuer_id, uint64_t serial);
};

bool operator==(ocspcertstatus_t& lhs, OCSPStatus& rhs);
bool operator!=(ocspcertstatus_t& lhs, OCSPStatus& rhs);
bool operator==(certstatus_t& lhs, OCSPStatus& rhs);
bool operator!=(certstatus_t& lhs, OCSPStatus& rhs);

/**
 * @brief Structure representing PVA-OCSP certificate status.  This is a superclass of OCSPStatus
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked, then there is also a
 * revocation date.  The status field contains the PVA certificate status in numerical and text form.
 * The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct PVACertificateStatus final : OCSPStatus {
    PVACertStatus status{UNKNOWN};
    CertDate renew_by{};
    bool operator==(const PVACertificateStatus& rhs) const override {
        return this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
               this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
    }
    bool renewal_due{false};
    bool operator!=(const PVACertificateStatus& rhs) const override { return !(*this == rhs); }

    bool operator==(certstatus_t& rhs) const override { return this->status == rhs; }
    bool operator!=(certstatus_t& rhs) const override { return !(*this == rhs); }
    bool operator==(ocspcertstatus_t& rhs) const override { return this->ocsp_status == rhs; }
    bool operator!=(ocspcertstatus_t& rhs) const override { return !(*this == rhs); }

    bool operator==(const OCSPStatus& rhs) const override {
        return this->status != VALID && this->status != REVOKED
                   ? false
                   : this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
                         this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
    }
    bool operator!=(const OCSPStatus& rhs) const override { return !(*this == rhs); }
    bool operator==(const CertificateStatus& rhs) const override;
    bool operator!=(const CertificateStatus& rhs) const override { return !(*this == rhs); }

    explicit PVACertificateStatus(const certstatus_t status, const shared_array<const uint8_t>& ocsp_bytes, X509_STORE* trusted_store_ptr,
                                 const std::string& cert_id)
        : OCSPStatus(ocsp_bytes, trusted_store_ptr, cert_id), status(status) {}

    explicit PVACertificateStatus(const certstatus_t status, const shared_array<const uint8_t>& ocsp_bytes, X509_STORE* trusted_store_ptr,
                                 const std::string& issuer_id, const uint64_t serial)
        : OCSPStatus(ocsp_bytes, trusted_store_ptr, issuer_id, serial), status(status) {}

    explicit PVACertificateStatus(const Value& status_value, X509_STORE* trusted_store_ptr, const std::string& cert_id)
        : PVACertificateStatus(status_value["value.index"].as<certstatus_t>(), status_value["ocsp_response"].as<shared_array<const uint8_t>>(),
                               trusted_store_ptr, cert_id) {
        if (ocsp_bytes.empty()) return;
        log_debug_printf(status_setup, "Value Status: %s\n", (SB() << status_value).str().c_str());
        log_debug_printf(status_setup, "Status Date: %s\n", this->status_date.s.c_str());
        log_debug_printf(status_setup, "Status Validity: %s\n", this->status_valid_until_date.s.c_str());
        log_debug_printf(status_setup, "Revocation Date: %s\n", this->revocation_date.s.c_str());
        if (!selfConsistent() ||
            !dateConsistent(CertDate(status_value["ocsp_status_date"].as<std::string>()), CertDate(status_value["ocsp_certified_until"].as<std::string>()),
                            CertDate(status_value["ocsp_revocation_date"].as<std::string>()))) {
            throw OCSPParseException("Certificate status does not match certified OCSP status");
        }
    }

    // To set an UNKNOWN status to indicate errors
    PVACertificateStatus() : OCSPStatus() {}
    explicit operator CertificateStatus() const noexcept override;

   private:
    friend class CertStatusFactory;
    /**
     * @brief Constructor for PVACertificateStatus
     * @param status PVA certificate status
     * @param ocsp_status OCSP certificate status
     * @param ocsp_bytes OCSP response bytes
     * @param status_date Status date
     * @param status_valid_until_time Status valid-until date
     * @param revocation_time Revocation date
     */
    explicit PVACertificateStatus(const certstatus_t status, const ocspcertstatus_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes,
                                  const CertDate& status_date, const CertDate& status_valid_until_time, const CertDate& revocation_time, const CertDate& renew_by={}, const bool renewal_due=false)
        : OCSPStatus(ocsp_status, ocsp_bytes, status_date, status_valid_until_time, revocation_time), status(status), renew_by(renew_by), renewal_due(renewal_due) {}

    /**
     * @brief Check if the PVACertificateStatus is self-consistent,
     * i.e., the OCSP status values are consistent with the PVA status values
     * @return true if the PVACertificateStatus is self-consistent, false otherwise
     */
    bool selfConsistent() const {
        return (ocsp_status == OCSP_CERTSTATUS_UNKNOWN && !(status == VALID || status == REVOKED)) ||
               (ocsp_status == OCSP_CERTSTATUS_REVOKED && status == REVOKED) || (ocsp_status == OCSP_CERTSTATUS_GOOD && status == VALID);
    }

    /**
     * @brief Check if the PVACertificateStatus is date-consistent,
     * i.e., the status date, status valid-until date, and revocation date are all the same
     * @param status_date_value Status date
     * @param status_valid_until_date_value Status valid-until date
     * @param revocation_date_value Revocation date
     * @return true if the PVACertificateStatus is date-consistent, false otherwise
     */
    bool dateConsistent(const CertDate& status_date_value, const CertDate& status_valid_until_date_value, const CertDate& revocation_date_value) const {
        return status_date == status_date_value && status_valid_until_date == status_valid_until_date_value && revocation_date == revocation_date_value;
    }
};

/**
 * @brief Equality operator for ocspcertstatus_t and PVACertificateStatus
 * @param lhs ocspcertstatus_t value to compare with
 * @param rhs PVACertificateStatus object to compare with
 * @return true if the ocspcertstatus_t value is equal to the ocsp_status of the PVACertificateStatus object, false otherwise
 */
bool operator==(ocspcertstatus_t& lhs, PVACertificateStatus& rhs);
/**
 * @brief Inequality operator for ocspcertstatus_t and PVACertificateStatus
 * @param lhs ocspcertstatus_t value to compare with
 * @param rhs PVACertificateStatus object to compare with
 * @return true if the ocspcertstatus_t value is not equal to the ocsp_status of the PVACertificateStatus object, false otherwise
 */
bool operator!=(ocspcertstatus_t& lhs, PVACertificateStatus& rhs);
/**
 * @brief Equality operator for certstatus_t and PVACertificateStatus
 * @param lhs certstatus_t value to compare with
 * @param rhs PVACertificateStatus object to compare with
 * @return true if the certstatus_t value is equal to the status of the PVACertificateStatus object, false otherwise
 */
bool operator!=(certstatus_t& lhs, PVACertificateStatus& rhs);

/**
 * @brief Structure representing certificate status.
 *
 * This struct is used to store the certificate status.  It contains the PVA certificate status,
 * the OCSP status, the status date, the status valid-until date, and the revocation date.
 */
struct CertificateStatus {
    virtual ~CertificateStatus() = default;
    CertificateStatus()
        : CertificateStatus(false, static_cast<PVACertStatus>(UNKNOWN), static_cast<OCSPCertStatus>(OCSP_CERTSTATUS_UNKNOWN), CertDate(std::time(nullptr)),
                            CertDate(PERMANENTLY_VALID_STATUS), CertDate(static_cast<time_t>(0))) {}

    // Enable copying
    CertificateStatus(const CertificateStatus&) = default;
    CertificateStatus& operator=(const CertificateStatus&) = default;

    explicit CertificateStatus(const PVACertificateStatus& cs)
        : CertificateStatus(cs.status != UNKNOWN && !cs.ocsp_bytes.empty(), cs.status, cs.ocsp_status, cs.status_date, cs.status_valid_until_date,
                            cs.revocation_date) {}

     /**
      * @brief Get the cert status class
      *
      * @return cert_status_class_t::GOOD (VALID), cert_status_class_t::BAD (REVOKED, EXPIRED), or cert_status_class_t::UNKNOWN (everything else)
      */
     cert_status_class_t getStatusClass() const noexcept {
         return status == VALID ? cert_status_class_t::GOOD : isRevokedOrExpired() ? cert_status_class_t::BAD : cert_status_class_t::UNKNOWN;
     }
     cert_status_class_t getEffectiveStatusClass() const noexcept { return isStatusCurrent() ? getStatusClass() : cert_status_class_t::UNKNOWN; }

    /**
     * @brief Check if the certificate is Expired of Revoked
     *
     * @return true if the certificate is Expired or Revoked
     */
    bool isRevokedOrExpired() const noexcept { return status == REVOKED || status == EXPIRED; }

     /**
      * @brief Check whether this *status result* is still current
      *
      * This checks the status validity period (status_valid_until_date), not whether
      * the certificate's status enumerator is VALID vs EXPIRED/REVOKED/etc.
      *
      * @return true if the status validity period has not expired
      */
     bool isStatusCurrent() const noexcept { // NOLINT(*-convert-member-functions-to-static)
         const auto now(std::time(nullptr));
         return status_valid_until_date.t > now;
     }

    bool isCertified() const noexcept { return certified; }

    bool isPermanent() const noexcept { return status_valid_until_date.t == PERMANENTLY_VALID_STATUS; }

    CertDate status_valid_until_date;
    bool certified{false};
    PVACertStatus status{UNKNOWN};
    OCSPCertStatus ocsp_status{OCSP_CERTSTATUS_UNKNOWN};
    CertDate status_date;
    CertDate revocation_date;

    /**
     * @brief Equality operator for PVACertificateStatus
     * @param rhs PVACertificateStatus object to compare with
     * @return true if the PVACertificateStatus objects are equal, false otherwise
     */
    bool operator==(const PVACertificateStatus& rhs) const { return static_cast<CertificateStatus>(rhs) == *this; }
    /**
     * @brief Inequality operator for PVACertificateStatus
     * @param rhs PVACertificateStatus object to compare with
     * @return true if the PVACertificateStatus objects are not equal, false otherwise
     */
    bool operator!=(const PVACertificateStatus& rhs) const { return !(*this == rhs); }
    /**
     * @brief Equality operator for CertificateStatus
     * @param rhs CertificateStatus object to compare with
     * @return true if the CertificateStatus objects are equal, false otherwise
     */
    bool operator==(const CertificateStatus& rhs) const {
        return this->certified == rhs.certified && this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
               this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
    }

    friend ParsedOCSPStatus;

   protected:
    // Protected constructor for derived classes
    CertificateStatus(const bool is_certified, const PVACertStatus& st, const OCSPCertStatus& ocsp_st, const CertDate& st_date, const CertDate& valid_until,
                      const CertDate& rev_date)
        : status_valid_until_date(valid_until), certified(is_certified), status(st), ocsp_status(ocsp_st), status_date(st_date), revocation_date(rev_date) {}

    /**
     * @brief Inequality operator for CertificateStatus
     * @param rhs CertificateStatus object to compare with
     * @return true if the CertificateStatus objects are not equal, false otherwise
     */
    bool operator!=(const CertificateStatus& rhs) const { return !(*this == rhs); }

    /**
     * @brief Equality operator for certstatus_t
     * @param rhs certstatus_t value to compare with
     * @return true if the certstatus_t value is equal to the status, false otherwise
     */
    bool operator==(const certstatus_t& rhs) const { return this->status == rhs; }

    /**
     * @brief Inequality operator for certstatus_t
     * @param rhs certstatus_t value to compare with
     * @return true if the certstatus_t value is not equal to the status, false otherwise
     */
    bool operator!=(const certstatus_t& rhs) const { return !(*this == rhs); }

    /**
     * @brief Equality operator for ocspcertstatus_t
     * @param rhs ocspcertstatus_t value to compare with
     * @return true if the ocspcertstatus_t value is equal to the ocsp_status, false otherwise
     */
    bool operator==(const ocspcertstatus_t& rhs) const { return this->ocsp_status == rhs; }

    /**
     * @brief Inequality operator for ocspcertstatus_t
     * @param rhs ocspcertstatus_t value to compare with
     * @return true if the ocspcertstatus_t value is not equal to the ocsp_status, false otherwise
     */
    bool operator!=(const ocspcertstatus_t& rhs) const { return !(*this == rhs); }

   private:
    friend struct CertifiedCertificateStatus;
    friend struct UnknownCertificateStatus;
    friend struct UnCertifiedCertificateStatus;
};

/**
 * @brief Represents the status of a certified certificate.
 *
 * This is the certificate status struct to use when you don't need to carry round the heavy PKCS#7 `ocsp_bytes`
 * It is certified because it can only be created from a certified `CertificateStatus` struct.
 * Create by casting a `CertificateStatus`, or passing one in to the single argument constructor.
 *
 * The `CertifiedCertificateStatus` struct encapsulates various attributes related to the
 * status of a certified certificate, including PVA certificate status, OCSP status, status date,
 * status valid-until date, and revocation date.
 */
struct CertifiedCertificateStatus final : CertificateStatus {
    explicit CertifiedCertificateStatus(const PVACertificateStatus& cs)
        : CertificateStatus(true, cs.status, cs.ocsp_status, cs.status_date, cs.status_valid_until_date, cs.revocation_date) {}

   private:
    friend struct OCSPStatus;
    explicit CertifiedCertificateStatus(const OCSPStatus& cs)
        : CertificateStatus(true, PVACertStatus(cs.ocsp_status == OCSP_CERTSTATUS_GOOD ? VALID : REVOKED), cs.ocsp_status, cs.status_date,
                            cs.status_valid_until_date, cs.revocation_date) {}
};

struct UnknownCertificateStatus final : CertificateStatus {
    UnknownCertificateStatus()
        : CertificateStatus(false, static_cast<PVACertStatus>(UNKNOWN), static_cast<OCSPCertStatus>(OCSP_CERTSTATUS_UNKNOWN), CertDate(std::time(nullptr)),
                            CertDate(PERMANENTLY_VALID_STATUS), CertDate(static_cast<time_t>(0))) {}
};

struct UnCertifiedCertificateStatus final : CertificateStatus {
    UnCertifiedCertificateStatus()
        : CertificateStatus(false, static_cast<PVACertStatus>(VALID), static_cast<OCSPCertStatus>(OCSP_CERTSTATUS_GOOD), CertDate(std::time(nullptr)),
                            CertDate(PERMANENTLY_VALID_STATUS), CertDate(static_cast<time_t>(0))) {}
};

template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = ossl_shared_ptr<T, cert_status_delete<T>>;

/**
 * @brief This class is used to parse OCSP responses and to get/subscribe to certificate status
 *
 * Parsing OCSP responses is carried out by providing the OCSP response buffer
 * to the static `parse()` function. This function will verify the response comes
 * from a trusted source, is well-formed, and then will return the `OCSPStatus`
 * it indicates.
 * @code
 *  auto ocsp_status(CertStatusManager::parse(ocsp_response);
 * @endcode
 *
 * To get certificate status call the status `getStatus()` method with the
 * the certificate you want to get status for.  It will make a request
 * to the PVACMS to get certificate status for the certificate. After verifying the
 * authenticity of the response and checking that it is from a trusted
 * source, it will return `CertificateStatus`.
 * @code
 *  auto cert_status(CertStatusManager::getStatus(cert);
 * @endcode
 *
 * To subscribe, call the subscribe method with the certificate you want to
 * subscribe to status for and provide a callback that takes a `CertificateStatus`
 * to be notified of status changes.  It will subscribe to PVACMS to monitor changes to
 * to the certificate status for the given certificate. After verifying the
 * authenticity of each status update and checking that it is from a trusted
 * source it will call the callback with a `CertificateStatus` representing the
 * updated status.
 * @code
 *  auto csm = CertStatusManager::subscribe(cert, [] (CertificateStatus &&cert_status) {
 *      std::cout << "STATUS DATE: " << cert_status.status_date.s << std::endl;
 *  });
 *  ...
 *  csm.unsubscribe();
 *  // unsubscribe() automatically called when csm goes out of scope
 * @endcode
 */
class CertStatusManager {
   public:
    friend struct OCSPStatus;
    using StatusCallback = std::function<void(const PVACertificateStatus &)>;

    CertStatusManager() = delete;
    ~CertStatusManager() = default;

    /**
     * Parse OCSP responses from the provided ocsp_bytes response
     * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
     *
     * First, verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well-formed.
     *
     * Then parse it, certify that it refers to the same certificate, and read out the status and the status times
     *
     * @param ocsp_bytes The input byte array containing the OCSP responses data.
     * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
     * @param cert_id the certificate ID that the status is referring to
     */
    static ParsedOCSPStatus parse(const shared_array<const uint8_t> &ocsp_bytes, X509_STORE *trusted_store_ptr, const std::string& cert_id);

    /**
     * Parse OCSP responses from the provided ocsp_bytes response
     * and return the parsed out status of the certificate which is the subject of the ocsp byte array.
     *
     * First, verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well-formed.
     *
     * Then parse it, certify that it refers to the same certificate, and read out the status and the status times
     *
     * @param ocsp_bytes The input byte buffer pointer containing the OCSP responses data.
     * @param ocsp_bytes_len the length of the byte buffer
     * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
     * @param cert_id the certificate ID that the status is referring to
     */
    static ParsedOCSPStatus parse(const uint8_t *ocsp_bytes, size_t ocsp_bytes_len, X509_STORE *trusted_store_ptr, const std::string& cert_id);

    /**
     * Parse OCSP responses from the provided OCSP response object
     * and return the parsed out status of the certificate which is the subject of the OCSP response.
     *
     * First, verify the ocsp response.  Check that it is signed by a trusted issuer and that it is well-formed.
     *
     * Then parse it, certify that it refers to the same certificate, and read out the status and the status times
     *
     * @param ocsp_response An OCSP response object.
     * @param trusted_store_ptr The trusted store to be used to validate the OCSP response
     * @param cert_id the certificate ID that the status is referring to
     */
    static ParsedOCSPStatus parse(const ossl_ptr<OCSP_RESPONSE> &ocsp_response, X509_STORE *trusted_store_ptr, const std::string& cert_id);

    /**
     * @brief Get the status PV from a Cert.
     * This function gets the PVA extension that stores the status PV in the certificate
     * if the certificate must be used in conjunction with a status monitor to check for
     * revoked status.
     * @param cert the certificate to check for the status PV extension
     * @return a blank string if no extension exists, otherwise contains the status PV
     *         e.g. CERT:STATUS:0293823f:098294739483904875
     */
    static std::string getStatusPvFromCert(const ossl_ptr<X509> &cert);

    /**
     * @brief Get the config PV from a Cert.
     * This function gets the PVA extension that stores the config PV in the certificate
     * if the certificate can be used in conjunction with a config monitor to check for
     * expired status.
     * @param cert the certificate to check for the config PV extension
     * @return a blank string if no extension exists, otherwise contains the config PV
     *         e.g. CERT:CONFIG:0293823f:098294739483904875
     */
    static std::string getConfigPvFromCert(const ossl_ptr<X509> &cert);


    /**
     * @brief Get the certificate issuer from a Cert.
     * This function gets the certificate issuer from the certificate
     * @param cert_ptr the certificate to check
     * @return the certificate issuer
     */
    static std::string getIssuerIdFromCert(const X509* cert_ptr);

    /**
     * @brief Get the certificate serial number from a Cert.
     * This function gets the certificate serial number from the certificate
     * @param cert_ptr the certificate to check
     * @return the certificate serial number
     */
    static std::string getSerialFromCert(const X509* cert_ptr);

    /**
     * @brief Get the certificate ID string from a Cert.
     * This function gets the certificate ID string from a certificate
     * @param cert_ptr the certificate ID string, made up of the issuer id and the serial number separated with a colon
     *         e.g. 0293823f:098294739483904875
     */
    static std::string getCertIdFromCert(const X509 *cert_ptr);
    static std::string getCertIdFromSerialAndIssuer(const std::string &issuer_id, const std::string &serial);
    static std::string getCertIdFromStatusPv(const std::string &status_pv);

    /**
     * @brief Get the status PV from a Cert.
     * This function gets the PVA certificate extension that holds the status PV
     * @param cert_ptr the certificate to check
     * @return a blank string if no extension exists, otherwise contains the status PV
     *         e.g. CERT:STATUS:0293823f:098294739483904875
     */
    static std::string getStatusPvFromCert(const X509 *cert_ptr);

    /**
     * @brief Get the certificate configuration PV from a Cert.
     * This function gets the PVA certificate extension that holds the certificate configuration PV
     * @param cert_ptr the certificate to check
     * @return a blank string if no extension exists, otherwise contains the certificate configuration PV
     *         e.g. CERT:CONFIG:0293823f:098294739483904875
     */
    static std::string getConfigPvFromCert(const X509 *cert_ptr);

    /**
     * @brief Get the expiration date from a Cert.
     * This function gets the certificate expiration date
     * @param cert the certificate to check
     * @return the certificate expiration date
     */
    static time_t getExpirationDateFromCert(const ossl_ptr<X509> &cert);

    /**
     * @brief Get the expiration date from a Cert.
     * This function gets the certificate expiration date
     * @param cert_ptr the certificate to check
     * @return the certificate expiration date
     */
    static time_t getExpirationDateFromCert(const X509 *cert_ptr);

    /**
     * @brief Used to create a helper that you can use to subscribe to certificate status with
     * Subsequently call subscribe() to subscribe
     *
     * @param client the client to use for the subscription
     * @param trusted_store_ptr the trusted store that we'll use to verify the OCSP responses received
     * @param status_pv the status PV to subscribe to
     * @param cert_id the certificate ID that we're subscribing to
     * @param callback the callback to call when a status change has appeared
     *
     * @see unsubscribe()
     */
    static cert_status_ptr<CertStatusManager> subscribe(const client::Context& client, X509_STORE *trusted_store_ptr, const std::string &status_pv,
                                                        const std::string& cert_id, StatusCallback &&callback);

    /**
     * @brief Unsubscribe from listening to certificate status
     *
     * This function idempotent unsubscribe from the certificate status updates
     */
    void unsubscribe();

   private:
    explicit CertStatusManager(const client::Context &client,
                               std::shared_ptr<client::Subscription> sub = std::shared_ptr<client::Subscription>())
        : client_(client), sub_(std::move(sub))
    {};

    void subscribe(const std::shared_ptr<client::Subscription> &sub) { sub_ = sub; }

    std::shared_ptr<StatusCallback> callback_ref{};  // Option placeholder for ref to callback if used
    client::Context client_;
    std::shared_ptr<client::Subscription> sub_;
    std::shared_ptr<CertificateStatus> status_;
    std::vector<uint8_t> cached_ocsp_bytes_;  // last-written OCSP bytes, used to skip redundant cache writes

    /**
     * @brief Get the custom status extension from the given certificate
     * @param certificate the certificate to retrieve the status extension from
     * @return the extension
     * @throws CertStatusNoExtensionException if no extension is present in the certificate
     */
    static X509_EXTENSION *getStatusExtension(const X509 *certificate);
    static X509_EXTENSION *getConfigExtension(const X509 *certificate);
    static ossl_ptr<OCSP_RESPONSE> getOCSPResponse(const shared_array<const uint8_t> &ocsp_bytes);
    static ossl_ptr<OCSP_RESPONSE> getOCSPResponse(const uint8_t *ocsp_bytes, size_t ocsp_bytes_len);
    static bool verifyOCSPResponse(const ossl_ptr<OCSP_BASICRESP> &basic_response, X509_STORE *trusted_store_ptr);
};

template <>
struct cert_status_delete<CertStatusManager> {
    void operator()(CertStatusManager *base_pointer) const {
        if (base_pointer) {
            base_pointer->unsubscribe();  // Idempotent unsubscribe
            delete base_pointer;
        }
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUS_H_
