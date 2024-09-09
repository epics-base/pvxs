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

#include <openssl/x509.h>

#include <pvxs/nt.h>

#include "certstatusmanager.h"
#include "ownedptr.h"

#define CERT_TIME_FORMAT "%a %b %d %H:%M:%S %Y UTC"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

namespace pvxs {
namespace certs {

class CertStatusManager;

///////////// OSCP RESPONSE ERRORS
class OCSPParseException : public std::runtime_error {
   public:
    explicit OCSPParseException(const std::string& message) : std::runtime_error(message) {}
};

// Certificate management
#define GET_MONITOR_CERT_STATUS_ROOT "CERT:STATUS"
#define GET_MONITOR_CERT_STATUS_PV "CERT:STATUS:????????:*"

// All certificate statuses
#define CERT_STATUS_LIST   \
    X_IT(UNKNOWN)          \
    X_IT(PENDING_APPROVAL) \
    X_IT(PENDING)          \
    X_IT(VALID)            \
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

/**
 * @brief Base class for Certificate status values.  Contains the enum index `i`
 * and the string representation `s` of the value for logging
 */
struct PVACertStatus;
struct OCSPCertStatus;
struct CertStatus {
    uint32_t i;
    std::string s;
    CertStatus() = default;

    bool operator==(PVACertStatus rhs) = delete;
    bool operator==(OCSPCertStatus rhs) = delete;
    bool operator==(ocspcertstatus_t rhs) = delete;
    bool operator==(certstatus_t rhs) = delete;
    bool operator!=(PVACertStatus rhs) = delete;
    bool operator!=(OCSPCertStatus rhs) = delete;
    bool operator!=(ocspcertstatus_t rhs) = delete;
    bool operator!=(certstatus_t rhs) = delete;

    /**
     * @brief The prototype of the data returned for a certificate status request
     * Essentially an enum, a serial number and the ocsp response
     *
     * @return The prototype of the data returned for a certificate status request
     */
    static inline Value getStatusPrototype() {
        using namespace members;
        nt::NTEnum enum_value;
        nt::NTEnum enum_ocspvalue;

        auto value = TypeDef(TypeCode::Struct,
                             {
                                 enum_value.build().as("status"),
                                 Member(TypeCode::UInt64, "serial"),
                                 Member(TypeCode::String, "state"),
                                 enum_ocspvalue.build().as("ocsp_status"),
                                 Member(TypeCode::String, "ocsp_state"),
                                 Member(TypeCode::String, "ocsp_status_date"),
                                 Member(TypeCode::String, "ocsp_certified_until"),
                                 Member(TypeCode::String, "ocsp_revocation_date"),
                                 Member(TypeCode::UInt8A, "ocsp_response"),
                             })
                         .create();
        shared_array<const std::string> choices(CERT_STATES);
        value["status.value.choices"] = choices.freeze();
        shared_array<const std::string> ocsp_choices(OCSP_CERT_STATES);
        value["ocsp_status.value.choices"] = ocsp_choices.freeze();
        return value;
    }

    /**
     * @brief  Get the issuer ID which is the first 8 hex digits of the hex SKI
     *
     * Note that the given cert must contain the skid extension in the first place
     *
     * @param ca_cert  the cert from which to get the subject key identifier extension
     * @return first 8 hex digits of the hex SKI
     */
    static inline std::string getIssuerId(const ossl_ptr<X509>& ca_cert) { return getIssuerId(ca_cert.get()); }

    static inline std::string getIssuerId(X509* ca_cert_ptr) {
        ossl_ptr<ASN1_OCTET_STRING> skid(reinterpret_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(ca_cert_ptr, NID_subject_key_identifier, nullptr, nullptr)));
        if (!skid.get()) {
            throw std::runtime_error("Failed to get Subject Key Identifier.");
        }

        // Convert first 8 chars to hex
        auto buf = const_cast<unsigned char*>(skid->data);
        std::stringstream ss;
        for (int i = 0; i < skid->length && ss.tellp() < 8; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
        }

        return ss.str();
    }

    static inline std::string makeStatusURI(std::string& issuer_id, uint64_t& serial) {
        return SB() << GET_MONITOR_CERT_STATUS_ROOT << ":" << issuer_id << ":" << std::setw(16) << std::setfill('0') << serial;
    }

   protected:
    explicit CertStatus(const uint32_t status, std::string&& status_string) : i(status), s(std::move(status_string)) {}
};

/**
 * @brief PVA Certificate status values enum and string
 */
struct PVACertStatus : CertStatus {
    PVACertStatus() = delete;

    explicit PVACertStatus(const certstatus_t& status) : CertStatus(status, toString(status)) {}

    bool operator==(PVACertStatus rhs) const { return this->i == rhs.i; }
    bool operator==(certstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(PVACertStatus rhs) const { return this->i != rhs.i; }
    bool operator!=(certstatus_t rhs) const { return this->i != rhs; }

   private:
    static inline std::string toString(const certstatus_t status) { return CERT_STATE(status); }
};

/**
 * @brief OCSP Certificate status values enum and string
 */
struct OCSPCertStatus : CertStatus {
    OCSPCertStatus() = default;

    explicit OCSPCertStatus(const ocspcertstatus_t& status) : CertStatus(status, toString(status)) {}

    bool operator==(OCSPCertStatus rhs) const { return this->i == rhs.i; }
    bool operator==(ocspcertstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(OCSPCertStatus rhs) const { return this->i != rhs.i; }
    bool operator!=(ocspcertstatus_t rhs) const { return this->i != rhs; }

   private:
    static inline std::string toString(const ocspcertstatus_t status) { return OCSP_CERT_STATE(status); }
};

/**
 * @brief To create and manipulate status dates.
 * Status dates have a string representation `s` as well as a time_t representation `t`
 */
struct StatusDate {
    std::time_t t;
    std::string s;

    StatusDate() = default;

    StatusDate(const std::time_t& time) : t(time), s(toString(time)) {}
    StatusDate(const ASN1_TIME* time) : t(asn1TimeToTimeT(time)), s(toString(t)) {}
    StatusDate(const ossl_ptr<ASN1_TIME>& time) : t(asn1TimeToTimeT(time.get())), s(toString(t)) {}
    StatusDate(const std::string& time_string) : t(toTimeT(time_string)), s(StatusDate(t).s) {}

    inline bool operator==(StatusDate rhs) const { return this->t == rhs.t; }

    inline operator const std::string&() const { return s; }
    inline operator std::string() const { return s; }
    inline operator const time_t&() const { return t; }
    inline operator time_t() const { return t; }
    inline operator ossl_ptr<ASN1_TIME>() const { return toAsn1_Time(); };

    inline ossl_ptr<ASN1_TIME> toAsn1_Time() const {
        ossl_ptr<ASN1_TIME> asn1(ASN1_TIME_new());
        ASN1_TIME_set(asn1.get(), t);
        return asn1;
    }

    static inline ossl_ptr<ASN1_TIME> toAsn1_Time(StatusDate status_date) { return status_date.toAsn1_Time(); }

    /**
     * @brief To get the time_t (unix time) from a ASN1_TIME* time pointer
     * @param time ASN1_TIME* time pointer to convert
     * @return a time_t (unix time) version
     */
    static inline time_t asn1TimeToTimeT(const ASN1_TIME* time) {
        std::tm t{};
        if (!time) return 0;

        if (ASN1_TIME_to_tm(time, &t) != 1) throw std::runtime_error("Failed to convert ASN1_TIME to tm structure");

        return tmToTimeTUTC(t);
    }

   private:
    /**
     * @brief To format a string representation of the given time_t
     * @param time the time_t to format
     * @return the string representation in local time
     */
    static inline std::string toString(const std::time_t& time) {
        char buffer[100];
        if (std::strftime(buffer, sizeof(buffer), CERT_TIME_FORMAT, std::gmtime(&time))) {
            return std::string(buffer);
        } else {
            throw OCSPParseException("Failed to format status date");
        }
    }

    static inline time_t toTimeT(std::string time_string) {
        // Read the string and parse it into std::tm
        if (time_string.empty()) return 0;
        std::tm tm = {};
        std::istringstream ss(time_string);
        ss >> std::get_time(&tm, CERT_TIME_FORMAT);

        // Check if parsing was successful
        if (ss.fail()) {
            throw OCSPParseException("Failed to parse date-time string.");
        }

        // Convert std::tm to time_t
        return tmToTimeTUTC(tm);
    }

    /**
     * @brief To get the time_t (unix time) from a std::tm structure
     * @param tm std::tm structure to convert
     * @return a time_t (unix time) version
     */
    static inline time_t tmToTimeTUTC(const std::tm& tm) {
        // For accurate time calculation the start day in a year of each month
        static const int kMonthStartDays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
        int year = 1900 + tm.tm_year;

        // Calculate days up to start of the current year
        time_t days = (year - 1970) * 365 + (year - 1969) / 4  // Leap years
                      - (year - 1901) / 100                    // Excluding non-leap centuries
                      + (year - 1601) / 400;                   // Including leap centuries

        // Calculate days up to the start of the current month within the current year
        days += kMonthStartDays[tm.tm_mon];
        if (tm.tm_mon > 1 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) {
            days += 1;  // Add one day for leap years after February
        }

        // Adjust with the current day in the month (tm_mday starts from 1)
        days += tm.tm_mday - 1;

        // Incorporate hours, minutes, and seconds
        return ((days * 24 + tm.tm_hour) * 60 + tm.tm_min) * 60 + tm.tm_sec;
    }
};

/**
 * @brief To store OCSP status value - parsed out of an OCSP response
 * A true struct - no processing is done.
 */
struct ParsedOCSPStatus {
    const OCSPCertStatus ocsp_status;
    const StatusDate status_date;
    const StatusDate status_valid_until_date;
    const StatusDate revocation_date;
    ParsedOCSPStatus(const OCSPCertStatus& ocsp_status, const StatusDate& status_date, const StatusDate& status_valid_until_date,
                     const StatusDate& revocation_date)
        : ocsp_status(ocsp_status), status_date(status_date), status_valid_until_date(status_valid_until_date), revocation_date(revocation_date) {}
};

/**
 * @brief Structure representing OCSP status.
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked then there is also a
 * revocation date.  The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct OCSPStatus {
    shared_array<const uint8_t> ocsp_bytes;
    OCSPCertStatus ocsp_status;
    StatusDate status_date;
    StatusDate status_valid_until_date;
    StatusDate revocation_date;

    // Constructor using lvalue reference
    explicit OCSPStatus(const shared_array<const uint8_t>& ocsp_bytes_param) : ocsp_bytes(ocsp_bytes_param) { init(); }

    // Constructor using rvalue reference
    explicit OCSPStatus(shared_array<const uint8_t>&& ocsp_bytes_param) : ocsp_bytes(std::move(ocsp_bytes_param)) { init(); }

    // To  set an OCSP UNKNOWN status to indicate errors
    OCSPStatus() : ocsp_status(OCSP_CERTSTATUS_UNKNOWN) {};

   private:
    friend struct CertificateStatus;
    explicit OCSPStatus(ocspcertstatus_t ocsp_status, shared_array<const uint8_t>&& ocsp_bytes, StatusDate status_date, StatusDate status_valid_until_time,
                        StatusDate revocation_time)
        : ocsp_bytes(std::move(ocsp_bytes)),
          ocsp_status(ocsp_status),
          status_date(status_date),
          status_valid_until_date(status_valid_until_time),
          revocation_date(revocation_time) {};
    inline void init() {
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
};

/**
 * @brief Structure representing PVA-OCSP certificate status.  This is a superclass of OCSPStatus
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked then there is also a
 * revocation date.  The status field contains the PVA certificate status in numerical and text form.
 * The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct CertificateStatus : public OCSPStatus {
    PVACertStatus status;
    inline bool operator==(const CertificateStatus& rhs) const { return this->status == rhs.status && this->ocsp_status == rhs.ocsp_status; }
    inline bool operator!=(const CertificateStatus& rhs) const { return this->status != rhs.status || this->ocsp_status != rhs.ocsp_status; }
    inline bool operator==(certstatus_t rhs) const { return this->status == rhs; }
    inline bool operator==(ocspcertstatus_t rhs) const { return this->ocsp_status == rhs; }
    inline bool operator!=(certstatus_t rhs) const { return !(this->status == rhs); }
    inline bool operator!=(ocspcertstatus_t rhs) const { return !(this->ocsp_status == rhs); }

    explicit CertificateStatus(certstatus_t status, const shared_array<const uint8_t>&& ocsp_bytes) : OCSPStatus(std::move(ocsp_bytes)), status(status) {};

    explicit CertificateStatus(const Value& status_value)
        : OCSPStatus(status_value["ocsp_response"].as<shared_array<const uint8_t>>()), status(status_value["status.value.index"].as<certstatus_t>()) {
        if (ocsp_bytes.empty()) return;
        if (!selfConsistent() || !dateConsistent(status_value["ocsp_status_date"].as<std::string>(), status_value["ocsp_certified_until"].as<std::string>(),
                                                 status_value["ocsp_revocation_date"].as<std::string>())) {
            throw OCSPParseException("Certificate status does not match certified OCSP status");
        };
    }

    // To  set an UNKNOWN status to indicate errors
    CertificateStatus() : OCSPStatus(), status(UNKNOWN) {}

    /**
     * @brief Verify that the status validity dates are currently valid and the status is known
     * @return true if the status is still valid
     */
    bool isValid() noexcept {
        if ( status == UNKNOWN ) return false;
        auto now(std::time(nullptr));
        return status_valid_until_date.t > now;
    }

  private:
    friend class CertStatusFactory;
    explicit CertificateStatus(certstatus_t status, ocspcertstatus_t ocsp_status, shared_array<const uint8_t>&& ocsp_bytes, StatusDate status_date,
                               StatusDate status_valid_until_time, StatusDate revocation_time)
        : OCSPStatus(ocsp_status, std::move(ocsp_bytes), status_date, status_valid_until_time, revocation_time), status(status) {};

    inline bool selfConsistent() {
        return (ocsp_status == OCSP_CERTSTATUS_UNKNOWN && (!(status == VALID || status == EXPIRED || status == REVOKED))) ||
               (ocsp_status == OCSP_CERTSTATUS_REVOKED && ((status == REVOKED) || (status == EXPIRED))) ||
               (ocsp_status == OCSP_CERTSTATUS_GOOD && (status == VALID));
    }

    inline bool dateConsistent(StatusDate status_date_value, StatusDate status_valid_until_date_value, StatusDate revocation_date_value) {
        return (status_date == status_date_value) && (status_valid_until_date == status_valid_until_date_value) && (revocation_date == revocation_date_value);
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUS_H_
