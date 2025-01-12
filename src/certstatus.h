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

#include <pvxs/log.h>
#include <pvxs/nt.h>

#include "ownedptr.h"

#define CERT_TIME_FORMAT "%a %b %d %H:%M:%S %Y UTC"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

DEFINE_LOGGER(status_setup, "pvxs.certs.status");

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
class OCSPParseException : public std::runtime_error {
   public:
    explicit OCSPParseException(const std::string& message) : std::runtime_error(message) {}
};

class CertStatusException : public std::runtime_error {
   public:
    explicit CertStatusException(const std::string& message) : std::runtime_error(message) {}
};

class CertStatusNoExtensionException : public CertStatusException {
   public:
    explicit CertStatusNoExtensionException(const std::string& message) : CertStatusException(message) {}
};

class CertStatusSubscriptionException : public CertStatusException {
   public:
    explicit CertStatusSubscriptionException(const std::string& message) : CertStatusException(message) {}
};

// Certificate management
#define GET_MONITOR_CERT_STATUS_ROOT "CERT:STATUS"
#define GET_MONITOR_CERT_STATUS_PV "CERT:STATUS:????????:*"

// All certificate statuses
#define CERT_STATUS_LIST   \
    X_IT(UNKNOWN)          \
    X_IT(VALID)            \
    X_IT(PENDING)          \
    X_IT(PENDING_APPROVAL) \
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
    uint32_t i;
    // string representation of the status
    std::string s;
    // Default constructor
    CertStatus() = default;
    CertStatus(const CertStatus&) = default;
    CertStatus& operator=(const CertStatus&) = default;

    // Move comparison operators to protected
    bool operator==(const CertStatus& rhs) const { return i == rhs.i; }
    bool operator!=(const CertStatus& rhs) const { return !(*this == rhs); }

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
     * @brief  Get the issuer ID which is the first 8 hex digits of the hex SKID (subject key identifier)
     *
     * Note that the given cert must contain the SKID extension in the first place
     *
     * @param ca_cert  the cert from which to get the subject key identifier extension
     * @return first 8 hex digits of the hex SKID (subject key identifier)
     */
    static inline std::string getIssuerId(const ossl_ptr<X509>& ca_cert) { return getIssuerId(ca_cert.get()); }

    /**
     * @brief Get the issuer ID which is the first 8 hex digits of the hex SKID (subject key identifier)
     *
     * Note that the given cert must contain the SKID extension in the first place
     *
     * @param ca_cert_ptr the cert pointer from which to get the subject key identifier extension
     * @return first 8 hex digits of the hex SKID (subject key identifier)
     */
    static inline std::string getIssuerId(X509* ca_cert_ptr) {
        ossl_ptr<ASN1_OCTET_STRING> skid(reinterpret_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(ca_cert_ptr, NID_subject_key_identifier, nullptr, nullptr)),
                                         false);
        if (!skid) {
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

    /**
     * @brief Get the common name of the given certificate
     * return the common name or an empty string if cert is null or
     * there are any problems retrieving the common name
     *
     * @param cert to retrieve the subject CN field
     * @return the common name
     */
    static inline std::string getCommonName(ossl_ptr<X509>& cert) {
        if (!cert) return "";

        // Get the subject name from the certificate
        X509_NAME* subject = X509_get_subject_name(cert.get());
        if (!subject) {
            return "";
        }

        // Find the position of the Common Name field within the subject name
        int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (idx < 0) {
            return "";
        }

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
        if (!entry) {
            return "";
        }

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (!data) {
            return "";
        }

        // Convert the ASN1_STRING to a UTF-8 C string
        unsigned char* utf8 = nullptr;
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (length < 0 || !utf8) {
            return "";
        }

        // Construct a std::string from the UTF-8 data
        std::string cn(reinterpret_cast<char*>(utf8), length);
        OPENSSL_free(utf8);

        return cn;
    }

    /**
     * @brief Make the status URI for a certificate
     *
     * @param issuer_id the issuer ID (first 8 hex digits of the hex SKID)
     * @param serial the serial number
     * @return the status URI
     */
    static inline std::string makeStatusURI(std::string& issuer_id, uint64_t& serial) {
        return SB() << GET_MONITOR_CERT_STATUS_ROOT << ":" << issuer_id << ":" << std::setw(16) << std::setfill('0') << serial;
    }

   protected:
    /**
     * @brief Constructor for CertStatus only to be used by PVACertStatus and OCSPCertStatus
     *
     * @param status the enum index of the status
     * @param status_string the string representation of the status
     */
    explicit CertStatus(const uint32_t status, std::string status_string) : i(status), s(status_string) {}

    // Friend declarations to allow cross-comparisons only between specific types
    friend struct PVACertStatus;
    friend struct OCSPCertStatus;
};

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
    bool operator==(PVACertStatus rhs) const { return this->i == rhs.i; }
    bool operator==(certstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(PVACertStatus rhs) const { return this->i != rhs.i; }
    bool operator!=(certstatus_t rhs) const { return this->i != rhs; }

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
    static inline std::string toString(const certstatus_t status) { return CERT_STATE(status); }
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
    explicit OCSPCertStatus(const ocspcertstatus_t& status) : CertStatus((uint32_t)status, toString(status)) {}

    // Define the comparison operators
    bool operator==(OCSPCertStatus rhs) const { return this->i == rhs.i; }
    bool operator==(ocspcertstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(OCSPCertStatus rhs) const { return this->i != rhs.i; }
    bool operator!=(ocspcertstatus_t rhs) const { return this->i != rhs; }

   private:
    /**
     * @brief Convert the enum index to the string representation of the status.  Internal use only
     *
     * @param status the enum index of the status
     * @return the string representation of the status
     */
    static inline std::string toString(const ocspcertstatus_t& status) { return OCSP_CERT_STATE(status); }
};

/**
 * @brief To create and manipulate status dates.
 * Status dates have a string representation `s` as well as a time_t representation `t`
 */
struct StatusDate {
    // time_t representation of the status date
    std::time_t t;
    // string representation of the status date
    std::string s;

    // Default constructor
    StatusDate() = default;

    // Constructor from time_t
    StatusDate(const std::time_t& time) : t(time), s(toString(time)) {}
    // Constructor from ASN1_TIME*
    StatusDate(const ASN1_TIME* time) : t(asn1TimeToTimeT(time)), s(toString(t)) {}
    // Constructor from ossl_ptr<ASN1_TIME>
    StatusDate(const ossl_ptr<ASN1_TIME>& time) : t(asn1TimeToTimeT(time.get())), s(toString(t)) {}
    // Constructor from time string
    StatusDate(const std::string& time_string) : t(toTimeT(time_string)), s(StatusDate(t).s) {}

    // Define the comparison operator
    inline bool operator==(StatusDate rhs) const { return this->t == rhs.t; }

    // Define the conversion operators
    inline operator const std::string&() const { return s; }
    inline operator std::string() const { return s; }
    inline operator const time_t&() const { return t; }
    inline operator time_t() const { return t; }
    inline operator ossl_ptr<ASN1_TIME>() const { return toAsn1_Time(); };

    /**
     * @brief Create an ASN1_TIME object from this StatusDate object
     * @return and ASN1_TIME object corresponding this StatusDate object
     */
    inline ossl_ptr<ASN1_TIME> toAsn1_Time() const {
        ossl_ptr<ASN1_TIME> asn1(ASN1_TIME_new());
        ASN1_TIME_set(asn1.get(), t);
        return asn1;
    }

    /**
     * @brief Create an ASN1_TIME object from a StatusDate object
     * @return and ASN1_TIME object corresponding the given StatusDate object
     */
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

    /**
     * @brief Convert the given string to a time_t value.
     *
     * The string is assumed to represent a time in the UTC timezone.  The
     * format of the string is defined by `CERT_TIME_FORMAT`.  The string is parsed
     * and the time_t extracted and returned.
     *
     * Any errors in format are signalled by raising OCSPParseExceptions as this function
     * is called from OCSP parsing
     *
     * @param time_string
     * @return
     */
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
    const StatusDate status_date;
    // valid-until date of the OCSP certificate status
    const StatusDate status_valid_until_date;
    // revocation date of the certificate if it is revoked
    const StatusDate revocation_date;

    /**
     * @brief Constructor for ParsedOCSPStatus
     *
     * @param serial the serial number of the certificate
     * @param ocsp_status the OCSP status of the certificate
     * @param status_date the status date of the certificate
     * @param status_valid_until_date the status valid-until date of the certificate
     * @param revocation_date the revocation date of the certificate if it is revoked
     */
    ParsedOCSPStatus(const uint64_t& serial, const OCSPCertStatus& ocsp_status, const StatusDate& status_date, const StatusDate& status_valid_until_date,
                     const StatusDate& revocation_date)
        : serial(serial),
          ocsp_status(ocsp_status),
          status_date(status_date),
          status_valid_until_date(status_valid_until_date),
          revocation_date(revocation_date) {}
};

// Forward declarations of the certificate status structures
struct CertificateStatus;
struct CertifiedCertificateStatus;
struct UnknownCertificateStatus;
struct UnCertifiedCertificateStatus;
struct PVACertificateStatus;

/**
 * @brief Structure representing OCSP status.
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked then there is also a
 * revocation date.  The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct OCSPStatus {
    // raw OCSP response bytes
    shared_array<const uint8_t> ocsp_bytes;
    // OCSP status of the certificate
    OCSPCertStatus ocsp_status;
    // date of the OCSP certificate status
    StatusDate status_date;
    // valid-until date of the OCSP certificate status
    StatusDate status_valid_until_date;
    // revocation date of the certificate if it is revoked
    StatusDate revocation_date;

    // Constructor from a PKCS#7 OCSP response that must be signed by the given trusted root.
    explicit OCSPStatus(const shared_array<const uint8_t>& ocsp_bytes_param, const ossl_ptr<X509> &trusted_root_ca) : ocsp_bytes(ocsp_bytes_param) {
        init(trusted_root_ca);
    }

    // To  set an OCSP UNKNOWN status to indicate errors
    OCSPStatus() : ocsp_status(OCSP_CERTSTATUS_UNKNOWN) {};

    virtual inline bool operator==(const OCSPStatus& rhs) const {
        return this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date && this->status_valid_until_date == rhs.status_valid_until_date &&
               this->revocation_date == rhs.revocation_date;
    }
    virtual inline bool operator!=(const OCSPStatus& rhs) const { return !(*this == rhs); }
    virtual bool operator==(const CertificateStatus& rhs) const;
    virtual inline bool operator!=(const CertificateStatus& rhs) const { return !(*this == rhs); }
    virtual bool operator==(const PVACertificateStatus& rhs) const;
    virtual inline bool operator!=(const PVACertificateStatus& rhs) const { return !(*this == rhs); }
    virtual inline bool operator==(ocspcertstatus_t& rhs) const { return this->ocsp_status == rhs; }
    virtual inline bool operator!=(ocspcertstatus_t& rhs) const { return !(*this == rhs); }
    virtual inline bool operator==(certstatus_t& rhs) const {
        return ((rhs == VALID && this->ocsp_status == OCSP_CERTSTATUS_GOOD) || (rhs == REVOKED && this->ocsp_status == OCSP_CERTSTATUS_REVOKED));
    }
    virtual inline bool operator!=(certstatus_t& rhs) const { return !(*this == rhs); }

    /**
     * @brief Verify that the status validity dates are currently valid and the status is known
     * @return true if the status is still valid
     */
    inline bool isValid() const noexcept {
        auto now(std::time(nullptr));
        return status_valid_until_date.t > now;
    }

    /**
     * @brief Check if the status is permanent
     *
     * @return true if the status is permanent, false otherwise
     */
    inline bool isPermanent() const noexcept { return status_valid_until_date.t == PERMANENTLY_VALID_STATUS; }

    /**
     * @brief Check if the status is GOOD
     *
     * @return true if the status is GOOD, false otherwise
     */
    inline bool isGood() const noexcept { return isValid() && ocsp_status == OCSP_CERTSTATUS_GOOD; }

    virtual explicit operator CertificateStatus() const noexcept;

   private:
    friend struct PVACertificateStatus;
    explicit OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, StatusDate status_date, StatusDate status_valid_until_time,
                        StatusDate revocation_time);

    void init(const ossl_ptr<X509> &trusted_root_ca);
};

bool operator==(ocspcertstatus_t& lhs, OCSPStatus& rhs);
bool operator!=(ocspcertstatus_t& lhs, OCSPStatus& rhs);
bool operator==(certstatus_t& lhs, OCSPStatus& rhs);
bool operator!=(certstatus_t& lhs, OCSPStatus& rhs);

/**
 * @brief Structure representing PVA-OCSP certificate status.  This is a superclass of OCSPStatus
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked then there is also a
 * revocation date.  The status field contains the PVA certificate status in numerical and text form.
 * The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct UnCertifiedCertificateStatus;
struct PVACertificateStatus final : public OCSPStatus {
    explicit PVACertificateStatus(const UnCertifiedCertificateStatus& status);

    PVACertStatus status;
    inline bool operator==(const PVACertificateStatus& rhs) const {
        return this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
               this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
    }
    inline bool operator!=(const PVACertificateStatus& rhs) const { return !(*this == rhs); }

    inline bool operator==(certstatus_t& rhs) const { return this->status == rhs; }
    inline bool operator!=(certstatus_t& rhs) const { return !(*this == rhs); }
    inline bool operator==(ocspcertstatus_t& rhs) const { return this->ocsp_status == rhs; }
    inline bool operator!=(ocspcertstatus_t& rhs) const { return !(*this == rhs); }

    inline bool operator==(const OCSPStatus& rhs) const {
        return (this->status != VALID && this->status != REVOKED)
                   ? false
                   : this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
                         this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
    }
    inline bool operator!=(const OCSPStatus& rhs) const { return !(*this == rhs); }
    bool operator==(const CertificateStatus& rhs) const;
    inline bool operator!=(const CertificateStatus& rhs) const { return !(*this == rhs); }

    explicit PVACertificateStatus(const certstatus_t status, const shared_array<const uint8_t>& ocsp_bytes, const ossl_ptr<X509> &trusted_root_ca)
        : OCSPStatus(ocsp_bytes, trusted_root_ca), status(status) {};

    explicit PVACertificateStatus(const Value& status_value, const ossl_ptr<X509> &trusted_root_ca)
        : PVACertificateStatus(status_value["status.value.index"].as<certstatus_t>(), status_value["ocsp_response"].as<shared_array<const uint8_t>>(), trusted_root_ca) {
        if (ocsp_bytes.empty()) return;
        log_debug_printf(status_setup, "Value Status: %s\n", (SB() << status_value).str().c_str());
        log_debug_printf(status_setup, "Status Date: %s\n", this->status_date.s.c_str());
        log_debug_printf(status_setup, "Status Validity: %s\n", this->status_valid_until_date.s.c_str());
        log_debug_printf(status_setup, "Revocation Date: %s\n", this->revocation_date.s.c_str());
        if (!selfConsistent() || !dateConsistent(status_value["ocsp_status_date"].as<std::string>(), status_value["ocsp_certified_until"].as<std::string>(),
                                                 status_value["ocsp_revocation_date"].as<std::string>())) {
            throw OCSPParseException("Certificate status does not match certified OCSP status");
        };
    }

    // To  set an UNKNOWN status to indicate errors
    PVACertificateStatus() : OCSPStatus(), status(UNKNOWN) {}
    operator CertificateStatus() const noexcept;

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
    explicit PVACertificateStatus(certstatus_t status, ocspcertstatus_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, StatusDate status_date,
                                  StatusDate status_valid_until_time, StatusDate revocation_time)
        : OCSPStatus(ocsp_status, ocsp_bytes, status_date, status_valid_until_time, revocation_time), status(status) {};

    /**
     * @brief Check if the PVACertificateStatus is self-consistent,
     * i.e. the OCSP status values are consistent with the PVA status values
     * @return true if the PVACertificateStatus is self-consistent, false otherwise
     */
    inline bool selfConsistent() {
        return (ocsp_status == OCSP_CERTSTATUS_UNKNOWN && (!(status == VALID || status == REVOKED))) ||
               (ocsp_status == OCSP_CERTSTATUS_REVOKED && (status == REVOKED)) || (ocsp_status == OCSP_CERTSTATUS_GOOD && (status == VALID));
    }

    /**
     * @brief Check if the PVACertificateStatus is date-consistent,
     * i.e. the status date, status valid-until date, and revocation date are all the same
     * @param status_date_value Status date
     * @param status_valid_until_date_value Status valid-until date
     * @param revocation_date_value Revocation date
     * @return true if the PVACertificateStatus is date-consistent, false otherwise
     */
    inline bool dateConsistent(StatusDate status_date_value, StatusDate status_valid_until_date_value, StatusDate revocation_date_value) {
        return (status_date == status_date_value) && (status_valid_until_date == status_valid_until_date_value) && (revocation_date == revocation_date_value);
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

    // Enable copying
    CertificateStatus(const CertificateStatus&) = default;
    CertificateStatus& operator=(const CertificateStatus&) = default;

    explicit CertificateStatus(PVACertificateStatus cs)
        : CertificateStatus(true, cs.status, cs.ocsp_status, cs.status_date, cs.status_valid_until_date, cs.revocation_date) {}

    /**
     * @brief Check if the certificate status is GOOD
     *
     * First checks if the status is still valid, then checks if the ocsp_status is GOOD
     *
     * @return true if the certificate status is GOOD, false otherwise
     */
    inline bool isGood() const noexcept { return isValid() && ocsp_status == OCSP_CERTSTATUS_GOOD; }

    /**
     * @brief Check if the certificate status is ostensibly GOOD
     *
     * This is true if the ocsp_status is GOOD irrespective of whether the status is valid or not.
     * Useful to determine the status a certificate had before that status' validity expired.
     *
     * @return true if the certificate status is ostensibly GOOD, false otherwise
     */
    inline bool isOstensiblyGood() const noexcept { return ocsp_status == OCSP_CERTSTATUS_GOOD; }

    /**
     * @brief Check if the certificate is Expired of Revoked
     *
     * @return true if certificate is Expired or Revoked
     */
    inline bool isRevokedOrExpired() const noexcept { return status == REVOKED || status == EXPIRED; }

    /**
     * @brief Verify that the status is currently valid
     * @return true if the status is still valid
     */
    inline bool isValid() const noexcept {
        auto now(std::time(nullptr));
        return status_valid_until_date.t > now;
    }

    StatusDate status_valid_until_date;
    bool certified;
    PVACertStatus status;
    OCSPCertStatus ocsp_status;
    StatusDate status_date;
    StatusDate revocation_date;

    /**
     * @brief Equality operator for PVACertificateStatus
     * @param rhs PVACertificateStatus object to compare with
     * @return true if the PVACertificateStatus objects are equal, false otherwise
     */
    inline bool operator==(const PVACertificateStatus& rhs) const { return (CertificateStatus)rhs == *this; }
    /**
     * @brief Inequality operator for PVACertificateStatus
     * @param rhs PVACertificateStatus object to compare with
     * @return true if the PVACertificateStatus objects are not equal, false otherwise
     */
    inline bool operator!=(const PVACertificateStatus& rhs) const { return !(*this == rhs); }
    /**
     * @brief Equality operator for CertificateStatus
     * @param rhs CertificateStatus object to compare with
     * @return true if the CertificateStatus objects are equal, false otherwise
     */
    inline bool operator==(const CertificateStatus& rhs) const {
        return this->certified == rhs.certified && this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
               this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
    }

   protected:
    // Protected constructor for derived classes
    CertificateStatus(bool is_certified, PVACertStatus st, OCSPCertStatus ocsp_st, StatusDate st_date, StatusDate valid_until, StatusDate rev_date)
        : status_valid_until_date(valid_until), certified(is_certified), status(st), ocsp_status(ocsp_st), status_date(st_date), revocation_date(rev_date) {}

    /**
     * @brief Inequality operator for CertificateStatus
     * @param rhs CertificateStatus object to compare with
     * @return true if the CertificateStatus objects are not equal, false otherwise
     */
    inline bool operator!=(const CertificateStatus& rhs) const { return !(*this == rhs); }

    /**
     * @brief Equality operator for certstatus_t
     * @param rhs certstatus_t value to compare with
     * @return true if the certstatus_t value is equal to the status, false otherwise
     */
    inline bool operator==(certstatus_t& rhs) const { return this->status == rhs; }

    /**
     * @brief Inequality operator for certstatus_t
     * @param rhs certstatus_t value to compare with
     * @return true if the certstatus_t value is not equal to the status, false otherwise
     */
    inline bool operator!=(certstatus_t& rhs) const { return !(*this == rhs); }

    /**
     * @brief Equality operator for ocspcertstatus_t
     * @param rhs ocspcertstatus_t value to compare with
     * @return true if the ocspcertstatus_t value is equal to the ocsp_status, false otherwise
     */
    inline bool operator==(ocspcertstatus_t& rhs) const { return this->ocsp_status == rhs; }

    /**
     * @brief Inequality operator for ocspcertstatus_t
     * @param rhs ocspcertstatus_t value to compare with
     * @return true if the ocspcertstatus_t value is not equal to the ocsp_status, false otherwise
     */
    inline bool operator!=(ocspcertstatus_t& rhs) const { return !(*this == rhs); }

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
 * Create by casting a `CertificateStatus` or by passing one to the single argument constructor.
 *
 * The `CertifiedCertificateStatus` struct encapsulates various attributes related to the
 * status of a certified certificate, including PVA certificate status, OCSP status, status date,
 * status valid-until date, and revocation date.
 */
struct CertifiedCertificateStatus final : public CertificateStatus {
    explicit CertifiedCertificateStatus(PVACertificateStatus cs)
        : CertificateStatus(true, cs.status, cs.ocsp_status, cs.status_date, cs.status_valid_until_date, cs.revocation_date) {};

   private:
    friend struct OCSPStatus;
    explicit CertifiedCertificateStatus(OCSPStatus cs)
        : CertificateStatus(true, PVACertStatus(cs.ocsp_status == OCSP_CERTSTATUS_GOOD ? VALID : REVOKED), cs.ocsp_status, cs.status_date,
                            cs.status_valid_until_date, cs.revocation_date) {};
};

struct UnknownCertificateStatus final : public CertificateStatus {
    UnknownCertificateStatus()
        : CertificateStatus(false, (PVACertStatus)UNKNOWN, (OCSPCertStatus)OCSP_CERTSTATUS_UNKNOWN, std::time(nullptr), PERMANENTLY_VALID_STATUS, (time_t)0) {};
};

struct UnCertifiedCertificateStatus final : public CertificateStatus {
    UnCertifiedCertificateStatus()
        : CertificateStatus(false, (PVACertStatus)VALID, (OCSPCertStatus)OCSP_CERTSTATUS_GOOD, std::time(nullptr), PERMANENTLY_VALID_STATUS, (time_t)0) {};
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUS_H_
