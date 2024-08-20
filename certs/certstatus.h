/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The OCSP helper functions
 *
 *   ocsphelper.h
 *
 */
#ifndef PVXS_CERTSTATUS_H_
#define PVXS_CERTSTATUS_H_

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>

#include "certmgmtservice.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

extern const int kMonthStartDays[];
extern const std::string kCertStatusPrefix;
extern Value kStatusPrototype;

///////////// OSCP RESPONSE ERRORS
class OCSPParseException : public std::runtime_error {
   public:
    explicit OCSPParseException(const std::string& message) : std::runtime_error(message) {}
};

template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = OwnedPtr<T, cert_status_delete<T>>;

// Certificate management
#define GET_MONITOR_CERT_STATUS_ROOT "CERT:STATUS"
#define GET_MONITOR_CERT_STATUS_PV "CERT:STATUS:????????:*"

// All certificate statuses
#define CERT_STATUS_LIST   \
    X_IT(UNKNOWN)          \
    X_IT(VALID)            \
    X_IT(EXPIRED)          \
    X_IT(REVOKED)          \
    X_IT(PENDING_APPROVAL) \
    X_IT(PENDING)

// Define the enum
#define X_IT(name) name,
enum certstatus_t { CERT_STATUS_LIST };
#undef X_IT

// String initializer list
#define X_IT(name) #name,
#define CERT_STATES {CERT_STATUS_LIST}
#define OCSP_CERT_STATES {"OCSP_CERTSTATUS_GOOD", "OCSP_CERTSTATUS_REVOKED", "OCSP_CERTSTATUS_UNKNOWN"}

// Gets status name based on index
#define CERT_STATE(index) ((const char*[])CERT_STATES[(index)])
#define OCSP_CERT_STATE(index) ((const char*[])OCSP_CERT_STATES[(index)])

std::string getIssuerId(X509* ca_cert_ptr);
Value getStatusPrototype();
std::string makeStatusURI(std::string& issuer_id, uint64_t& serial);

/**
 * @brief Base class for Certificate status values.  Contains the enum index `i`
 * and the string representation `s` of the value for logging
 */
struct CertStatus {
    const uint32_t i;
    const std::string s;
    CertStatus() = delete;

   protected:
    explicit CertStatus(const uint32_t status, std::string&& status_string) : i(status), s(std::move(status_string)) {}
};

/**
 * @brief PVA Certificate status values enum and string
 */
struct PVACertStatus : CertStatus {
    PVACertStatus() = delete;

    explicit PVACertStatus(const certstatus_t& status) : CertStatus(status, toString(status)) {}

   private:
    static inline std::string toString(const certstatus_t status) { return CERT_STATE(status); }
};

/**
 * @brief OCSP Certificate status values enum and string
 */
struct OCSPCertStatus : CertStatus {
    OCSPCertStatus() = delete;

    explicit OCSPCertStatus(const uint32_t& status) : CertStatus(status, toString(status)) {}

   private:
    static inline std::string toString(const uint32_t status) { return OCSP_CERT_STATE(status); }
};

/**
 * @brief To create and manipulate status dates.
 * Status dates have a string representation `s` as well as a time_t representation `t`
 */
struct StatusDate {
    const std::time_t t;
    const std::string s;

    StatusDate() = delete;

    StatusDate(const std::time_t& time) : t(time), s(toString(time)) {}
    StatusDate(const std::tm& tm) : t(tmToTimeTUTC(tm)), s(toString(t)) {}
    StatusDate(const ASN1_TIME* time) : t(asn1TimeToTimeT(time)), s(toString(t)) {}

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
        if (std::strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Y", std::localtime(&time))) {
            return std::string(buffer);
        } else {
            throw OCSPParseException("Failed to format status date");
        }
    }

    /**
     * @brief To get the time_t (unix time) from a std::tm structure
     * @param tm std::tm structure to convert
     * @return a time_t (unix time) version
     */
    static inline time_t tmToTimeTUTC(const std::tm& tm) {
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
 * @brief Structure representing OCSP status.
 *
 * It contains the OCSP response bytes as well as the date the status was set and how
 * long the status is valid for.  If the status is revoked then there is also a
 * revocation date.  The ocsp_status field contains the OCSP status in numerical and text form.
 */
struct OCSPStatus {
    const OCSPCertStatus ocsp_status;
    const shared_array<const uint8_t> ocsp_bytes;
    const StatusDate status_date;
    const StatusDate status_valid_until_date;
    const StatusDate revocation_date;

    explicit OCSPStatus(uint32_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, StatusDate status_date, StatusDate status_valid_until_date,
                        StatusDate revocation_date)
        : ocsp_status(ocsp_status),
          ocsp_bytes(ocsp_bytes),
          status_date(status_date),
          status_valid_until_date(status_valid_until_date),
          revocation_date(revocation_date) {};
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
    const PVACertStatus status;

    explicit CertificateStatus(certstatus_t status, uint32_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, StatusDate status_date,
                               StatusDate status_valid_until_date, StatusDate revocation_date)
        : OCSPStatus(ocsp_status, ocsp_bytes, status_date, status_valid_until_date, revocation_date), status(status) {};
};

/**
 * @brief Class used to create OCSP certificate status responses
 *
 * You can create a cert_status_creator and reuse it to make response statuses for
 * certificates providing their serial number and the desired status by calling
 * `createOCSPStatus()`.
 *
 * When using the getters (e.g. status()) be aware that they are references into
 * the class and so each time you call createOCSPStatus() these reference values
 * change.
 *
 * @code
 *      static auto cert_status_creator(CertStatusCreator(config, ca_cert, ca_pkey, ca_chain));
 *      auto cert_status = cert_status_creator.createOCSPStatus(serial, new_state);
 * @endcode
 */
class CertStatusCreator {
   public:
    /**
     * @brief Used to make OCSP responses for given statuses
     * You need the private key of the CA in order to do this.
     * Subsequently call createOCSPStatus() to make responses for certificates
     *
     * @param ca_cert the CA certificate to use to sign the OCSP response
     * @param ca_pkey the CA's private key to use to sign the response
     * @param ca_chain the CA's certificate change used to sign any response
     * @param cert_status_validity_mins_ the number of minutes the status is valid for
     *
     * @see createOCSPStatus()
     */
    CertStatusCreator(const ossl_ptr<X509>& ca_cert, const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain,
                      uint32_t cert_status_validity_mins = 30)
        : ca_cert_(ca_cert), ca_pkey_(ca_pkey), ca_chain_(ca_chain), cert_status_validity_mins_(cert_status_validity_mins) {};

    /**
     * @brief Create OCSP status for certificate identified by serial number
     * The configured ca_cert and ca_chain is encoded into the response so that consumers of the response can determine the issuer
     * and the chain of trust.  The issuer will have to have previously trusted the root certificate as this will
     * be verified.  The response will be signed with the configured private key so that authenticity of the response can be verified.
     *
     * The result contains the signed OCSP response as well as unencrypted OCSP status, status date , status validity date and
     * revocation date if applicable.
     * The PVA status is also included for completeness
     *
     * @param serial the serial number of the certificate to create an OCSP response for
     * @param status the PVA certificate status to create an OCSP response with
     * @param status_date the status date to set in the OCSP response
     * @param revocation_time the revocation date to set in the OCSP response if applicable
     *
     * @return the Certificate Status containing the signed OCSP response and other OCSP response data.
     */
    CertificateStatus createOCSPStatus(uint64_t serial, certstatus_t status, StatusDate status_date = std::time(nullptr),
                                       StatusDate revocation_time = std::time(nullptr));

   private:
    const ossl_ptr<X509>& ca_cert_;                          // CA Certificate to encode in the OCSP responses
    const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey_;                // CA Certificate's private key to sign the OCSP responses
    const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain_;  // CA Certificate chain to encode in the OCSP responses
    const uint32_t cert_status_validity_mins_;               // The status validity period in minutes to encode in the OCSP responses

    /**
     * @brief Internal function to create an OCSP CERTID.  Uses CertStatusCreator configuration
     * @param digest the method to use to create the CERTID
     * @return an OCSP CERTID
     */
    pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(const uint64_t& serial, const EVP_MD* digest = EVP_sha1());
    /**
     * @brief Internal function to convert an OCSP_BASICRESP into a byte array
     * @param basic_resp the OCSP_BASICRESP to convert
     * @return a byte array
     */
    std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);

    /**
     * @brief Internal function to convert a PVA serial number into an ASN1_INTEGER
     * @param serial the serial number to convert
     * @return ASN1_INTEGER
     */
    static pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1(const uint64_t& serial);
};

/**
 * @brief This class is used to parse OCSP responses and to get/subscribe to certificate status
 *
 * Parsing OCSP responses is carried out by providing the OCSP response buffer
 * to the static `parse()` function. This function will verify the response comes
 * from a trusted source, is well formed, and then will return the `OCSPStatus`
 * it indicates.
 * @code
 *  auto ocsp_status(CertStatusManager::parse(ocsp_response);
 * @endcode
 *
 * To get certificate status call the status `getStatus()` method with the
 * the certificate you want to get status for.  It will make a request
 * to the PVACMS to get certificate status for the certificate. After verifying the
 * authenticity of the response and checking that it is from a trusted
 * source it will return `CertificateStatus`.
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
    using StatusCallback = std::function<void(const CertificateStatus&)>;

    /**
     * @brief To parse OCSP responses
     *
     * Parsing OCSP responses is carried out by providing the OCSP response buffer.
     * This function will verify the response comes from a trusted source,
     * is well formed, and then will return the `OCSPStatus` it indicates.
     *
     * @param ocsp_bytes the ocsp response
     * @return the OCSP response status
     */
    static OCSPStatus parse(shared_array<const uint8_t> ocsp_bytes);

    /**
     * @brief Used to create a helper that you can use to subscribe to certificate status with
     * Subsequently call subscribe() to subscribe
     *
     * @param config the config to use
     * @param cert the certificate for which you want to subscribe to status
     *
     * @see unsubscribe()
     */
    static cert_status_ptr<CertStatusManager> subscribe(const ossl_ptr<X509>& cert, StatusCallback& callback);

    /**
     * @brief Get status for a given certificate
     * @param cert the certificate for which you want to get status
     * @return CertificateStatus
     */
    static CertificateStatus getStatus(const ossl_ptr<X509>& cert);

    /**
     * @brief Unsubscribe from listening to certificate status
     *
     * This function idempotent unsubscribe from the certificate status updates
     */
    void unsubscribe();

    /**
     * @brief Get status for a currently subscribed certificate
     * @return CertificateStatus
     */
    CertificateStatus getStatus();

   private:
    CertStatusManager(const ossl_ptr<X509>& cert, std::shared_ptr<client::Subscription> sub) : cert_(cert), sub_(sub) {};
    const ossl_ptr<X509>& cert_;
    const std::shared_ptr<client::Subscription> sub_;

    static ossl_ptr<OCSP_RESPONSE> getOSCPResponse(const shared_array<const uint8_t>& ocsp_bytes);
    static bool verifyOCSPResponse(ossl_ptr<OCSP_BASICRESP>& basic_response);
    static uint64_t ASN1ToUint64(ASN1_INTEGER* asn1_number);
    static CertificateStatus valToStatus(const Value& val);
    static uint64_t getSerialNumber(const ossl_ptr<X509>& cert);

    std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);
};

template <>
struct cert_status_delete<CertStatusManager> {
    inline void operator()(CertStatusManager* base_pointer) {
        if (base_pointer) {
            base_pointer->unsubscribe();  // Idempotent unsubscribe
            delete base_pointer;
        }
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUS_H_
