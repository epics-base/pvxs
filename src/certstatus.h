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

#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>

#include "certdate.h"
#include "ownedptr.h"
#include "security.h"

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

/**
 * @brief Get the Certificate Status PV base.
 * e.g., CERT:STATUS
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @return the Certificate Status PV base string
 */
inline std::string getCertStatusPvBase(const std::string &cert_pv_prefix) {
    std::string pv = cert_pv_prefix;
    pv += ":STATUS";
    return pv;
}

/**
 * @brief Get the Certificate Status PV name for configuring the PVACMS listener
 * e.g., CERT:STATUS:0192faeb:*
 * Note that the PVACMS only listens for requests for certificates
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer ID that this PVACMS is serving
 * @return the Certificate Status PV name
 */
inline std::string getCertStatusPv(const std::string &cert_pv_prefix, const std::string& issuer_id) {
    std::string pv = getCertStatusPvBase(cert_pv_prefix);
    pv += ":";
    pv += issuer_id;
    pv += ":*";
    return pv;
}

/**
 * @brief Get the Certificate Issuer PV name
 *
 * This is suitable for networks where there is only one certificate authority.  Clients will
 * not need to specify the issuer they are interested in
 *
 * e.g., CERT:ISSUER
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @return the generic Certificate Issuer PV name
 */
inline std::string getCertIssuerPv(const std::string &cert_pv_prefix) {
    std::string pv = cert_pv_prefix;
    pv += ":ISSUER";
    return pv;
}

/**
 * @brief get the Certificate Issuer PV name
*
 * This is suitable for networks where there are multiple certificate authorities.  Clients will
 * need to specify the issuer they are interested in
 *
 * e.g., CERT:ISSUER:0192faeb
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer ID that this PVACMS is serving
 * @return the generic Certificate Issuer PV name
 */
inline std::string getCertIssuerPv(const std::string &cert_pv_prefix, const std::string& issuer_id) {
    std::string pv = getCertIssuerPv(cert_pv_prefix);
    pv += ":";
    pv += issuer_id;
    return pv;
}

/**
 * @brief Get the Certificate Root Authority PV name
 *
 * This is suitable for networks where there is only one certificate authority.  Clients will
 * not need to specify the issuer they are interested in
 *
 * e.g., CERT:ROOT
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @return the generic Certificate Root Authority PV name
 */
inline std::string getCertAuthRootPv(const std::string &cert_pv_prefix) {
    std::string pv = cert_pv_prefix;
    pv += ":ROOT";
    return pv;
}

/**
 * @brief get the Certificate Root Authority PV name
*
 * This is suitable for networks where there are multiple certificate authorities.  Clients will
 * need to specify the issuer they are interested in
 *
 * e.g., CERT:ROOT:0192faeb
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer ID that this PVACMS is serving
 * @return the generic Certificate Root Authority PV name
 */
inline std::string getCertAuthRootPv(const std::string &cert_pv_prefix, const std::string& issuer_id) {
    std::string pv = getCertAuthRootPv(cert_pv_prefix);
    pv += ":";
    pv += issuer_id;
    return pv;
}

/**
 * @brief Get the Certificate Create PV name
 *
 * This is suitable for networks where there is only one certificate authority.  Clients will
 * not need to specify the issuer they are interested in
 *
 * e.g., CERT:CREATE
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @return the generic Certificate Create PV name
 */
inline std::string getCertCreatePv(const std::string &cert_pv_prefix) {
    std::string pv = cert_pv_prefix;
    pv += ":CREATE";
    return pv;
}

/**
 * @brief get the Certificate Create PV name
*
 * This is suitable for networks where there are multiple certificate authorities.  Clients will
 * need to specify the issuer they are interested in
 *
 * e.g., CERT:CREATE:0192faeb
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer ID that this PVACMS is serving
 * @return the generic Certificate Create PV name
 */
inline std::string getCertCreatePv(const std::string &cert_pv_prefix, const std::string& issuer_id) {
    std::string pv = getCertCreatePv(cert_pv_prefix);
    pv += ":";
    pv += issuer_id;
    return pv;
}

/**
 * @brief Returns the certificate URI.
 *
 * This function takes a prefix and a certificate ID as input parameters and returns the certificate URI.
 * The certificate URI is constructed by concatenating the prefix and the certificate ID using a colon `:` as a separator.
 * The serial number is left padded with zero's to make it 19 characters long
 *
 * e.g., CERT:STATUS:0192faeb:0095472510025972592
 *
 * @param prefix The prefix string for the certificate URI.
 * @param cert_id The certificate ID string.
 * @return The certificate URI string.
 */
inline std::string getCertStatusURI(const std::string &prefix, const std::string &cert_id) {
    const std::string pv_name(SB() << prefix << ":" << cert_id);
    return pv_name;
}

/**
 * @brief Make the config URI for a certificate
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer ID (first 8 hex digits of the hex SKID)
 * @param skid Subject Key Identifier based on a public key used to re-generate Cert
 * @return the config URI
 */
inline std::string getConfigURI(const std::string &cert_pv_prefix, const std::string& issuer_id, const std::string& skid) {
    std::string pv = cert_pv_prefix;
    pv += ":CONFIG:";
    pv += issuer_id;
    pv += ":";
    pv += skid;
    return pv;
}

/**
 * @brief Generates a serial number string as used in a certificate ID.
 *
 * Left pad with zeros in 20 characters
 *
 * @param serial The serial number of the certificate.
 * @return The the serial number string.
 *
 * @see SB
 */
inline std::string getSerialString(const uint64_t &serial) {
    std::ostringstream oss;
    oss << std::setw(20)
        << std::setfill('0')
        << serial;
    return oss.str();
}

/**
 * @brief Generates a unique certificate ID based on the issuer ID and serial number.
 *
 * This function takes the issuer ID and serial number as input and combines them
 * into a unique certificate ID. The certificate ID is generated by concatenating
 * the issuer ID and serial number with a ":" separator.
 *
 * @param issuer_id The issuer ID of the certificate.
 * @param serial The serial number of the certificate.
 * @return The unique certificate ID.
 *
 * @see SB
 */
inline std::string getCertId(const std::string &issuer_id, const uint64_t &serial) {
    std::ostringstream oss;
    oss << issuer_id
        << ":"
        << getSerialString(serial);
    return oss.str();
}

/**
 * @brief Generates the Certificate URI to write into the certificate given the configuration to determine the prefix, the issuer and the serial number
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer id
 * @param serial the certificate's serial number
 * @return the certificate URI to write into the certificate
 */
inline std::string getCertStatusURI(const std::string &cert_pv_prefix, const std::string &issuer_id, const uint64_t &serial) {
    auto cert_uri = getCertStatusPvBase(cert_pv_prefix);
    cert_uri += ":";
    cert_uri += getCertId(issuer_id, serial);
    return cert_uri;
}

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

// Certificate status categories
enum cert_status_category_t : int {
    BAD_STATUS = -1,
    UNKNOWN_STATUS = 0,
    GOOD_STATUS = 1,
};

// Forward declarations
struct PVACertStatus;
struct OCSPCertStatus;

struct DbCert {
    // The certificate's serial number
    uint64_t serial{0};
    // not before
    time_t not_before{0};
    // not after
    time_t not_after{0};
    // renew by
    time_t renew_by{0};
    // status
    certstatus_t status;
    // The certificate's issuer ID (first 8 hex digits of the hex SKID)
    std::string issuer_id{};
    // The certificate's SKID (subject key identifier)
    std::string skid{};
    // The certificate's subject CN
    std::string cn{};
    // The certificate's subject O
    std::string o{};
    // The certificate's subject OU
    std::string ou{};
    // The certificate's subject C
    std::string c{};

    DbCert(const uint64_t serial, const time_t not_after, const time_t renew_by, const certstatus_t status) : serial(serial), not_after(not_after), renew_by(renew_by), status(status) {};
    DbCert() = default;
};

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
     * @brief The prototype of the data returned for a certificate status request
     * Essentially an enum, a serial number and the ocsp response
     *
     * @return The prototype of the data returned for a certificate status request
     */
    static Value getStatusPrototype() {
        using namespace members;

        auto value = TypeDef(TypeCode::Struct, "epics:nt/NTEnum:1.0", {
                        Struct("value", "enum_t", {
                            Int32("index"),
                            StringA("choices"),
                        }),
                        nt::Alarm{}.build().as("alarm"),
                        nt::TimeStamp{}.build().as("timeStamp"),
                        Struct("display", {
                            String("description"),
                        }),
                        Member(TypeCode::UInt64, "serial"),
                        Member(TypeCode::String, "state"),
                        Member(TypeCode::UInt64, "renew_by"),
                        Member(TypeCode::Bool, "renewal_due"),
                        nt::NTEnum{}.build().as("ocsp_status"),
                        Member(TypeCode::String, "ocsp_state"),
                        Member(TypeCode::String, "ocsp_status_date"),
                        Member(TypeCode::String, "ocsp_certified_until"),
                        Member(TypeCode::String, "ocsp_revocation_date"),
                        Member(TypeCode::UInt8A, "ocsp_response"),
        }).create();

        shared_array<const std::string> choices(CERT_STATES);
        value["value.choices"] = choices.freeze();
        shared_array<const std::string> ocsp_choices(OCSP_CERT_STATES);
        value["ocsp_status.value.choices"] = ocsp_choices.freeze();
        return value;
    }

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
     * @brief  Get the issuer ID which is SKID (subject key identifier) of the issuer certificate authority in the given chain
     *
     * First determine the issuer certificate authority certificate then get the SKID
     *
     * @return first 8 hex digits of the hex SKID (Subject Key Identifier)
     */
    static std::string getIssuerId(const ossl_shared_ptr<STACK_OF(X509)>& chain) { return getSkId(getIssuerCa(chain)); }

    /**
     * @brief Get root certificate authority from a certificate authority chain
     * @param chain the certificate authority certificate chain
     * @return the root certificate authority
     */
    static X509* getRootCa(const ossl_shared_ptr<STACK_OF(X509)>& chain) {
        if (!chain || sk_X509_num(chain.get()) <= 0) {
            throw std::runtime_error("Invalid certificate chain");
        }

        const auto root_ca = sk_X509_value(chain.get(), sk_X509_num(chain.get()) - 1);

        if (root_ca == nullptr) {
            throw std::runtime_error("Failed to retrieve root certificate");
        }

        return root_ca;
    }

    /**
     * @brief Get issuer certificate authority from a certificate authority chain
     * @param chain the certificate authority certificate chain
     * @return the issuer certificate authority which is the second one or the first if only one
     */
    static X509* getIssuerCa(const ossl_shared_ptr<STACK_OF(X509)>& chain) {
        if (!chain) {
            throw std::runtime_error("Invalid certificate chain");
        }

        const auto N = sk_X509_num(chain.get());

        if (N <= 0) {
            throw std::runtime_error("Invalid certificate chain");
        }

        const auto issuer_ca = sk_X509_value(chain.get(), 0);

        if (issuer_ca == nullptr) {
            throw std::runtime_error("Failed to retrieve issuer certificate");
        }

        return issuer_ca;
    }

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

    /**
     * @brief Get the first 8 hex digits of the hex SKID (subject key identifier)
     *
     * Computes the SKID from the public key
     *
     * @param pub_key the public key to generate the skid from
     * @return first 8 hex digits of the hex SKID (subject key identifier)
     */
    static std::string getSkId(const std::string& pub_key) { return getFullSkId(pub_key).substr(0, 8); }

    /**
     * @brief Get the full hex SKID (subject key identifier)
     *
     * Computes the SKID from the public key
     *
     * @param pub_key the public key to generate the skid from
     * @return the full hex SKID (subject key identifier)
     */
    static std::string getFullSkId(const std::string& pub_key) {
        const KeyPair key_pair{pub_key};

        // First, DER encode the public key (SubjectPublicKeyInfo)
        const int der_len = i2d_PUBKEY(key_pair.pkey.get(), nullptr);
        if (der_len <= 0) {
            throw std::runtime_error("Failed to DER encode public key");
        }
        std::vector<unsigned char> der_data(der_len);
        unsigned char* der_ptr = der_data.data();
        if (i2d_PUBKEY(key_pair.pkey.get(), &der_ptr) != der_len) {
            throw std::runtime_error("DER encoding size mismatch");
        }

        // Parse the DER data into an X509_PUBKEY structure.
        const unsigned char* der_data_ptr = der_data.data();
        const ossl_ptr<X509_PUBKEY> pubkey_struct(d2i_X509_PUBKEY(nullptr, &der_data_ptr, der_len), false);
        if (!pubkey_struct) {
            throw std::runtime_error("Failed to parse X509_PUBKEY structure");
        }

        // Extract the raw public key BIT STRING (subjectPublicKey)
        ASN1_OBJECT* alg = nullptr;
        const unsigned char* pk_data = nullptr;
        int pk_len = 0;
        X509_ALGOR* algor = nullptr;
        if (!X509_PUBKEY_get0_param(&alg, &pk_data, &pk_len, &algor, pubkey_struct.get())) {
            throw std::runtime_error("Failed to extract public key parameter");
        }

        // Compute the SHA-1 hash of the BIT STRING.
        unsigned char hash[SHA_DIGEST_LENGTH] = {0};
        if (!SHA1(pk_data, pk_len, hash)) {
            throw std::runtime_error("SHA1 computation failed");
        }

        // Convert into a hexadecimal string.
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (const unsigned char i : hash) {
            oss << std::setw(2) << static_cast<unsigned int>(i);
        }

        return oss.str();
    }

    /**
     * @brief Get the common name of the given certificate
     * return the common name or an empty string if cert is null, or
     * there are any problems retrieving the common name
     *
     * @param cert to retrieve the subject CN field
     * @return the common name
     */
    static std::string getCommonName(const ossl_ptr<X509>& cert) {
        if (!cert) return "";

        // Get the subject name from the certificate
        const X509_NAME* subject = X509_get_subject_name(cert.get());
        if (!subject) {
            return "";
        }

        // Find the position of the Common Name field within the subject name
        const int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (idx < 0) {
            return "";
        }

        const X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
        if (!entry) {
            return "";
        }

        const ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (!data) {
            return "";
        }

        // Convert the ASN1_STRING to a UTF-8 C string
        unsigned char* utf8 = nullptr;
        const int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (length < 0 || !utf8) {
            return "";
        }

        // Construct a string from the UTF-8 data
        std::string cn(reinterpret_cast<char*>(utf8), length);
        OPENSSL_free(utf8);

        return cn;
    }


   protected:
    /**
     * @brief Constructor for CertStatus only to be used by PVACertStatus and OCSPCertStatus
     *
     * @param status the enum index of the status
     * @param status_string the string representation of the status
     */
    explicit CertStatus(const uint32_t status, const std::string& status_string) : i(status), s(status_string) {}

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
    bool operator==(const PVACertStatus rhs) const { return this->i == rhs.i; }
    bool operator==(const certstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(const PVACertStatus rhs) const { return this->i != rhs.i; }
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
    bool operator==(const OCSPCertStatus rhs) const { return this->i == rhs.i; }
    bool operator==(const ocspcertstatus_t rhs) const { return this->i == rhs; }
    bool operator!=(const OCSPCertStatus rhs) const { return this->i != rhs.i; }
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
struct CertificateStatus;
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
    ParsedOCSPStatus(const uint64_t& serial, const OCSPCertStatus& ocsp_status, const CertDate& status_date, const CertDate& status_valid_until_date,
                     const CertDate& revocation_date)
        : serial(serial),
          ocsp_status(ocsp_status),
          status_date(status_date),
          status_valid_until_date(status_valid_until_date),
          revocation_date(revocation_date) {}

    CertificateStatus status();
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
    explicit OCSPStatus(const shared_array<const uint8_t>& ocsp_bytes_param, X509_STORE* trusted_store_ptr) : ocsp_bytes(ocsp_bytes_param) {
        if (!trusted_store_ptr) {
            throw std::invalid_argument("Trusted store pointer is null");
        }
        init(trusted_store_ptr);
    }

    explicit OCSPStatus(const uint8_t* ocsp_bytes_ptr, const size_t ocsp_bytes_len, X509_STORE* trusted_store_ptr)
        : ocsp_bytes(ocsp_bytes_ptr, ocsp_bytes_len) {
        if (!trusted_store_ptr) {
            throw std::invalid_argument("Trusted store pointer is null");
        }
        init(trusted_store_ptr);
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
     * @brief Verify that the status validity dates are currently valid and the status is known
     * @return true if the status is still valid
     */
    bool isValid() const noexcept { // NOLINT(*-convert-member-functions-to-static)
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
    bool isGood() const noexcept { return isValid() && ocsp_status == OCSP_CERTSTATUS_GOOD; }

    virtual explicit operator CertificateStatus() const noexcept;

   private:
    friend struct PVACertificateStatus;
    explicit OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t>& ocsp_bytes, CertDate status_date, CertDate status_valid_until_time,
                        CertDate revocation_time);

    void init(X509_STORE* trusted_store_ptr);
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

    explicit PVACertificateStatus(const certstatus_t status, const shared_array<const uint8_t>& ocsp_bytes, X509_STORE* trusted_store_ptr)
        : OCSPStatus(ocsp_bytes, trusted_store_ptr), status(status) {}

    explicit PVACertificateStatus(const Value& status_value, X509_STORE* trusted_store_ptr)
        : PVACertificateStatus(status_value["value.index"].as<certstatus_t>(), status_value["ocsp_response"].as<shared_array<const uint8_t>>(),
                               trusted_store_ptr) {
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
     * @brief Get the status category
     *
     * @return GOOD_STATUS (VALID), BAD_STATUS (REVOKED, EXPIRED), or UNKNOWN_STATUS (everything else)
     */
    cert_status_category_t getStatusCategory() const noexcept { return status == VALID ? GOOD_STATUS : isRevokedOrExpired() ? BAD_STATUS : UNKNOWN_STATUS; }
    cert_status_category_t getEffectiveStatusCategory() const noexcept { return isValid() ? getStatusCategory() : UNKNOWN_STATUS; }

    /**
     * @brief Check if the certificate is Expired of Revoked
     *
     * @return true if the certificate is Expired or Revoked
     */
    bool isRevokedOrExpired() const noexcept { return status == REVOKED || status == EXPIRED; }

    /**
     * @brief Verify that the status is currently valid
     * @return true if the status is still valid
     */
    bool isValid() const noexcept { // NOLINT(*-convert-member-functions-to-static)
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

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTSTATUS_H_
