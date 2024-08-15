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
#ifndef PVXS_OCSPHELPER_H_
#define PVXS_OCSPHELPER_H_

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "certmgmtservice.h"
#include "configcms.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

class OCSPHelper {
   public:
    struct StatusDate {
        std::time_t t{};
        std::string s{};
        StatusDate() = default;
        explicit StatusDate(std::time_t t) : t(t) {
            char buffer[100];
            std::strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Y", std::localtime(&t));
            s = buffer;
        }
    };

    inline const uint64_t& serial() const { return serial_; }
    inline const CertStatus& status() const { return status_; }
    inline const uint32_t& ocsp_status() const { return ocsp_status_; }
    inline const std::string& status_date() const { return status_date_.s; }
    inline const std::string& status_valid_until_date() const { return status_valid_until_time_.s; }
    inline const std::string& revocation_date() const { return revocation_time_.s; }
    inline const std::time_t& status_time() const { return status_date_.t; }
    inline const std::time_t& status_valid_until_time() const { return status_valid_until_time_.t; }
    inline const std::time_t& revocation_time() const { return revocation_time_.t; }
    inline const std::vector<uint8_t>& ocsp_response() const { return ocsp_response_; }

    /**
     * @brief An OCSP Helper that can be used to make OCSP responses for given statuses
     * You need the private key of the CA in order to do this.
     *
     * @param config
     * @param ca_cert
     * @param ca_pkey
     * @param ca_chain
     */
    OCSPHelper(const ConfigCms& config, const ossl_ptr<X509>& ca_cert, const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey,
               const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain)
        : config_(config), ca_cert_(ca_cert), ca_pkey_(ca_pkey), ca_chain_(ca_chain), process_mode_(false) {};

    // An OCSP Helper that can be used to parse and verify OCSP responses and determine status
    OCSPHelper(const ConfigCms& config, const shared_array<uint8_t>& ocsp_bytes, const pvxs::ossl_ptr<X509>& ca_cert, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain);
    void makeOCSPResponse(uint64_t serial, CertStatus status, time_t status_date = std::time(nullptr), time_t revocation_time = std::time(nullptr));
    static time_t asn1TimeToTimeT(ASN1_TIME* time);

   private:
    static const int kMonthStartDays[];

    const ConfigCms& config_;
    const ossl_ptr<X509>& ca_cert_;
    const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey_;
    const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain_;
    const bool process_mode_;

    uint64_t serial_{};
    CertStatus status_{};
    uint32_t ocsp_status_{};
    StatusDate status_date_;
    StatusDate status_valid_until_time_;
    StatusDate revocation_time_;
    std::vector<uint8_t> ocsp_response_{};

    pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(const EVP_MD* digest = EVP_sha1());
    std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);
    pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1();
    std::string asn1TimeToString(ASN1_GENERALIZEDTIME* time);
    static time_t tmToTimeTUTC(std::tm& tm);

    bool verifyOCSPResponse(const shared_array<uint8_t>& ocsp_bytes);
    ossl_ptr<OCSP_RESPONSE> getOSCPResponse(const shared_array<uint8_t>& ocsp_bytes);
};

///////////// OSCP RESPONSE ERRORS
class OCSPParseException : public std::runtime_error {
   public:
    explicit OCSPParseException(const std::string& message) : std::runtime_error(message) {}
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_OCSPHELPER_H_
