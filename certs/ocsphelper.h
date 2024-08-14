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

///////////// OSCP RESPONSE CREATION
std::string asn1TimeToString(ASN1_GENERALIZEDTIME* time);
time_t asn1TimeToTimeT(ASN1_TIME* time);
std::vector<uint8_t> createAndSignOCSPResponse(ConfigCms &config, uint64_t serial, CertStatus status, const pvxs::ossl_ptr<X509>& ca_cert,
                                               const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain,
                                               time_t status_date=std::time(nullptr), time_t revocation_time=std::time(nullptr));
std::vector<std::vector<uint8_t>> createAndSignOCSPResponses(std::vector<uint64_t> serial, std::vector<CertStatus> status,
                                                             std::vector<time_t> revocation_time, std::vector<const X509*>& ca_cert,
                                                             std::vector<const EVP_PKEY*>& ca_pkey, std::vector<const STACK_OF(X509) *>& ca_chain);

pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(uint64_t serial, const pvxs::ossl_ptr<X509>& ca_cert, const EVP_MD* digest = EVP_sha1());
std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);
pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1(uint64_t serial);

///////////// OSCP RESPONSE PROCESSING
class OCSPParseException : public std::runtime_error {
  public:
    explicit OCSPParseException(const std::string& message) : std::runtime_error(message) {}
};

ossl_ptr<OCSP_RESPONSE> getOSCPResponse(const shared_array<uint8_t>& ocsp_bytes);

template <typename T>
int parseOCSPResponse(const shared_array<uint8_t>& ocsp_bytes, T& status_date, T& status_certified_until, T& revocation_date,
                      std::function<T(ASN1_GENERALIZEDTIME*)>&& date_convert_fn = asn1TimeToString);

template <typename T>
std::vector<int> parseOCSPResponses(const shared_array<uint8_t>& ocsp_bytes, std::vector<T>& status_date, std::vector<T>& status_certified_until,
                                    std::vector<T>& revocation_date, std::function<T(ASN1_GENERALIZEDTIME*)>&& date_convert_fn = asn1TimeToString);

bool verifyOCSPResponse(const shared_array<uint8_t>& ocsp_bytes, ossl_ptr<X509> &ca_cert) ;

}  // namespace certs
}  // namespace pvxs

#include "ocspparse.tpp"  // Include implementation file

#endif  // PVXS_OCSPHELPER_H_
