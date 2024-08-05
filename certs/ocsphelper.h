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
#include "ownedptr.h"

namespace pvxs {
namespace certs {

std::vector<uint8_t> createAndSignOCSPResponse(uint64_t serial, CertificateStatus status, time_t revocation_time, const pvxs::ossl_ptr<X509>& ca_cert, const pvxs::ossl_ptr<EVP_PKEY>& ca_pkey, const pvxs::ossl_shared_ptr<STACK_OF(X509)>& ca_chain);

pvxs::ossl_ptr<OCSP_CERTID> createOCSPCertId(uint64_t serial, const pvxs::ossl_ptr<X509> &ca_cert, const EVP_MD* digest = EVP_sha1());

std::vector<uint8_t> ocspResponseToBytes(const pvxs::ossl_ptr<OCSP_BASICRESP>& basic_resp);

pvxs::ossl_ptr<ASN1_INTEGER> uint64ToASN1(uint64_t serial);

}  // namespace certs
}  // namespace pvxs

#endif //PVXS_OCSPHELPER_H_
