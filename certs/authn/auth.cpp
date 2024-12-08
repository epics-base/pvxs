/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "auth.h"

#include <iostream>
#include <memory>
#include <string>

#include <pvxs/log.h>

#include "ccrmanager.h"
#include "ownedptr.h"
#include "security.h"
#include "certfactory.h"
#include "p12filefactory.h"

namespace pvxs {
namespace  certs {

/**
 * @brief Creates a signed certificate.
 *
 * Create a PVStructure that corresponds to the ccr parameter of a certificate
 * creation request. This request will be sent to the PVACMS through the default
 * channel (PVAccess) and will be used to create the certificate.
 *
 * @param credentials the credentials that describe the subject of the
 * certificate
 * @param key_pair the public/private key to be used in the certificate, only
 * public key is used
 * @param usage the desired certificate usage
 * @return A managed shared CertCreationRequest object.
 */
std::shared_ptr<CertCreationRequest> Auth::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                     const std::shared_ptr<KeyPair> &key_pair,
                                                                     const uint16_t &usage) const {
    // Create a new CertCreationRequest object.
    auto cert_creation_request = std::make_shared<CertCreationRequest>(type_, verifier_fields_);
    cert_creation_request->credentials = credentials;

    // Fill in the ccr from the base data we've gathered so far.
    cert_creation_request->ccr["name"] = credentials->name;
    cert_creation_request->ccr["country"] = credentials->country;
    cert_creation_request->ccr["organization"] = credentials->organization;
    cert_creation_request->ccr["organization_unit"] = credentials->organization_unit;
    cert_creation_request->ccr["type"] = type_;
    cert_creation_request->ccr["usage"] = usage;
    cert_creation_request->ccr["not_before"] = credentials->not_before;
    cert_creation_request->ccr["not_after"] = credentials->not_after;
    cert_creation_request->ccr["pub_key"] = key_pair->public_key;
    return cert_creation_request;
}

/**
 * @brief Signs a certificate.
 *
 * This function takes a certificate creation request and sends its ccr
 * PVStructure to PVACMS to be signed. It will wait for the signed signature or
 * any reported error.
 *
 * @param cert_creation_request A shared pointer to a CertCreationRequest object
 * containing the ccr PVStructure which contains the certificate, and its
 * validity as well as any verifier specific required fields.
 * @return the signed certificate
 * @throws std::runtime_error when exceptions arise
 *
 * @note It is the responsibility of the caller to ensure that the
 * cert_creation_request object is valid and contains the required information
 * before calling this function.
 */
std::string Auth::processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &cert_creation_request) const {
    // Forward the ccr to the certificate management service
    std::string p12_pem_string(ccr_manager_.createCertificate(cert_creation_request));
    return p12_pem_string;
}

std::shared_ptr<KeyPair> Auth::createKeyPair(const ConfigCommon &config) {
    // Create a key pair
    const auto key_pair(CertFileFactory::createKeyPair());

    // Create PKCS#12 file containing private key
    CertFileFactory::create(config.tls_private_key_filename,
                            config.tls_private_key_password,
                            key_pair)->writeIdentityFile();
    return key_pair;
}
}  // namespace certs
}  // namespace pvxs
