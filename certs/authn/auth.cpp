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

#include "authregistry.h"
#include "ccrmanager.h"
#include "certfactory.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "security.h"

namespace pvxs {
namespace certs {

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
std::shared_ptr<CertCreationRequest> Auth::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair,
                                                                     const uint16_t &usage) const {
    // Create a new CertCreationRequest object.
    auto cert_creation_request = std::make_shared<CertCreationRequest>(type_, verifier_fields_);
    cert_creation_request->credentials = credentials;

    // Fill in the ccr from the base data we've gathered so far.
    cert_creation_request->ccr["type"] = type_;
    cert_creation_request->ccr["usage"] = usage;
    cert_creation_request->ccr["pub_key"] = key_pair->public_key;
    cert_creation_request->ccr["name"] = credentials->name;
    cert_creation_request->ccr["country"] = credentials->country;
    cert_creation_request->ccr["organization"] = credentials->organization;
    cert_creation_request->ccr["organization_unit"] = credentials->organization_unit;
    cert_creation_request->ccr["not_before"] = credentials->not_before;
    cert_creation_request->ccr["not_after"] = credentials->not_after;
    cert_creation_request->ccr["config_uri_base"] = credentials->config_uri_base;
    return cert_creation_request;
}

/**
 * @brief Get a pointer to the singleton Auth object for the given type.
 *
 * This function returns a pointer to the singleton Auth object for the given type.
 *
 * @param type the type of the Auth object to get (e.g. "std", "ldap", "krb", "jwt")
 * @return a pointer to the singleton Auth object for the given type
 * @throws std::logic_error if the Auth object for the given type is not found
 */
Auth *Auth::getAuth(const std::string &type) {
    auto auth = AuthRegistry::instance().getAuth(type);
    if (auth == nullptr) {
        throw std::logic_error("Auth::getAuth: no such auth type");
    }
    return auth;
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
 * @param timeout the timeout for the request
 * @return the certificate in PEM format with the CA chain ordered from leaf to root
 * @throws std::runtime_error when exceptions arise
 *
 * @note It is the responsibility of the caller to ensure that the
 * CCR object is valid and contains the required information
 * before calling this function.
 */
std::string Auth::processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &cert_creation_request, double timeout) const {
    // Forward the ccr to the certificate management service
    return ccr_manager_.createCertificate(cert_creation_request, timeout);
}
}  // namespace certs
}  // namespace pvxs
