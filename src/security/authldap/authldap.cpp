/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authldap.h"

#include <memory>
#include <string>

#include <pvxs/config.h>

#include "auth.h"
#include "authregistry.h"
#include "security.h"

namespace pvxs {
namespace security {

DEFINE_LOGGER(auths, "pvxs.security.auth.LDAP");

std::shared_ptr<Credentials> LdapAuth::getCredentials(const impl::ConfigCommon &config) const {
    log_debug_printf(auths,
                     "\n******************************************\nLDAP "
                     "Authenticator: %s\n",
                     "Begin acquisition");

    auto ldap_credentials = std::make_shared<LdapCredentials>();
    throw std::runtime_error("Process not authenticated with LDAP");
    return ldap_credentials;
};

std::shared_ptr<CertCreationRequest> LdapAuth::createCertCreationRequest(
    const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const {
    auto ldap_credentials = castAs<LdapCredentials, Credentials>(credentials);

    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);

    return cert_creation_request;
};

std::string LdapAuth::processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr) const {
    throw std::runtime_error("Custom Signer: Failed to sign certificate.");
    return nullptr;
}

bool LdapAuth::verify(const Value ccr,
                      std::function<bool(const std::string &, const std::string &)> signature_verifier) const {
    // Verify that the signature provided in the CCR that was established in the
    // GSSAPI session was validated and signed
    return signature_verifier(ccrToString(ccr), ccr["verifier.signature"].as<std::string>());
}

}  // namespace security
}  // namespace pvxs
