/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnldap.h"

#include <configldap.h>
#include <memory>
#include <string>

#include <pvxs/config.h>

#include "auth.h"
#include "authregistry.h"

DEFINE_LOGGER(auth, "pvxs.auth.ldap");

namespace pvxs {
namespace certs {

struct AuthNLdapRegistrar {
    AuthNLdapRegistrar() { // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_LDAP_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNLdap()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_ldap_registrar;

std::shared_ptr<Credentials> AuthNLdap::getCredentials(const client::Config &config) const {
    auto ldap_config = dynamic_cast<const ConfigLdap&>(config);

    log_debug_printf(auth,
                     "\n******************************************\n"
                     "LDAP Authenticator: %s\n",
                     "Begin acquisition");

    auto ldap_credentials = std::make_shared<LdapCredentials>();
    throw std::runtime_error("Process not authenticated with LDAP");
    return ldap_credentials;
};

std::shared_ptr<CertCreationRequest> AuthNLdap::createCertCreationRequest(
    const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const {
    auto ldap_credentials = castAs<LdapCredentials, Credentials>(credentials);

    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);

    return cert_creation_request;
};

bool AuthNLdap::verify(const Value ccr,
                      std::function<bool(const std::string &, const std::string &)> signature_verifier) const {
    // Verify that the signature provided in the CCR that was established in the
    // GSSAPI session was validated and signed
    return signature_verifier(ccrToString(ccr), ccr["verifier.signature"].as<std::string>());
}

}  // namespace security
}  // namespace pvxs
