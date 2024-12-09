/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_LDAP_H
#define PVXS_AUTH_LDAP_H

#include <functional>
#include <memory>
#include <string>

#include <pvxs/config.h>
#include <pvxs/data.h>
#include <pvxs/version.h>

#include "auth.h"
#include "authregistry.h"
#include "certfactory.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_LDAP_AUTH_TYPE "ldap"

namespace pvxs {
namespace security {

/**
 * Definition of the LDAP identification type containing all required LDAP
 * credential information.
 */
struct LdapId {
    int i;  // TODO placeholder
};

/**
 * The subclass of Credentials that contains the LdapAuth specific
 * identification object
 */
struct LdapCredentials : Credentials {
    LdapId id;  // LDAP ID
};

/**
 * @class LdapAuth
 * @brief The LdapAuth class provides LDAP authentication
 * functionality.
 *
 * This class is responsible for retrieving credentials for users that have been
 * authenticated against an LDAP server. It inherits from the Auth base
 * class.
 *
 * In order to use the LdapAuth, it must be registered with the
 * CertFactory using the REGISTER_AUTHENTICATOR() macro.
 *
 * The LdapAuth class implements the getCredentials() and
 * createCertCreationRequest() methods. The getCredentials() method returns the
 * credentials used for authentication. The createCertCreationRequest() method
 * creates a signed certificate using the provided credentials.
 */
class LdapAuth : public Auth {
   public:
    REGISTER_AUTHENTICATOR();

    // Constructor
    LdapAuth() : Auth(PVXS_LDAP_AUTH_TYPE, {}) {};
    ~LdapAuth() override = default;

    std::shared_ptr<Credentials> getCredentials(const impl::ConfigCommon &config) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                   const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify(
        const Value ccr,
        std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const override;

    std::string processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr) const override;
};

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_AUTH_LDAP_H
