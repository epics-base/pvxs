/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

/**
 * @file authnstd.h the Default Authenticator.
 *
 * Provides class to encapsulate the Default Authenticator and defines custom
 * credentials for use with the authenticator.
 *
 * The default authenticator uses the hostname, and the username unless a
 * process name is provided in configuration, in which case it replaces the
 * username.
 *
 * ZERO TRUST:
 * For this, the Default Authenticator, there is nothing that the PVACMS can do
 * to verify the authenticity of the information contained in the credentials we
 * generate except for verification of the IP address from which the request
 * came, and even then, when the request comes via a gateway, this is not
 * possible. Other authenticators have their credentials verified in the PVACMS
 * so it can be sure of the claims of the certificate it is signing.
 *
 * IT IS THEREFORE THE RESPONSIBILITY OF THE ADMINISTRATOR OF THE PVACMS
 * TO IMPLEMENT POLICIES THAT ENSURE THAT ONLY AUTHORISED CLIENTS
 * (PVA CLIENTS AND SERVERS) CAN GET CERTIFICATES.
 *
 * The PVACMS provides facilities for maintaining a whitelist, and for
 * generating keys to be added to the certificate creation request (as the name)
 * to somewhat validate the credentials.
 *
 * For clients the security implications are less than for servers.  The
 * requirement is mainly to simply identify unique users, rather than to verify
 * that they are who they say they are.
 *
 * FOR SERVERS, IT IS RECOMMENDED THAT THEY ARE CONFIGURED MANUALLY THE FIRST
 * TIME AND THAT FROM THEN ON THEY ARE AUTOMATICALLY RENEWED BEFORE THE
 * EXPIRATION OF THEIR CERTIFICATES.
 */

#ifndef PVXS_AUTH_DEFAULT_H
#define PVXS_AUTH_DEFAULT_H

#include <functional>
#include <memory>
#include <string>

#include <pvxs/data.h>
#include <pvxs/version.h>

#include "auth.h"
#include "authregistry.h"
#include "certfactory.h"
#include "configstd.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_X509_AUTH_DEFAULT_VALIDITY_S (static_cast<time_t>(365.25 * 24 * 60 * 60) / 2)  // Half a year
#define PVXS_X509_AUTH_HOSTNAME_MAX 1024
#define PVXS_X509_AUTH_USERNAME_MAX 256

namespace pvxs {
namespace certs {

/**
 * The subclass of Credentials that contains the AuthNStd specific
 * identification object
 */
struct DefaultCredentials : Credentials {};

class AuthNStd : public Auth {
   public:
    // Constructor
    AuthNStd() : Auth(PVXS_DEFAULT_AUTH_TYPE, {}) {}
    ~AuthNStd() override = default;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config) const override;
    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify(Value ccr) const override;
    void fromEnv(std::unique_ptr<client::Config> &config) override {
        config.reset(new ConfigStd(ConfigStd::fromEnv()));
    }
    std::string getOptionsText() override {return {};}
    std::string getParameterHelpText() override {return {};}
    void addParameters(CLI::App & app, std::map<const std::string, std::unique_ptr<client::Config>> & authn_config_map) override {}
    void configure(const client::Config &config) override {};
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_DEFAULT_H
