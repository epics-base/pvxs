/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_JWT_H
#define PVXS_AUTH_JWT_H

#include <functional>
#include <memory>
#include <string>

#include <curl/curl.h>

#include <pvxs/config.h>
#include <pvxs/data.h>
#include <pvxs/server.h>
#include <pvxs/version.h>

#include "auth.h"
#include "configjwt.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_JWT_AUTH_TYPE "jwt"

namespace pvxs {
namespace certs {
constexpr int PORT = 8080;
const std::string TOKEN_ENDPOINT = "/token";

/**
 * Definition of the JWT identification type that contains the token and any
 * other required identification info.
 */
struct Jwt {
    std::string token;
    int32_t kid;  // key ID if present
};

/**
 * The subclass of Credentials that contains the JwtAuth specific
 * identification object
 */
struct JwtCredentials : public Credentials {
    Jwt jwt;  // jwt
};

class AuthNJwt : public Auth {
    public:
    // Constructor
    AuthNJwt() : Auth(PVXS_JWT_AUTH_TYPE, {}) {};
    ~AuthNJwt() override = default;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify(const Value ccr, std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const override;

    client::Config fromEnv() {
        return static_cast<client::Config>(ConfigJwt::fromEnv());
    };

    std::string getOptionsText() {return " [jwt options]";}
    std::string getParameterHelpText() {return  "\n"
                                              "jwt options\n"
                                              "        --jwt-request_format <format>        The JWT request format.  String containing \"#token#\"\n"
                                              "        --jwt-request-method <method>        The JWT request method.  GET or POST\n"
                                              "        --jwt-response-format <format>       The JWT response format.  String containing \"#response#\"\n"
                                              "        --jwt-trusted_uri <uri>              The trusted URI to validate JWT tokens against\n"
                                              "        --jwt-use_response-code <yes|no>     Use the HTTP response code (200) instead of the response body to indicate success.  Default no\n";}

    void addParameters(CLI::App & app, const std::map<const std::string, client::Config> & authn_config_map) {
        auto &config = authn_config_map.at(PVXS_JWT_AUTH_TYPE);
        auto config_jwt = static_cast<const ConfigJwt &>(config);
        app.add_option("--jwt-request_format", config_jwt.jwt_request_format, "Specify LDAP account name");
        app.add_option("--jwt-request-method", config_jwt.jwt_request_method, "Specify LDAP account's password file");
        app.add_option("--jwt-response-format", config_jwt.jwt_response_format, "Specify LDAP hostname or IP address");
        app.add_option("--jwt-trusted_uri", config_jwt.jwt_trusted_uri, "Specify LDAP port number");
        app.add_option("--jwt-use_response-code", config_jwt.jwt_use_response_code, "Specify LDAP search root");
    }
};



}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_JWT_H
