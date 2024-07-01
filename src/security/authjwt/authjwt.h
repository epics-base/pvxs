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
#include "authregistry.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_JWT_AUTH_TYPE "jwt"

namespace pvxs {
namespace security {

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

/**
 * @class JwtAuth
 * @brief The JwtAuth class provides JWT authentication functionality.
 *
 * This class is responsible for retrieving credentials for users that have been
 * authenticated against an JWT server. It inherits from the Auth base
 * class.
 *
 * In order to use the JwtAuth, it must be registered with the
 * CertFactory using the REGISTER_AUTHENTICATOR() macro.
 *
 * The JwtAuth class implements the getCredentials() and
 * createCertCreationRequest() methods. The getCredentials() method returns the
 * credentials used for authentication. The createCertCreationRequest() method
 * creates a signed certificate using the provided credentials.
 */
class JwtAuth : public Auth {
   public:
    REGISTER_AUTHENTICATOR();

    // Constructor
    JwtAuth() : Auth(PVXS_JWT_AUTH_TYPE, {Member(TypeCode::String, "token"), Member(TypeCode::UInt32, "kid")}) {};
    ~JwtAuth() override = default;

    std::shared_ptr<Credentials> getCredentials(const impl::ConfigCommon &config) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                   const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify(
        const Value ccr,
        std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const override;

    static inline void curlInit() {
        static std::once_flag flag;
        std::call_once(flag, []() {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            std::atexit(curlCleanup);
        });
    };

    static void curlCleanup() { curl_global_cleanup(); }

   private:
    static bool getIssuerVerificationStatus(const server::Config &config, const std::string &validation_uri,
                                            const std::string &token, const std::string &key_id);

    static void sendRequest(CURL *curl, const std::string &validation_uri, struct curl_slist *headers,
                            std::string &response_string);

    static size_t writeCallback(void *http_response, size_t member_size, size_t number_of_members,
                                std::string *output_response_string);
};

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_AUTH_JWT_H
