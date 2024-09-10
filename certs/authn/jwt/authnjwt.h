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

//#include "auth.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_JWT_AUTH_TYPE "jwt"

namespace pvxs {
namespace certs {

const int PORT = 8080;
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

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_JWT_H
