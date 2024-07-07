/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnjwt.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include <curl/curl.h>
#include <json/json.h>
#include <jwt-cpp/jwt.h>

#include <pvxs/config.h>
#include <pvxs/server.h>

#include "auth.h"
#include "security.h"

namespace pvxs {
namespace security {

DEFINE_LOGGER(auths, "pvxs.security.auth.jwt");

std::shared_ptr<Credentials> JwtAuth::getCredentials(const impl::ConfigCommon &config) const {
    log_debug_printf(auths, "\n******************************************\nJWT Auth: %s\n", "Begin acquisition");

    const auto &token = config.jwt_token;
    if (token.empty()) {
        throw std::runtime_error("Process not authenticated with JWT");
    }
    auto jwt_credentials = std::make_shared<JwtCredentials>();
    try {
        // Decode token
        auto decoded = jwt::decode(token.c_str());
        auto payload_json = decoded.get_payload_json();

        jwt_credentials->name = payload_json["sub"].to_str();
        // Split out organisation if its present
        std::size_t found;
        if ((found = jwt_credentials->name.find('@')) != std::string::npos) {
            jwt_credentials->organization = jwt_credentials->name.substr(found + 1);
            jwt_credentials->name.resize(found);
        }
        jwt_credentials->organization_unit = payload_json["aud"].to_str();
        jwt_credentials->not_before = static_cast<time_t>(payload_json["nbf"].get<double>());
        jwt_credentials->not_after = static_cast<time_t>(payload_json["exp"].get<double>());
        jwt_credentials->jwt.token = token;
        char *end;
        std::string str(payload_json["kid"].to_str());
        long number = std::strtol(str.c_str(), &end, 10);

        if (end == str.c_str()) {
            std::cout << "Conversion error, non-convertible part: " << end;
        } else if (errno == ERANGE) {
            std::cout << "Conversion error, out of range of integer.";
        } else {
            jwt_credentials->jwt.kid = static_cast<int32_t>(number);
        }
        log_debug_printf(auths, "JWT Credentials retrieved for: %s@%s\n", jwt_credentials->name.c_str(),
                         jwt_credentials->organization.c_str());

    } catch (const std::exception &e) {
        throw std::runtime_error(SB() << "Invalid JWT: " << e.what());
    }

    return jwt_credentials;
};

/**
 * @brief Create the CCR with a JWT token.
 * This will add the token to the verifier fields of a standard CCR request
 *
 * @param credentials the credentials that have already been extracted from the
 * JWT token
 * @param key_pair the key pair that has been created to secure this certificate
 * @param usage certificate usage
 * @return a shared pointer to a CCR
 */
std::shared_ptr<CertCreationRequest> JwtAuth::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                        const std::shared_ptr<KeyPair> &key_pair,
                                                                        const uint16_t &usage) const {
    auto jwt_credentials = castAs<JwtCredentials, Credentials>(credentials);

    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);

    // JWT specific fields
    cert_creation_request->ccr["verifier.token"] = jwt_credentials->jwt.token;
    cert_creation_request->credentials = jwt_credentials;

    return cert_creation_request;
};

/**
 * @brief To verify that the token is authentic.
 *
 * This is called on the PVACMS server to verify that the token is authentic.
 * It will contact the issuer and ask it if the token is valid.  It will return
 * true if the issuer says the certificate is valid and that the information
 * in the token corresponds to the information requested in the CCR.
 *
 * @param ccr the Certificate Creation Request containing the token
 * @return true if the issuer says the certificate is valid and that the
 * information in the token corresponds to the information requested in the CCR
 */
bool JwtAuth::verify(const Value ccr, std::function<bool(const std::string &, const std::string &)>) const {
    // initialise curl globally for life of executable (will be cleaned up
    // automatically afterward
    curlInit();

    // Get environment variables configured for this server
    static auto const config(server::Config::fromEnv());

    auto token = ccr["verifier.token"].as<std::string>();

    // Extract validation uri JWT header
    auto decoded = jwt::decode(token);
    auto header_json = decoded.get_payload_json();
    auto validation_uri = header_json["iss"].to_str();
    std::string key_id;
    try {
        key_id = header_json["kid"].to_str();
    } catch (...) {
    }

    // Make sure that the validation URI is the same as the trusted URI in the
    // config.
    if (validation_uri != config.jwt_trusted_uri) {
        throw std::runtime_error("Validation URI does not match trusted URI");
    }

    return getIssuerVerificationStatus(config, validation_uri, token, key_id);
}

/**
 * @brief Get the issuer verification status
 *
 * There are many ways to call the verification URI.  This function uses
 * the provided config to determine which one to use (GET/POST, HTTP response
 * code vs decoded HTTP response body).  It will return true if the
 * issuer validates the token and false if it does not
 *
 * @param config the config used to determine how to communicate with the issuer
 * @param validation_uri  the verification uri from the issuer
 * @param token the token to verify
 * @param key_id key ID to use to verify
 * @return true if the issuer validates the token, false otherwise
 */
bool JwtAuth::getIssuerVerificationStatus(const server::Config &config, const std::string &validation_uri,
                                          const std::string &token, const std::string &key_id) {
    std::string post_body;
    CURL *curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to allocate CURL handle");

    try {
        // Set response type to json
        struct curl_slist *headers = nullptr;
        if (!(headers = curl_slist_append(headers, "Content-Type: application/json"))) {
            throw std::runtime_error("Failed to set response type header");
        }

        try {
            if (config.jwt_request_method == server::Config::GET) {
                // Set token in auth header if this is a GET
                std::string header = "Authorization: Bearer " + token;
                headers = curl_slist_append(headers, header.c_str());
            } else {
                // token in POST body if this is a POST
                post_body = config.getJwtRequest(token, key_id);
                curl_easy_setopt(curl, CURLOPT_POST,
                                 1L);  // Specify the request is a POST request
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_body.length());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body.c_str());
            }

            // Execute the request
            std::string response;
            sendRequest(curl, validation_uri, headers, response);

            // Cleanup headers
            curl_slist_free_all(headers);
            // Cleanup curl handle
            curl_easy_cleanup(curl);

            if (config.jwt_use_response_code) return true;

            return config.isJwtResponseValid(response);
        } catch (...) {
            // Cleanup headers
            curl_slist_free_all(headers);
            std::rethrow_exception(std::current_exception());
        }
    } catch (...) {
        // Cleanup curl handle
        curl_easy_cleanup(curl);
        std::rethrow_exception(std::current_exception());
    }
}

/**
 * @brief Send request to the validation endpoint.
 * The endpoint is referenced by the validation_uit parameter.  Headers
 * will have been set up as either authorization header, or json mime type.
 * A response string reference is provided that is filled with
 * response data if any is read.
 *
 * @param curl the curl context pointer
 * @param validation_uri the validation uri to call
 * @param headers the previously-set-up headers
 * @param response_string the place to store the response if one is returned
 * @throws if the call gave HTTP response code other than 200
 */
void JwtAuth::sendRequest(CURL *curl, const std::string &validation_uri, struct curl_slist *headers,
                          std::string &response_string) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, validation_uri.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

    // Perform the request
    res = curl_easy_perform(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (res == CURLE_OK && response_code == 200) return;

    throw std::runtime_error(SB() << "received " << response_code
                                  << " HTTP response code while calling validation URI: " << validation_uri);
}

/**
 * @brief The callback provided to the curl framework that is called when
 * data is ready to be read back as the result of the HTTP request (the response).
 *
 * @param http_response The HTTP response data
 * @param member_size the size of each member in the http response data
 * @param number_of_members the number of members in the http response data
 * @param output_response_string pointer to output response string
 * @return the amount of data written to the output response string
 */
size_t JwtAuth::writeCallback(void *http_response, size_t member_size, size_t number_of_members,
                              std::string *output_response_string) {
    output_response_string->append((char *)http_response, member_size * number_of_members);
    return member_size * number_of_members;
}

}  // namespace security
}  // namespace pvxs
