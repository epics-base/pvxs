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

void Auth::runDaemon(const ConfigAuthN &authn_config, bool for_client, ossl_ptr<X509> &&cert, const std::function<ossl_ptr<X509>()> &&fn) {
    auto serial = CertStatusFactory::getSerialNumber(cert);
    std::string issuer_id(CertStatus::getIssuerId(cert));

    // Check time before certificate expires
    const time_t now = time(nullptr);
    const StatusDate expiry_date = X509_get_notAfter(cert.get());
    time_t expires_in = expiry_date.t - now;

    const ConfigMonitor config_monitor_params{authn_config, cert, std::move(fn)};
    auto config = server::Config::fromEnv(true);
    // set alternative server ports so that we avoid clashes normally
    config.tcp_port += PVXS_NON_CLASH_PORT_OFFSET;
    config.tls_port += PVXS_NON_CLASH_PORT_OFFSET;
    config.udp_port += PVXS_NON_CLASH_PORT_OFFSET;
    config_server_ = server::Server(config, [&config_monitor_params](short evt) { return configMonitor(config_monitor_params); });
    server::SharedPV config_pv(server::SharedPV::buildMailbox());

    config_pv.onFirstConnect(
        [&authn_config, &expires_in, for_client, &issuer_id, &serial, this](server::SharedPV &pv) {
            pv.close();

            Value config_value;
            const auto was_open = pv.isOpen();
            if (was_open) {
                config_value = pv.fetch();
            } else {
                config_value = getConfigPrototype();
            }
            setValue<uint64_t>(config_value, "serial", serial);
            setValue<std::string>(config_value, "issuer_id", issuer_id);
            setValue<std::string>(config_value, "keychain", for_client ? authn_config.tls_keychain_file : authn_config.tls_srv_keychain_file);
            setValue<uint64_t>(config_value, "expires_in", expires_in);

            if (was_open) {
                pv.post(config_value);
            } else {
                pv.open(config_value);
            }
        });

    config_pv.onLastDisconnect(
        [](server::SharedPV &pv) { pv.close(); });

    const std::string pv_name = CertStatus::makeConfigURI(authn_config.config_uri_base, issuer_id, serial);
    config_server_.addPV(pv_name, config_pv);
    std::cout << "Config server listening on: " << pv_name << std::endl;
    config_server_.run();
}

timeval Auth::configMonitor(const ConfigMonitor &config_monitor_params) {
    // Check time before certificate expires
    const time_t now = time(nullptr);
    const StatusDate expiry_date = X509_get_notAfter(config_monitor_params.cert_.get());
    time_t expires_in = expiry_date.t - now;

    // If timer has not yet expired
    if (expires_in > 0) {
        // Set time interval for next callback and return
        return {expires_in, 0};
    }

    // If timer has expired call function to get a new certificate
    config_monitor_params.cert_ = config_monitor_params.fn_();
    if (!config_monitor_params.cert_) {
        // Stop if no cert retrieved
        return {0, 0};
    }
    StatusDate new_expiry_date = X509_get_notAfter(config_monitor_params.cert_.get());
    expires_in = expiry_date.t - now;

    if ( expires_in <= 0 ) {
        // Stop if new cert has expired
        return {0, 0};
    }

    // Otherwise post an update and wait until this new cert has expired

    return {expires_in, 0};
}

}  // namespace certs
}  // namespace pvxs
