/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "ccrmanager.h"

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>

#include "certstatus.h"
#include "openssl.h"
#include "security.h"

DEFINE_LOGGER(auth_log, "pvxs.auth.ccr");

namespace pvxs {
namespace certs {

using namespace members;

/**
 * @brief Create a certificate
 *
 * This function creates a certificate from the given Certificate Creation Request (CCR).
 *
 * @param cert_creation_request Certificate Creation Request (CCR)
 * @param cert_pv_prefix the CMS pv prefix
 * @param issuer_id the issuer ID of the CMS
 * @param timeout Timeout for the request
 * @param timeout Timeout for the request
 * @return std::string PEM format Certificate.
 */
std::tuple<time_t, std::string> CCRManager::createCertificate(const std::shared_ptr<CertCreationRequest> &cert_creation_request, const std::string &cert_pv_prefix, const std::string &issuer_id, const double timeout) {
    auto uri = nt::NTURI({}).build();
    uri += {Struct("query", CCR_PROTOTYPE(cert_creation_request->verifier_fields))};
    auto arg = uri.create();

    // Set values of request argument
    const auto create_pv = issuer_id.empty() ? getCertCreatePv(cert_pv_prefix) : getCertCreatePv(cert_pv_prefix, issuer_id);
    arg["path"] = create_pv;
    arg["query"].from(cert_creation_request->ccr);

    auto config = client::Config::fromEnv();
    config.tls_disabled = true;
    auto client = config.build();
    auto value(client.rpc(create_pv, arg).exec()->wait(timeout));

    std::string pem_string;
    auto pem_val = value["cert"];
    if ( pem_val ) {
        pem_string = pem_val.as<std::string>();
        log_info_printf(auth_log, "X.509 certificate(%s)\n", value["state"].as<std::string>().c_str());
    } else {
        log_info_printf(auth_log, "X.509 certificate RENEWED (%s)\n", value["state"].as<std::string>().c_str());
    }
    log_debug_printf(auth_log, "%s\n", value["status.value.index"].as<std::string>().c_str());
    log_debug_printf(auth_log, "%llu\n", (unsigned long long)value["serial"].as<serial_number_t>());
    log_debug_printf(auth_log, "%s\n", value["issuer"].as<std::string>().c_str());
    log_debug_printf(auth_log, "%s\n", value["cert_id"].as<std::string>().c_str());
    log_debug_printf(auth_log, "%s\n", value["status_pv"].as<std::string>().c_str());
    const auto renew_by_val = value["renew_by"];
    const CertDate expiration_date(value["expiration"].as<time_t>());
    log_debug_printf(auth_log, "Expires On: %s\n", expiration_date.s.c_str() );
    if (renew_by_val) {
        const auto renew_by_t = renew_by_val.as<time_t>() - POSIX_TIME_AT_EPICS_EPOCH;
        const CertDate renew_by(renew_by_t);
        log_debug_printf(auth_log, "Renew By: %s\n", renew_by.s.c_str() );
        return {renew_by.t, pem_string};
    }
    return {0, pem_string};
}
}  // namespace certs
}  // namespace pvxs
