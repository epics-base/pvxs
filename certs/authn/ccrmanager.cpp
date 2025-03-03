/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "ccrmanager.h"

#include <pvxs/nt.h>

#include "client.h"
#include "pvacms.h"
#include "security.h"

DEFINE_LOGGER(auths, "pvxs.certs.auth.ccr");

namespace pvxs {
namespace certs {

using namespace members;

/**
 * @brief Create a certificate
 *
 * This function creates a certificate from the given Certificate Creation Request (CCR).
 *
 * @param cert_creation_request Certificate Creation Request (CCR)
 * @param timeout Timeout for the request
 * @return std::string PEM format Certificate.
 */
std::string CCRManager::createCertificate(const std::shared_ptr<CertCreationRequest> &cert_creation_request, double timeout) {
    auto uri = nt::NTURI({}).build();
    uri += {Struct("query", CCR_PROTOTYPE(cert_creation_request->verifier_fields))};
    auto arg = uri.create();

    // Set values of request argument
    arg["path"] = RPC_CERT_CREATE;
    arg["query"].from(cert_creation_request->ccr);

    auto client = client::Config::fromEnv(true).build();
    auto value(client.rpc(RPC_CERT_CREATE, arg).exec()->wait(timeout));

    log_info_printf(auths, "X.509 CLIENT certificate%s\n", "");
    log_info_printf(auths, "%s\n", value["status.value.index"].as<std::string>().c_str());
    log_info_printf(auths, "%s\n", value["state"].as<std::string>().c_str());
    log_info_printf(auths, "%llu\n", value["serial"].as<serial_number_t>());
    log_info_printf(auths, "%s\n", value["issuer"].as<std::string>().c_str());
    log_info_printf(auths, "%s\n", value["certid"].as<std::string>().c_str());
    log_info_printf(auths, "%s\n", value["statuspv"].as<std::string>().c_str());
    return value["cert"].as<std::string>();
}
}  // namespace certs
}  // namespace pvxs
