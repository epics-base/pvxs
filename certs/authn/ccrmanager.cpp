// Created on 19/09/2024.
//
#include <pvxs/nt.h>

#include "ccrmanager.h"
#include "client.h"
#include "security.h"
#include "pvacms.h"

DEFINE_LOGGER(auths, "pvxs.certs.auth");

namespace pvxs {
namespace certs {

using namespace members;

std::string CCRManager::createCertificate(const std::shared_ptr<CertCreationRequest> &cert_creation_request) const {
    std::string p12PemString;
    auto uri = nt::NTURI({}).build();
    uri += {Struct("query", CCR_PROTOTYPE(cert_creation_request->verifier_fields))};
    auto arg = uri.create();

    // Set values of request argument
    arg["path"] = RPC_CERT_CREATE;
    arg["query"].from(cert_creation_request->ccr);

    auto ctxt(client::Context::fromEnv());
    auto value(ctxt.rpc(RPC_CERT_CREATE, arg).exec()->wait(5.0));

    log_info_printf(auths, "X.509 CLIENT certificate%s\n", "");
    log_info_printf(auths, "%s\n", value["status.value.index"].as<std::string>().c_str());
    log_info_printf(auths, "%s\n", value["state"].as<std::string>().c_str());
    log_info_printf(auths, "%llu\n", value["serial"].as<uint64_t>());
    log_info_printf(auths, "%s\n", value["issuer"].as<std::string>().c_str());
    log_info_printf(auths, "%s\n", value["certid"].as<std::string>().c_str());
    log_info_printf(auths, "%s\n", value["statuspv"].as<std::string>().c_str());
    return value["cert"].as<std::string>() ;
}
} // certs
} // pvxs
