/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 */

#include "certmgmtservice.h"

#include <iostream>
#include <memory>
#include <string>
#include <tuple>

#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/nt.h>

#include "certfactory.h"
#include "keychainfactory.h"
#include "openssl.h"
#include "ownedptr.h"
#include "security.h"
#include "utilpvt.h"

namespace pvxs {
namespace security {

DEFINE_LOGGER(cert_mgmt, "pvxs.security.certs.mgnt.service");

/**
 * @brief Creates and signs a certificate based on the given certificate
 * creation request.
 *
 * This function takes a shared pointer to a CertCreationRequest object and
 * sends a request to the PVACMS service so it can verify the request and
 * create and sign a certificate.
 * The created certificate is returned as a PEM string including the
 * CA chain all the way back to the root certificate which is included.
 *
 * @param ccr A shared pointer to a CertCreationRequest object containing the
 * information needed to create the certificate.
 * @return PEM string containing certificate and CA chain
 */
std::string CertMgmtService::createAndSignCertificate(const std::shared_ptr<CertCreationRequest> &ccr) const {
    // Build the `uri` which contains the `path` and `query`
    // and in which the `query` contains the arguments which are built
    // from the prototype which contains some common fields and then
    // a verifier field that is specific to the auth type.
    // The `path` points to the PVACMS service's Create PV (RPC_SERVER_CREATE)
    using namespace members;
    std::string p12PemString;
    auto uri = nt::NTURI({}).build();
    uri += {Struct("query", CCR_PROTOTYPE(ccr->verifier_fields))};
    auto arg = uri.create();

    // Set values of request argument
    arg["path"] = RPC_CERT_CREATE;
    arg["query"].from(ccr->ccr);

    // Make a PVAccess client to send request
    // tls_disabled flag set to true so that we won't try to authenticate
    // our side of the session
    std::exception_ptr exptr = nullptr;
    auto pva_client(client::Context::fromEnv(true));

    epicsEvent done;     // To signal from result callback that everything is ok
    Value return_value;  // To store the result, set by result callback

    // Send the CCR to the PVACMS service and wait for the response
    auto name_string = NAME_STRING(arg["query.name"].as<std::string>(), arg["query.organization"].as<std::string>());
    log_debug_printf(cert_mgmt, "RPC call to %s get a certificate using %s for %s\n", RPC_CERT_CREATE,
                     METHOD_STRING(arg["query.type"].as<std::string>()).c_str(), name_string.c_str());
    auto operation = pva_client.rpc(RPC_CERT_CREATE, arg)
                         .result([&return_value, &done, &exptr](client::Result &&result) {
                             try {
                                 auto val = result();
                                 return_value = val;
                             } catch (std::exception &e) {
                                 exptr = std::current_exception();
                             }
                             done.signal();
                         })
                         .exec();

    (void)operation;  // Indicate that operation is intentionally not being used

    // expedite search after starting all requests
    pva_client.hurryUp();
    SigInt sig([&done]() { done.signal(); });

    // if does not complete successfully (timeout) then throw
    if (!done.wait(RPC_SERVER_TIMEOUT)) {
        throw std::runtime_error(
            SB() << "Timeout waiting for certificate creation using " << METHOD_STRING(ccr->type) << ": "
                 << NAME_STRING(ccr->ccr["name"].as<std::string>(), ccr->ccr["organization"].as<std::string>()));
    }

    // Rethrow the exception from the `result()` callback here!
    if (exptr) {
        std::rethrow_exception(exptr);
    }

    // Return the PEM String that represents the certificate and CA chain
    return return_value["cert"].as<std::string>();
}

}  // namespace security
}  // namespace pvxs
