/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 */

#include "certstatusclient.h"

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

#include "openssl.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "security.h"
#include "utilpvt.h"
#include "certstatusmanager.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(cert_mgmt, "pvxs.certs.status");

CertificateStatus CertStatusClient::get() const {
    auto serial = CertStatusManager::getSerialNumber(cert_);
    auto issuer_id = CertStatus::getIssuerId(cert_);
    auto status_uri = CertStatus::makeStatusURI(issuer_id, serial);

    auto client(client::Context::fromEnv());
    auto status_value = client.get(status_uri).exec()->wait(5.0);
    auto status = CertStatusManager::valToStatus(status_value);
    return status;
}

}  // namespace security
}  // namespace pvxs
