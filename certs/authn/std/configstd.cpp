/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configstd.h"

DEFINE_LOGGER(cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigStd::fromStdEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_STD_CERT_VALIDITY_MINS
    if (pickone({"EPICS_AUTH_STD_CERT_VALIDITY_MINS"})) {
        try {
            cert_validity_mins = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(cfg, "%s invalid validity minutes : %s", pickone.name.c_str(), e.what());
        }
    }

    // EPICS_AUTH_STD_NAME
    if (pickone({"EPICS_PVA_AUTH_STD_NAME"})) {
        name = server_name = pickone.val;
    }

    // EPICS_AUTH_STD_ORG
    if (pickone({"EPICS_PVA_AUTH_STD_ORG"})) {
        organization = server_organization = pickone.val;
    }

    // EPICS_AUTH_STD_ORG_UNIT
    if (pickone({"EPICS_PVA_AUTH_STD_ORG_UNIT"})) {
        organizational_unit = server_organizational_unit = pickone.val;
    }

    // EPICS_AUTH_STD_COUNTRY
    if (pickone({"EPICS_PVA_AUTH_STD_COUNTRY"})) {
        country = server_country = pickone.val;
    }

    // EPICS_AUTH_STD_NAME
    if (pickone({"EPICS_PVAS_AUTH_STD_NAME"})) {
        server_name = pickone.val;
    }

    // EPICS_AUTH_STD_ORG
    if (pickone({"EPICS_PVAS_AUTH_STD_ORG"})) {
        server_organization = pickone.val;
    }

    // EPICS_AUTH_STD_ORG_UNIT
    if (pickone({"EPICS_PVAS_AUTH_STD_ORG_UNIT"})) {
        server_organizational_unit = pickone.val;
    }

    // EPICS_AUTH_STD_COUNTRY
    if (pickone({"EPICS_PVAS_AUTH_STD_COUNTRY"})) {
        server_country = pickone.val;
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_srv_cert_filename = pickone.val);
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"})) {
        tls_srv_cert_password = getFileContents(pickone.val);
    }
}

}  // namespace certs
}  // namespace pvxs
