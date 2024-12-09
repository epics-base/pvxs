/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configstd.h"

DEFINE_LOGGER(_logname, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

void ConfigStd::fromStdEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};

    // EPICS_AUTH_STD_CERT_VALIDITY_MINS
    if (pickone({"EPICS_AUTH_STD_CERT_VALIDITY_MINS"})) {
        try {
            cert_validity_mins = parseTo<uint64_t>(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(_logname, "%s invalid validity minutes : %s", pickone.name.c_str(), e.what());
        }
    }

    // EPICS_AUTH_STD_DEVICE_NAME
    if (pickone({"EPICS_AUTH_STD_DEVICE_NAME"})) {
        device_name = pickone.val;
    }

    // EPICS_AUTH_STD_PROCESS_NAME
    if (pickone({"EPICS_AUTH_STD_PROCESS_NAME"})) {
        process_name = pickone.val;
    }

    // EPICS_AUTH_STD_USE_PROCESS_NAME
    if (pickone({"EPICS_AUTH_STD_USE_PROCESS_NAME"})) {
        use_process_name = parseTo<bool>(pickone.val);
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_srv_cert_filename = tls_srv_private_key_filename = pickone.val);
    }

    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"})) {
        tls_srv_cert_password = tls_srv_private_key_password = getFileContents(pickone.val);
    }

    // EPICS_PVAS_TLS_PKEY
    if (pickone({"EPICS_PVAS_TLS_PKEY"})) {
        ensureDirectoryExists(tls_srv_private_key_filename = pickone.val);
    }

    // EPICS_PVAS_TLS_PKEY_PWD_FILE
    if (pickone({"EPICS_PVAS_TLS_PKEY_PWD_FILE"})) {
        tls_srv_private_key_password = getFileContents(pickone.val);
    }
}

}  // namespace certs
}  // namespace pvxs
