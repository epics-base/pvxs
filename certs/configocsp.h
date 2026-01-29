/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCMS_H_
#define PVXS_CONFIGCMS_H_

#include <memory>

#include "ownedptr.h"

class ConfigCms : public Config {
   public:
    /**
     * @brief The port for the OCSP server to listen on.
     */
    unsigned short ocsp_port = 8080;

    /**
     * @brief This is the string that determines
     * the fully qualified path to the keychain file that contains
     * the certificate authority certificate, and public and private keys.
     *
     * This is used to sign certificates being created in the PVACMS or
     * sign certificate status responses being delivered by OCSP-PVA.
     * If this is not specified it defaults to the TLS_KEYCHAIN file.
     *
     * Note: This certificate needs to be trusted by all EPICS agents.
     */
    std::string cert_auth_keychain_file;

    /**
     * @brief This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the `cert_auth_keychain_file`.
     *
     * This is optional.  If not specified, the `cert_auth_keychain_file`
     * contents will not be encrypted.
     */
    std::string cert_auth_keychain_pwd;
};

class ConfigCmsFactory : public ConfigFactoryInterface {
   public:
    std::unique_ptr<Config> create() override { return std::make_unique<ConfigCms>(); }
};

#endif  // PVXS_CONFIGCMS_H_
