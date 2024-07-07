/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCMS_H_
#define PVXS_CONFIGCMS_H_

#include <memory>

#include "ownedptr.h"

#include "certconfig.h"

class ConfigCms : public Config {
  public:
    /**
     * @brief PVACMS only: Minutes before expiry that `EXPIRY_IMMINENT`
     * status should be set on a certificate status.
     *
     * When a server or client receives such a status it will try to
     * renew the cert but will keep a backup and if it fails to renew
     * it will continue to use the original one.
     */
    uint32_t cert_pre_expiry_mins = 1440;

    /**
     * @brief PVACMS only: When basic credentials are used then set to true to
     * request administrator approval to issue client certificates.
     *
     * This will mean that clients will have to keep retrying connections
     * until the certificate request is approved by an administrator.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_client_require_approval = false;

    /**
     * @brief PVACMS only: When basic credentials are used then set to true
     * to request administrator approval to issue server certificates.
     * This will mean that servers will have to keep retrying connections
     * until the certificate request is approved by an administrator.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_server_require_approval = true;

    /**
     * @brief PVACMS only: This is the string that determines the fully
     * qualified path to a file that will be used as the sqlite PVACMS
     * certificate database for a PVACMS process.
     *
     * The default is the current directory in a file called certs.db
     */
    std::string ca_db_filename = "certs.db";

    /**
     * @brief PVACMS and OCSP-PVA only: This is the string that determines
     * the fully qualified path to the PKCS#12 keychain file that contains
     * the CA certificate, and public and private keys.
     *
     * This is used to sign certificates being created in the PVACMS or
     * sign certificate status responses being delivered by OCSP-PVA.
     * If this is not specified it defaults to the TLS_KEYCHAIN file.
     *
     * Note: This certificate needs to be trusted by all EPICS agents.
     */
    std::string ca_keychain_filename;

    /**
     * @brief PVACMS and OCSP-PVA only: This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the `ca_keychain_filename`.
     *
     * This is optional.  If not specified, the `ca_keychain_filename`
     * contents will not be encrypted.
     */
    std::string ca_keychain_password;

    /**
     * @brief PVACMS only: This is the string that determines the
     * fully qualified path to a file that will be used as the
     * ACF file that configures the permissions that are accorded
     * to validated peers of the PVACMS.
     *
     * This will specify administrators that have the right to revoke
     * certificates, and the default read permissions for certificate statuses.
     * There is no default so it must be specified on the command line or
     * as an environment variable.
     *
     * e.g.
     * @code
     *      AG(ADMINS) {
     *       "ed@slac.stanford.edu",
     *       "greg@slac.stanford.edu"
     *      }
     *
     *      SG(SPECIAL) {
     *       RULE(1,WRITE,TRAPWRITE) {
     *         UAG(ADMINS)
     *      }
     *
     * @endcode
     *
     */
    std::string ca_acf_filename;

    /**
     * @brief PVACMS only: If a CA root certificate has not been established
     * prior to the first time that the PVACMS starts up, then one
     * will be created automatically.
     *
     * To provide the name (CN) to be used in the subject of the
     * CA certificate we can use this environment variable.
     */
    std::string ca_name = "EPICS Root CA";

    /**
     * @brief PVACMS only: If a CA root certificate has not been established
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the CA certificate we can use this environment variable.
     */
    std::string ca_organization = "ca.epics.org";

    /**
     * @brief PVACMS only: If a CA root certificate has not been
     * established prior to the first time that the PVACMS starts up,
     * then one will be created automatically.
     *
     * To provide the organizational unit (OU) to be used in the
     * subject of the CA certificate we can use this environment variable.
     */
    std::string ca_organizational_unit = "EPICS Certificate Authority";

};

class ConfigCmsFactory : public ConfigFactoryInterface {
  public:
    std::unique_ptr<Config> create() override {
        return std::make_unique<ConfigCms>();
    }
};

#endif //PVXS_CONFIGCMS_H_
