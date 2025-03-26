/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCMS_H_
#define PVXS_CONFIGCMS_H_

#include <certfactory.h>
#include <memory>

#include <pvxs/config.h>
#include <pvxs/server.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

class ConfigCms final : public server::Config {
   public:
    ConfigCms& applyEnv() {
        Config::applyEnv();
        return *this;
    }

    /**
     * @brief Create a CMS configuration from environment variables
     *
     * @return ConfigCms
     */
    static ConfigCms fromEnv() {
        // Get default config
        auto config = ConfigCms{}.applyEnv();

        // Indicate that this is a CMS configuration
        config.config_target = CMS;

        // Disable status checking as this is the CMS itself
        config.tls_disable_status_check = true;

        // Override with any specific CMS configuration from environment variables
        config.fromCmsEnv(std::map<std::string, std::string>());
        return config;
    }

    void updateDefs(defs_t& defs) const override;

    /**
     * @brief Minutes that the ocsp status response will
     * be valid before a client must re-request an update
     */
    uint32_t cert_status_validity_mins = 30;

    /**
     * @brief When basic credentials are used then set to true to
     * request administrator approval to issue client certificates.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_client_require_approval = true;

    /**
     * @brief When basic credentials are used then set to true
     * to request administrator approval to issue server certificates.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_server_require_approval = true;

    /**
     * @brief When basic credentials are used then set to true
     * to request administrator approval to issue hybrid certificates.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_hybrid_require_approval = true;

    /**
     * @brief This flag is used to indicate that a certificate user must subscribe
     * to the certificate status PV to verify certificate's revoked status.
     *
     * With this flag set two extensions are added to created certificates.
     * A flag indicating that subscription is required and a string
     * containing the PV name to subscribe to.
     *
     * If set to YES, status subscription is always required.
     * If set to NO, status subscription is never required.
     * If set to DEFAULT, the client's no_status flag determines whether status subscription is required.
     *
     * Default is DEFAULT
     */
    CertStatusSubscription cert_status_subscription{DEFAULT};

    /**
     * @brief This is the string that determines the fully
     * qualified path to a file that will be used as the sqlite PVACMS
     * certificate database for a PVACMS process.
     *
     * The default is the current directory in a file called certs.db
     */
    std::string certs_db_filename = "certs.db";

    /**
     * @brief This is the string that determines
     * the fully qualified path to the keychain file that contains
     * the certificate authority's certificate, and its private key.
     * It also contains any certificate chain leading back to the root
     * certificate authority if this is not the root.
     *
     * This is used to sign certificates being created in the PVACMS or
     * sign certificate status responses being delivered by OCSP-PVA.
     *
     * Note: This certificate needs to be in all EPICS agents keychain files so
     * that they can trust any certificate or status that it signs.
     */
    std::string cert_auth_keychain_file{};

    /**
     * @brief This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the `cert_auth_keychain_file`.
     *
     * This is optional.  If not specified, the `cert_auth_keychain_file`
     * contents will not be encrypted.
     */
    std::string cert_auth_keychain_pwd{};

    /**
     * @brief This is the string that determines
     * the fully qualified path to the keychain file that contains
     * the admin user's certificate, and public and private keys.
     */
    std::string admin_keychain_file{};

    /**
     * @brief This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the admin user's keychain file.
     */
    std::string admin_keychain_pwd{};

    /**
     * @brief This is the string that determines the
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
     *      USG(ADMINS) {
     *       "admin",
     *       "admin@yourdomain.com"
     *      }
     *
     *      ASG(SPECIAL) {
     *       RULE(0,READ)
     *       RULE(1,WRITE) {
     *         UAG(ADMINS)
     *         METHOD("x509")
     *         AUTHORITY("CN of your Certificate Authority")
     *      }
     *
     * @endcode
     *
     */
    std::string pvacms_acf_filename{"pvacms.acf"};

    /**
     * @brief If a root certificate authority certificate has not been determined
     * prior to the first time that the PVACMS starts up, then one
     * will be created automatically.
     *
     * To provide the `name` (CN) to be used in the subject of the
     * certificate authority certificate we can use this environment variable.
     */
    std::string cert_auth_name = "EPICS Root Certificate Authority";

    /**
     * @brief If a root certificate authority certificate has not been determined
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the certificate authority certificate we can use this environment variable.
     */
    std::string cert_auth_organization = "certs.epics.org";

    /**
     * @brief If a root certificate authority certificate has not been determined
     * established prior to the first time that the PVACMS starts up,
     * then one will be created automatically.
     *
     * To provide the organizational unit (OU) to be used in the
     * subject of the certificate authority certificate we can use this environment variable.
     */
    std::string cert_auth_organizational_unit = "EPICS Certificate Authority";

    /**
     * @brief The certificate authority's country code
     */
    std::string cert_auth_country{"US"};

    /**
     * @brief If a PVACMS certificate has not been established
     * prior to the first time that the PVACMS starts up, then one
     * will be created automatically.
     *
     * To provide the name (CN) to be used in the subject of the
     * PVACMS certificate we can use this environment variable.
     */
    std::string pvacms_name = "PVACMS Service";

    /**
     * @brief If a PVACMS certificate has not been established
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the PVACMS certificate we can use this environment variable.
     */
    std::string pvacms_organization = "certs.epics.org";

    /**
     * @brief If a PVACMS certificate has not been
     * established prior to the first time that the PVACMS starts up,
     * then one will be created automatically.
     *
     * To provide the organizational unit (OU) to be used in the
     * subject of the PVACMS certificate we can use this environment variable.
     */
    std::string pvacms_organizational_unit = "EPICS PVA Certificate Management Service";

    /**
     * @brief The PVACMS Country
     */
    std::string pvacms_country{"US"};

    void fromCmsEnv(const std::map<std::string, std::string>& defs);
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGCMS_H_
