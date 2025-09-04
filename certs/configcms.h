/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCMS_H_
#define PVXS_CONFIGCMS_H_

#include <pvxs/config.h>
#include <pvxs/server.h>

#include "certfactory.h"
#include "configcerts.h"
#include "serverev.h"

namespace pvxs {
namespace certs {

class ConfigCms final : public Config {
   public:
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
     * @brief When basic credentials are used, then set to true
     * to request administrator approval to issue ioc certificates.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_ioc_require_approval = true;

    /**
     * @brief By default, Authenticators can request custom certificate durations.  Setting this flag disallows this for client certificates.
     *
     * This is useful for preventing a client from requesting a client certificate with a duration that is too long.
     *
     * Overrides the `EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION` environment variable, which,
     * if set, overrides the default of false.
     *
     * Default is false
     *
     */
    bool cert_disallow_client_custom_duration = false;

    /**
     * @brief By default, Authenticators can request custom certificate durations.  Setting this flag disallows this for server certificates.
     *
     * This is useful for preventing a client from requesting a server certificate with a duration that is too long.
     *
     * Overrides the `EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION` environment variable, which,
     * if set, overrides the default of false.
     *
     * Default is false
     *
     */
    bool cert_disallow_server_custom_duration = false;

    /**
     * @brief By default, Authenticators can request custom certificate durations.  Setting this flag disallows this for IOC certificates.
     *
     * This is useful for preventing a client from requesting an IOC certificate with a duration that is too long.
     *
     * Overrides the `EPICS_PVACMS_DISALLOW_IOC_CUSTOM_DURATION` environment variable, which,
     * if set, overrides the default of false.
     *
     * Default is false
     *
     */
    bool cert_disallow_ioc_custom_duration = false;

    /**
     * @brief Default client certificate validity period
     *
     * Expressed using format: 1y 2M 3w 4d 5h 6m 7s
     * This is the amount of time that a client certificate will be given to a new client
     * certificate unless overridden by the Authenticator verify routine.
     */
    std::string default_client_cert_validity="6M";

    /**
     * @brief Default server certificate validity period
     *
     * Expressed using format: 1y 2M 3w 4d 5h 6m 7s
     * This is the amount of time that a server certificate will be given to a new server
     * certificate unless overridden by the Authenticator verify routine.
     */
    std::string default_server_cert_validity="6M";

    /**
     * @brief Default IOC certificate validity period
     *
     * Expressed using format: 1y 2M 3w 4d 5h 6m 7s
     * This is the amount of time that a IOC certificate will be given to a new IOC
     * certificate unless overridden by the Authenticator verify routine.
     */
    std::string default_ioc_cert_validity="6M";

    /**
     * @brief This flag is used to indicate that a certificate user must subscribe
     * to the certificate status PV to verify the certificate's revoked status.
     *
     * With this flag set, an extension is added to created certificates -
     * a string containing the PV name to subscribe to.
     *
     * If set to YES, a status subscription is always required.
     * If set to NO, a status subscription is never required.
     * If set to DEFAULT, the client's no_status flag determines whether a status subscription is required.
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
     * certificates and the default read permissions for certificate statuses.
     * There is no default, so it must be specified on the command line or
     * as an environment variable.
     *
     * e.g.
     * @code
     *      AUTHORITY(YOUR_AUTH_ROOT, "CN of your Certificate Authority")
     *
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
     *         AUTHORITY(YOUR_AUTH_ROOT)
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
     * certificate authority certificate, we can use this environment variable.
     */
    std::string cert_auth_name = "EPICS Root Certificate Authority";

    /**
     * @brief If a root certificate authority certificate has not been determined
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the certificate authority certificate, we can use this environment variable.
     */
    std::string cert_auth_organization = "certs.epics.org";

    /**
     * @brief If a root certificate authority certificate has not been determined
     * established prior to the first time that the PVACMS starts up,
     * then one will be created automatically.
     *
     * To provide the organizational unit (OU) to be used in the
     * subject of the certificate authority certificate, we can use this environment variable.
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
     * PVACMS certificate, we can use this environment variable.
     */
    std::string pvacms_name = "PVACMS Service";

    /**
     * @brief If a PVACMS certificate has not been established
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the PVACMS certificate, we can use this environment variable.
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

    void applyCmsEnv(const std::map<std::string, std::string>& defs);
    static ConfigCms forCms();
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGCMS_H_
