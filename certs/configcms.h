/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCMS_H_
#define PVXS_CONFIGCMS_H_

#include <memory>

#include <pvxs/config.h>
#include <pvxs/server.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

class ConfigCms : public pvxs::server::Config {
   public:
    ConfigCms& applyEnv() {
        pvxs::server::Config::applyEnv();
        return *this;
    }

    static inline ConfigCms fromEnv() {
        auto config = ConfigCms{}.applyEnv();
        config.fromCmsEnv(std::map<std::string, std::string>());
        return config;
    }

    /**
     * @brief Minutes that the ocsp status response will
     * be valid before a client must re-request an update
     */
    uint32_t cert_status_validity_mins = 30;

    /**
     * @brief When basic credentials are used then set to true to
     * request administrator approval to issue client certificates.
     *
     * This will mean that clients will have to keep retrying connections
     * until the certificate request is approved by an administrator.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_client_require_approval = false;

    /**
     * @brief When basic credentials are used then set to true
     * to request administrator approval to issue server certificates.
     * This will mean that servers will have to keep retrying connections
     * until the certificate request is approved by an administrator.
     *
     * All other auth methods will never require administrator approval.
     */
    bool cert_server_require_approval = true;

    /**
     * @brief This flag is used to indicate that a certificate user must subscribe
     * to the certificate status PV to verify certificate's revoked status.
     *
     * With this flag set two extensions are added to created certificates.
     * A flag indicating that subscription is required and a string
     * containing the PV name to subscribe to.
     *
     * In absence of this flag certificate validity will work as normal
     * but clients will not know that they have been revoked.
     */
    bool cert_status_subscription_required = false;

    /**
     * @brief This is the string that determines the fully
     * qualified path to a file that will be used as the sqlite PVACMS
     * certificate database for a PVACMS process.
     *
     * The default is the current directory in a file called certs.db
     */
    std::string ca_db_filename = "certs.db";

    /**
     * @brief This is the string that determines
     * the fully qualified path to the PKCS#12 file that contains
     * the CA certificate, and public and private keys.
     *
     * This is used to sign certificates being created in the PVACMS or
     * sign certificate status responses being delivered by OCSP-PVA.
     * If this is not specified it defaults to the TLS_KEYCHAIN file.
     *
     * Note: This certificate needs to be trusted by all EPICS agents.
     */
    std::string ca_cert_filename;

    /**
     * @brief This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the `ca_cert_filename`.
     *
     * This is optional.  If not specified, the `ca_cert_filename`
     * contents will not be encrypted.
     */
    std::string ca_cert_password;

    /**
     * @brief This is the string that determines
     * the fully qualified path to the PKCS#12 key file that contains
     * the private keys.
     *
     * This is optional.  If not specified, the `ca_cert_filename` is used.
     */
    std::string ca_private_key_filename;

    /**
     * @brief This is the string that determines
     * the fully qualified path to a file that contains the password that
     * unlocks the `ca_pkey_filename`.
     */
    std::string ca_private_key_password;

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
     * @brief If a CA root certificate has not been established
     * prior to the first time that the PVACMS starts up, then one
     * will be created automatically.
     *
     * To provide the name (CN) to be used in the subject of the
     * CA certificate we can use this environment variable.
     */
    std::string ca_name = "EPICS Root CA";

    /**
     * @brief If a CA root certificate has not been established
     * prior to the first time that the PVACMS starts up, then one will be
     * created automatically.
     *
     * To provide the organization (O) to be used in the subject of
     * the CA certificate we can use this environment variable.
     */
    std::string ca_organization = "ca.epics.org";

    /**
     * @brief If a CA root certificate has not been
     * established prior to the first time that the PVACMS starts up,
     * then one will be created automatically.
     *
     * To provide the organizational unit (OU) to be used in the
     * subject of the CA certificate we can use this environment variable.
     */
    std::string ca_organizational_unit = "EPICS Certificate Authority";

    void fromCmsEnv(const std::map<std::string, std::string>& defs);
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGCMS_H_
