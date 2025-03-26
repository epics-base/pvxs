/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_KERB_H
#define PVXS_AUTH_KERB_H

#include <functional>
#include <string>

#include <configkrb.h>

#ifdef __APPLE__
#include <GSS/gssapi_krb5.h>
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#include <pvxs/data.h>

#include "auth.h"
#include "configkrb.h"
#include "security.h"

#define PVXS_KRB_AUTH_TYPE "krb"
#define GSS_STATUS_BUFFER_LEN 1024

namespace pvxs {
namespace certs {

// Declarations
extern gss_OID_desc krb5_oid_desc;
extern gss_OID krb5_oid;

struct PrincipalInfo {
    std::string principal;
    OM_uint32 lifetime;
};

/**
 * The subclass of Credentials that contains the AuthNKrb specific
 * identification object
 */
struct KrbCredentials final : Credentials {
    // gss-api token for default Kerberos Ticket Granting Ticket
    // (TGT) on the system, stored as a byte array
    std::vector<uint8_t> token{};
};

class AuthNKrb final : public Auth {
   public:
    // Constructor.  Adds in kerberos specific fields (ticket) to the verifier
    // field of the ccr
    explicit AuthNKrb()
        : Auth(PVXS_KRB_AUTH_TYPE,
               {
                   Member(TypeCode::Int8A, "token"),  // Add a `token` field to the CCR
                   Member(TypeCode::Int8A, "mic")     // Add a `mic` field to the CCR
               }),
          krb5_oid(&krb5_oid_desc),  // Initialize the Kerberos OID to the constant value for the Kerberos protocol
          krb5_oid_ptr(&krb5_oid)    // Initialize the pointer to the Kerberos OID
    {
        // Initialize the Kerberos OID to the constant value for the Kerberos protocol
        krb5_oid_desc.length = 9;
        krb5_oid_desc.elements = const_cast<char *>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
    }

    ~AuthNKrb() override = default;

    /**
     * Get the realm from the kerberos ticket
     *
     * This function gets the realm from the kerberos ticket.  It is used
     * only when the realm is not set in the configuration.
     *
     * @return the realm from the kerberos ticket
     */
    static std::string getRealm();

    // Kerberos OID for the Kerberos protocol
    gss_OID krb5_oid;
    // Pointer to the Kerberos OID
    gss_OID *krb5_oid_ptr;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config, bool for_client) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                 const std::shared_ptr<KeyPair> &key_pair,
                                                                 const uint16_t &usage,
                                                                 const ConfigAuthN &config) const override;

    bool verify(Value ccr) const override;

    void fromEnv(std::unique_ptr<client::Config> &config) override { config.reset(new ConfigKrb(ConfigKrb::fromEnv())); }

    /**
     * Apply the kerberos specific configuration to the authenticator.
     *
     * This function applies the kerberos specific configuration to the authenticator.
     * It sets the kerberos validator service name and the kerberos realm for use in the authenticator client,
     * and the realm and the kerberos keytab file for use in the PVACMS kerberos verifier.
     *
     * @param config the configuration for the authenticator
     */
    void configure(const client::Config &config) override {
        auto &config_krb = dynamic_cast<const ConfigKrb &>(config);
        krb_validator_service_name = SB() << config_krb.krb_validator << PVXS_KRB_DEFAULT_VALIDATOR_CLUSTER_PART << config_krb.krb_realm;
        krb_realm = config_krb.krb_realm;
        krb_keytab_file = config_krb.krb_keytab;
    }

    /**
     * Update the definitions with the kerberos authenticator specific definitions.
     *
     * This function is called from PVACMS to update the definitions with the kerberos authenticator specific definitions.
     * It updates the definitions with the kerberos keytab file, the kerberos client keytab file,
     * the kerberos validator service name, and the kerberos realm.
     *
     * @param defs the definitions to update with the kerberos authenticator specific definitions
     */
    void updateDefs(client::Config::defs_t &defs) const override {
        defs["KRB5_KTNAME"] = krb_keytab_file;
        defs["KRB5_CLIENT_KTNAME"] = krb_keytab_file;
        defs["EPICS_AUTH_KRB_VALIDATOR_SERVICE"] = krb_validator_service_name;
        defs["EPICS_AUTH_KRB_REALM"] = krb_realm;
    }

    /**
     * Get the heading for the Kerberos options section of the help text for PVACMS when compiled with the kerberos authenticator.
     *
     * This function returns the heading for the Kerberos options section of the help text for PVACMS when compiled with the kerberos authenticator.
     *
     * @return the heading for the Kerberos options section of the help text for PVACMS when compiled with the kerberos authenticator
     */
    std::string getOptionsPlaceholderText() override { return " [kerberos options]"; }

    /**
     * Get the help text for the Kerberos options section of the help text for PVACMS when compiled with the kerberos authenticator.
     *
     * This function returns the help text for the Kerberos options section of the help text for PVACMS when compiled with the kerberos authenticator.
     *
     * @return the help text for the Kerberos options section of the help text for PVACMS when compiled with the kerberos authenticator
     */
    std::string getOptionsHelpText() override {
        return "\n"
               "kerberos options\n"
               "        --krb-keytab <keytab file>           kerberos keytab file for non-interactive login`\n"
               "        --krb-realm <realm>                  kerberos realm.  Default `EPICS.ORG`\n"
               "        --krb-validator <validator-service>  pvacms kerberos service name.  Default `pvacms`\n";
    }

    /**
     * @brief Add the kerberos specific parameters to the command line application for the PVACMS executable.
     *
     * This function adds the kerberos specific parameters to the command line application for the PVACMS executable.
     * The parameters are added to the commandline application as options so that they will
     * be parsed from the command line when the PVACMS executable is run.
     *
     * The parameter values retrieved from the command line are stored in an authenticator specific
     * config object in the `authn_config_map` map keyed on the authenticator type.  In this case
     * the authenticator specific config object is a ConfigKrb object.
     *
     * @param app the CLI11 application object to add the parameters to
     * @param authn_config_map the map of authenticator configuration parameters keyed on the authenticator type
     */
    void addOptions(CLI::App &app, std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map) override {
        auto &config = authn_config_map.at(PVXS_KRB_AUTH_TYPE);
        auto config_krb = dynamic_cast<const ConfigKrb &>(*config);
        app.add_option("--krb-keytab", config_krb.krb_keytab, "kerberos keytab file.");
        app.add_option("--krb-realm", config_krb.krb_realm, "kerberos realm.");
        app.add_option("--krb-validator", config_krb.krb_validator, "pvacms kerberos validator service name");
    }

   private:
    gss_OID_desc krb5_oid_desc{};
    std::string krb_validator_service_name{PVXS_KRB_DEFAULT_VALIDATOR_SERVICE_NAME};
    std::string krb_keytab_file{};
    std::string krb_realm{PVXS_KRB_DEFAULT_VALIDATOR_REALM };

    static std::string gssErrorDescription(OM_uint32 major_status, OM_uint32 minor_status);

    static void gssNameFromString(const std::string &name, gss_name_t &target_name);
    static PrincipalInfo getPrincipalInfo();
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_KERB_H
