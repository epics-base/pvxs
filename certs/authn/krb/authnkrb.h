/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_KERB_H
#define PVXS_AUTH_KERB_H

#include <configkrb.h>
#include <functional>
#include <string>

#ifdef __APPLE__
#include <GSS/gssapi_krb5.h>
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#include <pvxs/data.h>

#include "auth.h"
#include "security.h"

#define PVXS_KRB_AUTH_TYPE "krb"
#define GSS_STATUS_BUFFER_LEN 1024

namespace pvxs {
namespace certs {

// Declarations
extern gss_OID_desc krb5_oid_desc;
extern gss_OID krb5_oid;

/**
 * The subclass of Credentials that contains the AuthNKrb specific
 * identification object
 */
struct KrbCredentials : Credentials {
    // gss-api token for default Kerberos Ticket Granting Ticket
    // (TGT) on the system, stored as a byte array
    std::vector<uint8_t> token{};
};

class AuthNKrb : public Auth {
   public:

    // Constructor.  Adds in kerberos specific fields (ticket) to the verifier
    // field of the ccr
    explicit AuthNKrb()
        : Auth(PVXS_KRB_AUTH_TYPE, {Member(TypeCode::Int8A, "token"), Member(TypeCode::Int8A, "mic")}),
          krb5_oid(&krb5_oid_desc),
          krb5_oid_ptr(&krb5_oid) {
        krb5_oid_desc.length = 9;
        krb5_oid_desc.elements = const_cast<char*>("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
    };

    ~AuthNKrb() override = default;
    void configure(const ConfigKrb &config) {krb_validator_service_name = config.krb_validator_service + "/cluster@" + config.krb_realm;}

    gss_OID krb5_oid;
    gss_OID *krb5_oid_ptr;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                   const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify( Value ccr, std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const override;

    void fromEnv(std::unique_ptr<client::Config> &config) override {
        config.reset(new ConfigKrb(ConfigKrb::fromEnv()));
    };

    void configure(const client::Config &config) override {
        auto &config_krb = dynamic_cast<const ConfigKrb&>(config);
        krb_validator_service_name = SB() << config_krb.krb_validator_service <<  "/cluster@" << config_krb.krb_realm;
        krb_realm = config_krb.krb_realm;
        krb_keytab_file = config_krb.krb_keytab;
    };

    std::string getOptionsText() override {return " [kerberos options]";}
    std::string getParameterHelpText() override {return  "\n"
                                              "kerberos options\n"
                                              "        --krb-realm <realm>                  kerberos realm.  Default `EPICS.ORG`\n"
                                              "        --krb-service <service>              pvacms kerberos service name.  Default `pvacms`\n";}
    void addParameters(CLI::App & app, const std::map<const std::string, std::unique_ptr<client::Config>> & authn_config_map) override {
        auto &config = authn_config_map.at(PVXS_KRB_AUTH_TYPE);
        auto config_krb = dynamic_cast<const ConfigKrb &>(*config);
        app.add_option("--krb-realm", config_krb.krb_realm, "kerberos realm.");
        app.add_option("--krb-service", config_krb.krb_validator_service, "pvacms kerberos service name");
    }

    private:
    gss_OID_desc krb5_oid_desc{};
    std::string krb_validator_service_name{"pvacms/cluster@EPICS.ORG"};
    std::string krb_keytab_file{};
    std::string krb_realm{"EPICS.ORG"};

    static std::string gssErrorDescription(OM_uint32 major_status, OM_uint32 minor_status);

    static void gssNameFromString(const std::string &name, gss_name_t &target_name);
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_KERB_H
