/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_KERB_H
#define PVXS_AUTH_KERB_H

#include <functional>
#include <memory>
#include <string>

#include <gssapi/gssapi_krb5.h>

#include <pvxs/config.h>
#include <pvxs/data.h>
#include <pvxs/version.h>

#include "auth.h"
#include "authregistry.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_KRB_AUTH_TYPE "krb"
#define GSS_STATUS_BUFFER_LEN 1024

namespace pvxs {
namespace security {

// Declarations
extern gss_OID_desc krb5_oid_desc;
extern gss_OID krb5_oid;

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/**
 * The subclass of Credentials that contains the KrbAuth specific
 * identification object
 */
struct KrbCredentials : public Credentials {
    // gss-api token for default Kerberos Ticket Granting Ticket
    // (TGT) on the system, stored as a byte array
    std::vector<uint8_t> token;

    KrbCredentials() {}

    ~KrbCredentials() {}
};

/**
 * @class KrbAuth
 * @brief The KrbAuth class provides Kerberos authentication
 * functionality.
 *
 * This class is responsible for retrieving credentials for users that have been
 * authenticated against a Kerberos server. It inherits from the Auth
 * base class.
 *
 * In order to use the KrbAuth, it must be registered with the
 * CertFactory using the REGISTER_AUTHENTICATOR() macro.
 *
 * The KrbAuth class implements the getCredentials() and
 * createCertCreationRequest() methods. The getCredentials() method returns the
 * credentials used for authentication. The createCertCreationRequest() method
 * creates a kerberos specific certificate creation request using the provided
 * credentials.
 */
class KrbAuth : public Auth {
   public:
    REGISTER_AUTHENTICATOR();

    // Constructor.  Adds in kerberos specific fields (ticket) to the verifier
    // field of the ccr
    KrbAuth()
        : Auth(PVXS_KRB_AUTH_TYPE, {Member(TypeCode::Int8A, "token")}),
          krb5_oid(&krb5_oid_desc),
          krb5_oid_ptr(&krb5_oid) {
        krb5_oid_desc.length = 9;
        krb5_oid_desc.elements = (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
    };
    ~KrbAuth() override = default;

    gss_OID krb5_oid;
    gss_OID *krb5_oid_ptr;

    std::shared_ptr<Credentials> getCredentials(const impl::ConfigCommon &config) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                   const std::shared_ptr<KeyPair> &key_pair,
                                                                   const uint16_t &usage) const override;

    bool verify(
        const Value ccr,
        std::function<bool(const std::string &data, const std::string &signature)> signature_verifier) const override;

   private:
    gss_OID_desc krb5_oid_desc;

    std::string gssErrorDescription(OM_uint32 major_status, OM_uint32 minor_status) const;

    void gssNameFromString(const std::string &name, gss_name_t &target_name) const;
};

#if defined(__APPLE__) && defined(__clang__)
#pragma GCC diagnostic pop
#endif

}  // namespace security
}  // namespace pvxs

#endif  // PVXS_AUTH_KERB_H
