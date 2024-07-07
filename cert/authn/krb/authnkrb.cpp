/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnkrb.h"

#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#include <pvxs/config.h>

#include "auth.h"
#include "authregistry.h"
#include "security.h"

namespace pvxs {
namespace security {

DEFINE_LOGGER(auths, "pvxs.security.auth.krb");

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

std::shared_ptr<Credentials> KrbAuth::getCredentials(const impl::ConfigCommon &config) const {
    log_debug_printf(auths,
                     "\n******************************************\nKerberos "
                     "Authenticator: %s\n",
                     "Begin acquisition");

    // Create KrbCredentials shared_ptr
    auto kerberos_credentials = std::make_shared<KrbCredentials>();

    return kerberos_credentials;
}

/**
 * @brief Creates a signed certificate for the Kerberos authentication type.
 *
 * This function generates a signed certificate using the provided credentials
 * and key pair. The certificate creation request (CSR) will be passed through
 * the custom requestor to PVACMS (the CA) to sign the included X.509
 * certificate for client or server authentication, depending on the usage.
 *
 * @param credentials The credentials used to create the signed certificate.
 * @param key_pair The key pair containing the public key used for signing.
 * @param usage the desired certificate usage bitmask
 * @return The certificate creation request.
 */
std::shared_ptr<CertCreationRequest> KrbAuth::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                        const std::shared_ptr<KeyPair> &key_pair,
                                                                        const uint16_t &usage) const {
    auto krb_credentials = castAs<KrbCredentials, Credentials>(credentials);

    // Call subclass to set up common CSR fields
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);

    OM_uint32 major_status, minor_status;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;

    // We use GSS_C_NO_CREDENTIAL to specify that we want to use the default
    // credentials Usually, the default credential is obtained from the system's
    // Kerberos TGT

    // Similarly, for the target name, it will be of the format service@hostname
    gss_name_t target_name;
    // TODO remove server hardcoding.  Determine target PVACMS server by config
    gssNameFromString("PVACMS@SLAC.STANFORD.EDU", target_name);

    // Initialize the context from a kerberos ticket
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    major_status = gss_init_sec_context(&minor_status, GSS_C_NO_CREDENTIAL, &context, target_name,
                                        krb5_oid,  // Kerberos 5 credentials only
                                        GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG, 0, GSS_C_NO_CHANNEL_BINDINGS,
                                        GSS_C_NO_BUFFER, /* No input token provided because we haven't got
                                                        anything from other side, and we won't use it
                                                        anyway*/
                                        NULL, &output_token, NULL, NULL);

    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Failed to initialize kerberos security context: "
                                      << gssErrorDescription(major_status, minor_status));
    }

    // Add token to credentials
    krb_credentials->token = std::vector<uint8_t>(static_cast<uint8_t *>(output_token.value),
                                                  static_cast<uint8_t *>(output_token.value) + output_token.length);

    // Clean up
    gss_delete_sec_context(&minor_status, &context, &output_token);

    // KRB specific fields
    shared_array<const uint8_t> token_bytes(krb_credentials->token.begin(), krb_credentials->token.end());
    cert_creation_request->credentials = krb_credentials;
    cert_creation_request->ccr["verifier.token"] = token_bytes;

    return cert_creation_request;
}

/**
 * @brief Verify the Kerberos authentication against the provided CCR.
 *
 * This function verifies the Kerberos authentication by comparing the provided
 * CCR with the Kerberos authentication information provided in the GSS-API
 * verifier.token.
 *
 * @param ccr The CCR which includes the information required in the certificate
 * as well as the verifier.token created in the client capturing the kerberos
 * ticket and wrapping it as a GSS-API token
 * @param compareFunc We don't use the side-band verification with kerberos so
 * we won't use this callback.
 * @return True if the kerberos credentials extracted from the token and
 * validated by the KDC match those in the CCR, false otherwise.
 */
bool KrbAuth::verify(const Value ccr, std::function<bool(const std::string &, const std::string &)>) const {
    // Verify that the token in the ccr is created from a ticket generated by
    // the same KDC I'm configured in as a service

    // Extract and decode client token from ccr
    auto token_bytes = ccr["verifier.token"].as<shared_array<const uint8_t>>();
    std::vector<uint8_t> vec_bytes(token_bytes.begin(), token_bytes.end());

    gss_buffer_desc client_token;
    client_token.length = vec_bytes.size();

    std::unique_ptr<uint8_t[]> buffer(new uint8_t[client_token.length]);
    client_token.value = buffer.get();
    std::copy(vec_bytes.begin(), vec_bytes.end(), static_cast<uint8_t *>(client_token.value));

    // Get ready for accepting the client's token
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc server_token;
    OM_uint32 major_status;
    OM_uint32 minor_status;

    // The server accepts the context using the client's token
    major_status = gss_accept_sec_context(&minor_status, &context,
                                          GSS_C_NO_CREDENTIAL,  // use the default credential
                                          &client_token, GSS_C_NO_CHANNEL_BINDINGS,
                                          NULL,          // don't need the name of client
                                          krb5_oid_ptr,  // Kerberos 5 credentials only
                                          &server_token,
                                          NULL,  // don't care about ret_flags
                                          NULL,  // ignore time_rec
                                          NULL   // ignore delegated_cred_handle
    );

    // Note: If the context is not fully established, major_status will be
    // GSS_S_CONTINUE_NEEDED, and we would need to send the server_token back to
    // the client and run this process again until it returns GSS_S_COMPLETE.
    // However, as we are only interested in kerberos tickets and don't care
    // about mutual authentication here, we won't ever send anything back and
    // are only interested in finding out if the context can be created with the
    // client token, and then what the context can tell us about the peer

    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Verify Credentials: Failed to validate kerberos token: "
                                      << gssErrorDescription(major_status, minor_status));
    }

    // Now get the peer credentials information from the context

    // Retrieve the credentials
    gss_name_t peer_name;
    OM_uint32 peer_lifetime;
    gss_OID_set peer_mechanisms;
    int peer_credential_usage;
    time_t now = time(NULL);

    major_status =
        gss_inquire_cred(&minor_status, nullptr, &peer_name, &peer_lifetime, &peer_credential_usage, &peer_mechanisms);
    throw std::runtime_error(SB() << "Verify Credentials: Failed to inquire credentials: "
                                  << gssErrorDescription(major_status, minor_status));

    // Get the principal name
    gss_buffer_desc peer_name_buffer;
    major_status = gss_display_name(&minor_status, peer_name, &peer_name_buffer, NULL);
    if (GSS_ERROR(major_status)) {
        gss_release_name(&minor_status, &peer_name);
        throw std::runtime_error(SB() << "Verify Credentials: Failed to get principal name: "
                                      << gssErrorDescription(major_status, minor_status));
    }

    std::string peer_principal(static_cast<char *>(peer_name_buffer.value), peer_name_buffer.length);
    gss_release_buffer(&minor_status, &peer_name_buffer);
    gss_release_name(&minor_status, &peer_name);

    // Check if the credentials are for Kerberos
    if (peer_mechanisms->elements != krb5_oid) {
        throw std::runtime_error(SB() << "Verify Credentials: Client credentials are not for Kerberos "
                                         "mechanism: "
                                      << gssErrorDescription(major_status, minor_status));
    }

    // Now, 'principal' contains the principal name, 'lifetime' contains the
    // remaining lifetime of the credentials in seconds, and 'expiration'
    // contains the ticket expiration time

    // Verify the peer credentials against ccr fields
    //   ccr["name"] == peer_principal(before @ sign)
    //   ccr["organization"] == peer_principal(after @ sign)
    //   ccr["organization_unit"] == blank
    //   ccr["country"] == blank
    //   ccr["type"] == "krb"
    //   ccr["not_before"] < now+peer_lifetime
    //   ccr["not_after"] <= now+peer_lifetime

    // Split out name and organization if the principal has an at sign
    std::size_t found;
    auto peer_principal_name(ccr["name"].as<std::string>());
    std::string peer_principal_organization;
    if ((found = peer_principal_name.find('@')) != std::string::npos) {
        peer_principal_organization = peer_principal_name.substr(found + 1);
        peer_principal_name.resize(found);
    }
    // Now the tests
    if (peer_principal_name.compare(ccr["name"].as<std::string>()) != 0) {
        throw std::runtime_error(SB() << "Verify Credentials: Kerberos name does not match name in CCR");
    }
    if (peer_principal_organization.compare(ccr["organization"].as<std::string>()) != 0) {
        throw std::runtime_error(SB() << "Verify Credentials: Kerberos organization "
                                         "does not match name in CCR");
    }
    if (!ccr["organization_unit"].as<std::string>().empty()) {
        throw std::runtime_error(SB() << "Verify Credentials: Organization Unit in CCR not blank");
    }
    if (!ccr["country"].as<std::string>().empty()) {
        throw std::runtime_error(SB() << "Verify Credentials: Country in CCR not blank");
    }
    if (ccr["type"].as<std::string>().compare(PVXS_KRB_AUTH_TYPE) != 0) {
        throw std::runtime_error(SB() << "Verify Credentials: Type of CCR not Kerberos");
    }
    if (ccr["not_before"].as<uint32_t>() >= now + peer_lifetime) {
        throw std::runtime_error(SB() << "Verify Credentials: CCR not_before after "
                                         "end of kerberos ticket lifetime");
    }

    if (ccr["not_after"].as<uint32_t>() > now + peer_lifetime) {
        throw std::runtime_error(SB() << "Verify Credentials: CCR not_after after "
                                         "end of kerberos ticket lifetime");
    }

    return true;
}

void KrbAuth::gssNameFromString(const std::string &name, gss_name_t &target_name) const {
    OM_uint32 major_status, minor_status;
    gss_buffer_desc name_buf;
    gss_OID name_type = GSS_C_NT_HOSTBASED_SERVICE;

    /* initialize the name buffer */
    name_buf.value = (void *)name.c_str();
    name_buf.length = name.size() + 1;

    /* import the name */
    major_status = gss_import_name(&minor_status, &name_buf, name_type, &target_name);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Kerberos can't create name from \"" << name
                                      << "\" : " << gssErrorDescription(major_status, minor_status));
    }
}

std::string KrbAuth::gssErrorDescription(OM_uint32 major_status, OM_uint32 minor_status) const {
    OM_uint32 msg_ctx;
    OM_uint32 minor;
    gss_buffer_desc status_string;
    auto error_description = SB();
    char context[GSS_STATUS_BUFFER_LEN] = "";

    msg_ctx = 0;
    while (!gss_display_status(&minor, major_status, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &status_string)) {
        snprintf(context, GSS_STATUS_BUFFER_LEN, "%.*s\n", (int)status_string.length, (char *)status_string.value);
        error_description << context;
        gss_release_buffer(&minor, &status_string);
    }

    msg_ctx = 0;
    while (!gss_display_status(&minor, minor_status, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string)) {
        snprintf(context, GSS_STATUS_BUFFER_LEN, "%.*s\n", (int)status_string.length, (char *)status_string.value);
        error_description << context;
        gss_release_buffer(&minor, &status_string);
    }

    return error_description.str();
}

#if defined(__APPLE__) && defined(__clang__)
#pragma GCC diagnostic pop
#endif

}  // namespace security
}  // namespace pvxs
