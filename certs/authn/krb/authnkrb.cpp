/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnkrb.h"

#include <cstring>
#include <stdexcept>
#include <string>

#ifdef __APPLE__
#include <GSS/gssapi.h>
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif


#include <CLI/CLI.hpp>

#include <pvxs/config.h>

#include "authregistry.h"
#include "certfilefactory.h"
#include "configkrb.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"
#include "certstatusfactory.h"

DEFINE_LOGGER(auth, "pvxs.auth.krb");

namespace pvxs {
namespace certs {

struct AuthNKrbRegistrar {
    AuthNKrbRegistrar() { // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_KRB_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNKrb()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_krb_registrar;

std::shared_ptr<Credentials> AuthNKrb::getCredentials(const client::Config &) const {
    log_debug_printf(auth,
                     "\n******************************************\n"
                     "Kerberos Authenticator: %s\n",
                     "Begin acquisition");

    // Create KrbCredentials shared_ptr
    auto kerberos_credentials = std::make_shared<KrbCredentials>();

    // Initialize GSSAPI structures
    OM_uint32 minor_status, major_status;
    gss_name_t name = GSS_C_NO_NAME;
    gss_buffer_desc name_buffer = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    OM_uint32 lifetime;


    // Acquire the default credential handle
    log_debug_printf(auth, "gss_acquire_cred: GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT%s", "\n");
    major_status = gss_acquire_cred(&minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred_handle, nullptr, nullptr);
    if (major_status != GSS_S_COMPLETE) throw std::runtime_error(SB() << "getCredentials: Failed to acquire credentials: " << gssErrorDescription(major_status, minor_status));


    // Get the principal name associated with the credential
    log_debug_printf(auth, "gss_inquire_cred%s", "\n");
    major_status = gss_inquire_cred(&minor_status, cred_handle, &name, &lifetime, nullptr, nullptr);
    if (major_status != GSS_S_COMPLETE) {
        gss_release_cred(&minor_status, &cred_handle);
        throw std::runtime_error(SB() << "getCredentials: Failed to inquire credentials: " << gssErrorDescription(major_status, minor_status));
    }


    // Convert the principal name to a string
    log_debug_printf(auth, "gss_display_name%s", "\n");
    major_status = gss_display_name(&minor_status, name, &name_buffer, nullptr);
    if (major_status != GSS_S_COMPLETE) {
        gss_release_name(&minor_status, &name);
        gss_release_cred(&minor_status, &cred_handle);
        throw std::runtime_error(SB() << "getCredentials: Failed to get principal name: " << gssErrorDescription(major_status, minor_status));
    }

    std::string principal_name(static_cast<char*>(name_buffer.value), name_buffer.length);
    gss_release_buffer(&minor_status, &name_buffer);
    gss_release_name(&minor_status, &name);

    log_debug_printf(auth, "Set Credentials%s", "\n");
    // Split the principal name into name and organization
    size_t at_pos = principal_name.find('@');
    if (at_pos == std::string::npos) {
        gss_release_cred(&minor_status, &cred_handle);
        throw std::runtime_error(SB() << "getCredentials: Invalid principal name format: " << principal_name.c_str());
    }

    kerberos_credentials->name = principal_name.substr(0, at_pos);
    kerberos_credentials->organization = principal_name.substr(at_pos + 1);
    kerberos_credentials->organization_unit = {};
    kerberos_credentials->country = {};

    // Get the current time and the ticket's expiration time
    time_t now = time(nullptr);
    kerberos_credentials->not_before = now;
    kerberos_credentials->not_after = now + lifetime;
    log_debug_printf(auth, "\nName: %s, \nOrg: %s, \nnot_before: %lu, \nnot_after: %lu\n", kerberos_credentials->name.c_str(), kerberos_credentials->organization.c_str(), kerberos_credentials->not_before, kerberos_credentials->not_after);

    // Release the credential handle
    gss_release_cred(&minor_status, &cred_handle);

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
std::shared_ptr<CertCreationRequest> AuthNKrb::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                        const std::shared_ptr<KeyPair> &key_pair,
                                                                        const uint16_t &usage) const {
    auto krb_credentials = castAs<KrbCredentials, Credentials>(credentials);

    // Call subclass to set up common CSR fields
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);
    log_debug_printf(auth, "CCR: created%s", "\n");

    OM_uint32 minor_status;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;

    // We use GSS_C_NO_CREDENTIAL to specify that we want to use the default
    // credentials Usually, the default credential is obtained from the system's
    // Kerberos TGT

    // Similarly, for the target name, it will be of the format service@hostname (default: pvacms/cluster@EPICS.ORG)
    log_debug_printf(auth, "Getting Target Name: %s\n", krb_validator_service_name.c_str());
    gss_name_t target_name;
    gssNameFromString(krb_validator_service_name, target_name);

    // Initialize the context from a kerberos ticket
    log_debug_printf(auth, "gss_init_sec_context%s", "\n");
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    OM_uint32 major_status = gss_init_sec_context(
        &minor_status,
        GSS_C_NO_CREDENTIAL,
        &context,
        target_name,
        krb5_oid,
        0,                         // minimal flags
        GSS_C_INDEFINITE,          // use indefinite lifetime
        GSS_C_NO_CHANNEL_BINDINGS,
        GSS_C_NO_BUFFER,
        nullptr,
        &output_token,
        nullptr,
        nullptr);

    /*
    OM_uint32 major_status = gss_init_sec_context(&minor_status, GSS_C_NO_CREDENTIAL, &context, target_name, krb5_oid,
                                                  0, // no flags or only the minimal flags required
                                                  0, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, nullptr, &output_token,
                                                  nullptr, nullptr);

    */

    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Failed to initialize kerberos security context: "
                                      << gssErrorDescription(major_status, minor_status));
    }

    // Add token to credentials
    log_debug_printf(auth, "Got Security Token%s", "\n");
    krb_credentials->token = std::vector<uint8_t>(static_cast<uint8_t *>(output_token.value),
                                                  static_cast<uint8_t *>(output_token.value) + output_token.length);

    // Clean up
    log_debug_printf(auth, "Deleting Security Context%s", "\n");
    gss_delete_sec_context(&minor_status, &context, &output_token);

    // KRB specific fields
    log_debug_printf(auth, "Setting token in CCR%s", "\n");
    shared_array<const uint8_t> token_bytes(krb_credentials->token.begin(), krb_credentials->token.end());
    cert_creation_request->credentials = krb_credentials;
    cert_creation_request->ccr["verifier.token"] = token_bytes;

    return cert_creation_request;
}

void AuthNKrb::gssNameFromString(const std::string &name, gss_name_t &target_name) {
    OM_uint32 minor_status;
    gss_buffer_desc name_buf;
    gss_OID name_type = GSS_KRB5_NT_PRINCIPAL_NAME;

    /* initialize the name buffer */
    name_buf.value = const_cast<char *>(name.c_str());
    name_buf.length = name.size() + 1;

    /* import the name */
    OM_uint32 major_status = gss_import_name(&minor_status, &name_buf, name_type, &target_name);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Kerberos can't create name from \"" << name
                                      << "\" : " << gssErrorDescription(major_status, minor_status));
    }
}

std::string AuthNKrb::gssErrorDescription(OM_uint32 major_status, OM_uint32 minor_status) {
    OM_uint32 msg_ctx;
    OM_uint32 minor;
    gss_buffer_desc status_string;
    auto error_description = SB();
    char context[GSS_STATUS_BUFFER_LEN] = "";

    msg_ctx = 0;
    while (!gss_display_status(&minor, major_status, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &status_string)) {
        snprintf(context, GSS_STATUS_BUFFER_LEN, "%.*s\n", static_cast<int>(status_string.length), static_cast<char *>(status_string.value));
        error_description << context;
        gss_release_buffer(&minor, &status_string);
    }

    msg_ctx = 0;
    while (!gss_display_status(&minor, minor_status, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string)) {
        snprintf(context, GSS_STATUS_BUFFER_LEN, "%.*s\n", static_cast<int>(status_string.length), static_cast<char *>(status_string.value));
        error_description << context;
        gss_release_buffer(&minor, &status_string);
    }

    return error_description.str();
}
/**
 * @brief Verify the Kerberos authentication against the provided CCR.
 *
 * This function verifies the Kerberos authentication by comparing the provided
 * CCR with the Kerberos authentication information provided in the GSS-API
 * verifier.token.
 *
 * @param ccr The CCR which includes the information required in the certificate
 * as well as the `verifier.token` created in the client capturing the kerberos
 * ticket and wrapping it as a GSS-API token
 * @return True if the kerberos credentials extracted from the token and
 * validated by the KDC match those in the CCR, false otherwise.
 */
bool AuthNKrb::verify(const Value ccr, std::function<bool(const std::string &, const std::string &)>) const {
    log_debug_printf(auth, "Verifying Kerberos CCR request%s", "\n");

    log_debug_printf(auth, "Checking Keytab is configured: %s\n", krb_keytab_file.c_str());
    if (krb_keytab_file.empty()) {
        log_debug_printf(auth, "Keytab is NOT configured - ***exiting***: %s\n", krb_keytab_file.c_str());
        throw std::runtime_error("KRB5_KTNAME environment variable needs to be set to point to the location of the keytab.  e.g. ~/.config/pva/1.3/pvacms.keytab");
    }

    // acquire the correct server credentials
    log_debug_printf(auth, "Server name into name buffer: %s\n", krb_validator_service_name.c_str());
    gss_name_t serverName = GSS_C_NO_NAME;
    gss_buffer_desc nameBuf;
    nameBuf.value = (void*)krb_validator_service_name.c_str(); // e.g. "pvacms/cluster@EPICS.ORG"
    nameBuf.length = krb_validator_service_name.size();

    OM_uint32 minor_status, major_status;
    major_status = gss_import_name(&minor_status, &nameBuf,
                                   GSS_KRB5_NT_PRINCIPAL_NAME, &serverName);
    if (GSS_ERROR(major_status)) {
        log_debug_printf(auth, "Error importing name: %s\n", krb_validator_service_name.c_str());
        throw std::runtime_error("Failed to import server name");
    }

    log_debug_printf(auth, "Acquire Server Credentials for PVACMS service: %s\n", krb_validator_service_name.c_str());
    gss_cred_id_t serverCred = GSS_C_NO_CREDENTIAL;
    major_status = gss_acquire_cred(&minor_status, serverName, GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET, GSS_C_ACCEPT, &serverCred,
                                    nullptr, nullptr);
    if (GSS_ERROR(major_status)) {
        log_debug_printf(auth, "Failed to acquire server credentials: %s\n", krb_validator_service_name.c_str());
        throw std::runtime_error("Failed to acquire server credentials");
    }


    // Extract and decode client token from ccr
    log_debug_printf(auth, "Get GSS-API Token from CCR: %s", "\n");
    auto token_bytes = ccr["verifier.token"].as<shared_array<const uint8_t>>();
    std::vector<uint8_t> vec_bytes(token_bytes.begin(), token_bytes.end());

    log_debug_printf(auth, "Convert token to gss_buffer_desc: %s", "\n");
    gss_buffer_desc client_token;
    client_token.length = vec_bytes.size();

    std::unique_ptr<uint8_t[]> buffer(new uint8_t[client_token.length]);
    client_token.value = buffer.get();
    std::copy(vec_bytes.begin(), vec_bytes.end(), static_cast<uint8_t *>(client_token.value));

    log_debug_printf(auth, "Accept this client token: %s", "\n");
    // Get ready for accepting the client's token
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc server_token;

    // The server accepts the context using the client's token
    major_status = gss_accept_sec_context(&minor_status, &context, serverCred,
                                      &client_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      nullptr, krb5_oid_ptr,
                                      &server_token, nullptr, nullptr, nullptr);

    if (GSS_ERROR(major_status)) {
        log_debug_printf(auth, "Failed to accept client token: %s\n", gssErrorDescription(major_status, minor_status).c_str());
        throw std::runtime_error(SB() << "Verify Credentials: Failed to validate kerberos token: "
            << gssErrorDescription(major_status, minor_status));
    }

    // Now get the peer credentials information from the context

    // Retrieve the credentials
    OM_uint32 peer_lifetime = 0;
    time_t now = time(nullptr);

    gss_name_t initiator_name = GSS_C_NO_NAME;
    major_status = gss_inquire_context(&minor_status, context,
                                       &initiator_name,
                                       nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error("Failed to inquire context for initiator name");
    }

    // Optionally, if the context supports it:
    major_status = gss_inquire_context(&minor_status, context,
                                       nullptr, nullptr, &peer_lifetime,
                                       nullptr, nullptr, nullptr, nullptr);
    if (GSS_ERROR(major_status)) {
        // TODO handle error or decide on a fallback
        peer_lifetime = 24*60*60;  // One day TODO Change this hardcoded monstrosity!!
    }

    // Get the peer principal
    log_debug_printf(auth, "Get peer name: %s", "\n");
    gss_buffer_desc peer_name_buffer;
    major_status = gss_display_name(&minor_status, initiator_name, &peer_name_buffer, nullptr);
    if (GSS_ERROR(major_status)) {
        gss_release_name(&minor_status, &initiator_name);
        throw std::runtime_error(SB() << "Verify Credentials: Failed to get principal name: "
            << gssErrorDescription(major_status, minor_status));
    }

    std::string peer_principal(static_cast<char *>(peer_name_buffer.value), peer_name_buffer.length);
    gss_release_buffer(&minor_status, &peer_name_buffer);
    gss_release_name(&minor_status, &initiator_name);


    // Now, 'principal' contains the principal name, 'peer_lifetime' contains the
    // remaining lifetime of the credentials in seconds, and 'expiration'
    // contains the ticket expiration time

    // Split out name and organization if the principal has an at sign
    std::size_t found;
    auto peer_principal_name(ccr["name"].as<std::string>());
    std::string peer_principal_organization;
    if ((found = peer_principal_name.find('@')) != std::string::npos) {
        peer_principal_organization = peer_principal_name.substr(found + 1);
        peer_principal_name.resize(found);
    }


    log_debug_printf(auth, "Check against CCR: %s", "\n");
    // Now the tests
    // Verify the peer credentials against ccr fields
    //   ccr["name"] == peer_principal(before @ sign)
    //   ccr["organization"] == peer_principal(after @ sign)
    //   ccr["organization_unit"] == blank
    //   ccr["country"] == blank
    //   ccr["type"] == "krb"
    //   ccr["not_before"] < now+peer_lifetime
    //   ccr["not_after"] <= now+peer_lifetime
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

}  // namespace security
}  // namespace pvxs
