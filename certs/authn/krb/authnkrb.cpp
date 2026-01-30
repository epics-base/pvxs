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

#include "authregistry.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "utilpvt.h"

DEFINE_LOGGER(auth, "pvxs.auth.krb");

namespace pvxs {
namespace certs {

/**
 * @brief Registrar for the Kerberos authenticator
 *
 * This will register the Kerberos authenticator with the AuthRegistry.
 * This allows it to be found by PVACMS to authenticate kerberos certificate
 * creation requests (CCRs).
 */
struct AuthNKrbRegistrar {
    AuthNKrbRegistrar() {  // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_KRB_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNKrb()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_krb_registrar;

/**
 * @brief Get the credentials for the Kerberos authenticator
 *
 * This function gets the credentials for the Kerberos authenticator.
 *
 * It gets the principal name from the kerberos ticket and splits it into
 * a name and organization.  It then sets the validity times for the
 * credentials to the current time and the lifetime of the kerberos ticket.
 *
 * @param config kerberos authenticator config
 *
 * @return the credentials for the Kerberos authenticator
 */
std::shared_ptr<Credentials> AuthNKrb::getCredentials(const client::Config &config, bool) const {
    const auto krb_config = dynamic_cast<const ConfigKrb &>(config);
    log_debug_printf(auth,
                     "\n******************************************\n"
                     "Kerberos Authenticator: %s\n",
                     "Begin acquisition");

    auto kerberos_credentials = std::make_shared<KrbCredentials>();
    // Get principal info from the kerberos ticket
    const auto info = getPrincipalInfo();
    auto const &principal_name = info.principal;

    // Split the principal name into name and organization.
    const size_t at_pos = principal_name.find('@');
    if (at_pos == std::string::npos) throw std::runtime_error(SB() << "getCredentials: Invalid principal name format: " << principal_name);

    kerberos_credentials->name = principal_name.substr(0, at_pos);
    kerberos_credentials->organization = principal_name.substr(at_pos + 1);
    kerberos_credentials->organization_unit = {};
    kerberos_credentials->country = {};

    // Set validity times.
    const time_t now = time(nullptr);
    kerberos_credentials->not_before = now;
    if ( krb_config.cert_validity_mins <= 0 ) {
        kerberos_credentials->not_after = 0;
    } else {
        kerberos_credentials->not_after = now + krb_config.cert_validity_mins * 60;
    }

    log_debug_printf(auth, "\nName: %s, \nOrg: %s, \nnot_before: %lu, \nnot_after: %lu\n", kerberos_credentials->name.c_str(),
                     kerberos_credentials->organization.c_str(), kerberos_credentials->not_before, kerberos_credentials->not_after);

    return kerberos_credentials;
}

/**
 * @brief Get the realm from the kerberos ticket
 *
 * This function gets the realm from the kerberos ticket.  It is used
 * only when the realm is not set in the configuration.
 *
 * @return the realm from the kerberos ticket
 */
std::string AuthNKrb::getRealm() {
    log_debug_printf(auth,
                     "\n******************************************\n"
                     "Kerberos Authenticator: %s\n",
                     "Begin realm extraction");

    // Get principal info from the kerberos ticket
    const auto &info = getPrincipalInfo();
    auto const &principal_name = info.principal;

    const size_t at_pos = principal_name.find('@');
    if (at_pos == std::string::npos) throw std::runtime_error(SB() << "getRealm: Invalid principal name format: " << principal_name);

    return principal_name.substr(at_pos + 1);
}

/**
 * @brief Creates a certificate creation request for the Kerberos Authenticator.
 *
 * This function generates a certificate creation request (CCR) using the
 * provided credentials and key pair.
 *
 * It works by creating a security context from a Kerberos ticket and then
 * using the GSSAPI to obtain a security token (service ticket) from the KDC
 * to access the PVACMS service.
 *
 * It then generates a MIC over the public key and adds both the security
 * token and the MIC to the CCR.
 *
 * The MIC is used to ensure that the Public Key or security token has not
 * been tampered with.  The security token is used to authenticate the client
 * to the PVACMS service.
 *
 * When this CCR is verified and used to create a certificate, the certificate
 * will only be able to be used in conjunction with the private key that the
 * client holds.
 *
 * @param credentials The credentials to be used to create certificate creation request.
 * @param key_pair The key pair containing the public key used for the CCR.
 * @param usage the desired certificate usage bitmask: client, server, or ioc
 * @return The certificate creation request (CCR).
 */
std::shared_ptr<CertCreationRequest> AuthNKrb::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage,
const ConfigAuthN &config) const {
    const auto krb_credentials = castAs<KrbCredentials, Credentials>(credentials);

    // Call base class to set up the common CCR fields.
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage, config);
    log_debug_printf(auth, "CCR: created%s", "\n");

    OM_uint32 minor_status;
    auto context = GSS_C_NO_CONTEXT;

    // Get the target name (e.g. "pvacms/cluster@EPICS.ORG").
    log_debug_printf(auth, "Getting Target Name: %s\n", krb_validator_service_name.c_str());
    gss_name_t target_name;
    gssNameFromString(krb_validator_service_name, target_name);

    // Initialize a security context from a Kerberos ticket.
    log_debug_printf(auth, "Calling gss_init_sec_context%s", "\n");
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    OM_uint32 major_status = gss_init_sec_context(&minor_status,
                                                  GSS_C_NO_CREDENTIAL,  // Use default credentials (TGT)
                                                  &context, target_name, krb5_oid,
                                                  0,                 // Minimal flags
                                                  GSS_C_INDEFINITE,  // Indefinite lifetime
                                                  GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, nullptr, &output_token, nullptr, nullptr);

    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Failed to initialize Kerberos security context: " << gssErrorDescription(major_status, minor_status));
    }

    // Save the output token from the security context.
    log_debug_printf(auth, "Obtained Security Token%s", "\n");
    krb_credentials->token = std::vector<uint8_t>(static_cast<uint8_t *>(output_token.value), static_cast<uint8_t *>(output_token.value) + output_token.length);

    // MIC generation for message integrity
    log_debug_printf(auth, "Computing MIC over public key%s", "\n");
    const std::string public_key_str = key_pair->public_key;
    gss_buffer_desc data_buffer;
    data_buffer.value = reinterpret_cast<void *>(const_cast<char *>(public_key_str.c_str()));
    data_buffer.length = public_key_str.size();

    gss_buffer_desc mic_token = GSS_C_EMPTY_BUFFER;
    major_status = gss_get_mic(&minor_status, context, GSS_C_QOP_DEFAULT, &data_buffer, &mic_token);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Failed to obtain MIC: " << gssErrorDescription(major_status, minor_status));
    }

    // Convert the MIC token into shared_array.
    const shared_array<const uint8_t> mic_bytes(static_cast<const uint8_t *>(mic_token.value),
                                                static_cast<const uint8_t *>(mic_token.value) + mic_token.length);

    // Release the MIC token buffer.
    gss_release_buffer(&minor_status, &mic_token);

    // Clean up
    log_debug_printf(auth, "Deleting Security Context%s", "\n");
    gss_delete_sec_context(&minor_status, &context, &output_token);

    // Add both the security token and the MIC to the certificate creation request.
    log_debug_printf(auth, "Setting token and MIC in CCR%s", "\n");
    const shared_array<const uint8_t> token_bytes(krb_credentials->token.begin(), krb_credentials->token.end());
    cert_creation_request->credentials = krb_credentials;
    cert_creation_request->ccr["verifier.token"] = token_bytes;
    cert_creation_request->ccr["verifier.mic"] = mic_bytes;

    return cert_creation_request;
}

/**
 * @brief Convert a string to a GSS-API name.
 *
 * This function converts a string to a GSS-API name.
 *
 * @param name the string to convert
 * @param target_name the string converted as a GSS-API name
 */
void AuthNKrb::gssNameFromString(const std::string &name, gss_name_t &target_name) {
    OM_uint32 minor_status;
    gss_buffer_desc name_buf;
    // ReSharper disable once CppLocalVariableMayBeConst
    gss_const_OID name_type = GSS_KRB5_NT_PRINCIPAL_NAME;

    /* initialize the name buffer */
    name_buf.value = const_cast<char *>(name.c_str());
    name_buf.length = name.size() + 1;

    /* import the name */
    const OM_uint32 major_status = gss_import_name(&minor_status, &name_buf, const_cast<gss_OID>(name_type), &target_name);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "Kerberos can't create name from \"" << name << "\" : " << gssErrorDescription(major_status, minor_status));
    }
}

/**
 * @brief When a GSS-API error occurs this function retrieves the error description.
 *
 * This function retrieves the error description from the GSS-API of the last
 * error that occurred.
 *
 * @param major_status the major status code or the last error
 * @param minor_status the minor status code or the last error
 * @param only_first Only retrieve the first error code instead of the full string of errors.  Default false
 * @return the error description
 */
std::string AuthNKrb::gssErrorDescription(const OM_uint32 major_status, const OM_uint32 minor_status, bool only_first) {
    OM_uint32 msg_ctx;
    OM_uint32 minor;
    gss_buffer_desc status_string;
    auto error_description = SB();
    char context[GSS_STATUS_BUFFER_LEN] = "";

    msg_ctx = 0;
    do {
        if (gss_display_status(&minor, major_status, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &status_string) != GSS_S_COMPLETE) {
            throw std::logic_error(SB() << "GSS display status failed: ");
        }
        snprintf(context, GSS_STATUS_BUFFER_LEN, "%.*s\n", static_cast<int>(status_string.length), static_cast<char *>(status_string.value));
        error_description << context;
        gss_release_buffer(&minor, &status_string);
        if (only_first) return error_description.str();
    } while (msg_ctx);

    msg_ctx = 0;
    do {
        if (gss_display_status(&minor, minor_status, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &status_string) != GSS_S_COMPLETE) {
            throw std::logic_error(SB() << "GSS display status failed: ");
        }
        snprintf(context, GSS_STATUS_BUFFER_LEN, "%.*s\n", static_cast<int>(status_string.length), static_cast<char *>(status_string.value));
        error_description << context;
        gss_release_buffer(&minor, &status_string);
    } while (msg_ctx);

    return error_description.str();
}

/**
 * @brief Verify the provided CCR with the configured KDC.
 *
 * This function verifies the provided CCR against the configured KDC.
 *
 * It does this by acquiring the server credentials for the PVACMS service from
 * the configured keytab (`krb5_keytab_file`) that allows passwordless Kerberos
 * authentication.
 *
 * It then "accepts" the client's token to establish a security context.  If successful,
 * this means that the client's token is valid with the KDC and the client is therefore
 * authentic.
 *
 * It then compares the peer principal name from the context with the
 * peer principal name provided in the CCR.  If these do not match, then an
 * exception is thrown.
 *
 * It then verifies the MIC over the public key in the CCR.  If this fails,
 * then an exception is thrown.  It would mean that the public key has been
 * tampered with or the kerberos ticket has been compromised.
 *
 * Finally, the function checks that the CCR fields are valid.  This involves
 * verification that the not_before and not_after times are within the valid
 * lifetime of the kerberos ticket, and that the organisation unit and country
 * are empty strings.
 *
 * If all of the above checks pass, then the function returns true indicating
 * that the CCR is valid, and that certificate creation can proceed with the
 * information contained in the CCR.
 *
 * @param ccr The certificate creation request (CCR) to verify
 * @param authenticated_expiration_date The amount of time the authenticator says we can
 *                                      have.  Leave empty for defaults
 * @return True if the CCR is valid.
 * @throw std::runtime_error if the CCR is not valid
 */
bool AuthNKrb::verify(Value &ccr, time_t &authenticated_expiration_date) const {
    log_debug_printf(auth, "Verifying Kerberos CCR request%s", "\n");

    log_debug_printf(auth, "Checking Keytab is configured: %s\n", krb_keytab_file.c_str());
    if (krb_keytab_file.empty()) {
        log_debug_printf(auth, "Keytab is NOT configured - ***exiting***: %s\n", krb_keytab_file.c_str());
        throw std::runtime_error(
            "KRB5_KTNAME environment variable needs to be set to point to the location of the keytab.  e.g. ~/.config/pva/1.5/pvacms.keytab");
    }

    // Acquire the correct server credentials.
    log_debug_printf(auth, "Server name into name buffer: %s\n", krb_validator_service_name.c_str());
    gss_name_t serverName = GSS_C_NO_NAME;
    gss_buffer_desc nameBuf;
    nameBuf.value = (void *)krb_validator_service_name.c_str();  // e.g. "pvacms/cluster@EPICS.ORG"
    nameBuf.length = krb_validator_service_name.size();

    OM_uint32 minor_status, major_status;
    major_status = gss_import_name(&minor_status, &nameBuf, GSS_KRB5_NT_PRINCIPAL_NAME, &serverName);
    if (GSS_ERROR(major_status)) {
        log_debug_printf(auth, "Error importing name: %s\n", krb_validator_service_name.c_str());
        throw std::runtime_error("Failed to import server name");
    }

    log_debug_printf(auth, "Acquire Server Credentials for PVACMS service: %s\n", krb_validator_service_name.c_str());
    auto serverCred = GSS_C_NO_CREDENTIAL;
    major_status = gss_acquire_cred(&minor_status, serverName, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &serverCred, nullptr, nullptr);
    if (GSS_ERROR(major_status)) {
        log_debug_printf(auth, "Failed to acquire server credentials: %s\n", krb_validator_service_name.c_str());
        throw std::runtime_error("Failed to acquire server credentials");
    }

    // Extract and decode the client token from the CCR.
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
    // Accept the client's token to establish a security context.
    auto context = GSS_C_NO_CONTEXT;
    gss_buffer_desc server_token;

    major_status = gss_accept_sec_context(&minor_status, &context, serverCred, &client_token, GSS_C_NO_CHANNEL_BINDINGS, nullptr, krb5_oid_ptr, &server_token,
                                          nullptr, nullptr, nullptr);

    if (GSS_ERROR(major_status)) {
        log_debug_printf(auth, "Failed to accept client token: %s\n", gssErrorDescription(major_status, minor_status).c_str());
        throw std::runtime_error(SB() << "Verify Credentials: Failed to validate kerberos token: " << gssErrorDescription(major_status, minor_status));
    }

    // Retrieve peer credential information from the context.
    OM_uint32 peer_lifetime = 0;
    time_t now = time(nullptr);

    auto initiator_name = GSS_C_NO_NAME;
    major_status = gss_inquire_context(&minor_status, context, &initiator_name, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error("Failed to inquire context for initiator name");
    }

    major_status = gss_inquire_context(&minor_status, context, nullptr, nullptr, &peer_lifetime, nullptr, nullptr, nullptr, nullptr);
    if (GSS_ERROR(major_status)) {
        gss_release_name(&minor_status, &initiator_name);
        throw std::runtime_error(SB() << "Verify Credentials: Failed to get peer lifetime: " << gssErrorDescription(major_status, minor_status));
    }

    log_debug_printf(auth, "Get peer name: %s", "\n");
    gss_buffer_desc peer_name_buffer;
    major_status = gss_display_name(&minor_status, initiator_name, &peer_name_buffer, nullptr);
    if (GSS_ERROR(major_status)) {
        gss_release_name(&minor_status, &initiator_name);
        throw std::runtime_error(SB() << "Verify Credentials: Failed to get principal name: " << gssErrorDescription(major_status, minor_status));
    }

    std::string ctx_principal(static_cast<char *>(peer_name_buffer.value), peer_name_buffer.length);
    gss_release_buffer(&minor_status, &peer_name_buffer);
    gss_release_name(&minor_status, &initiator_name);

    // Compose the expected peer principal from CCR fields.
    auto peer_principal_name(ccr["name"].as<std::string>() + "@" + ccr["organization"].as<std::string>());

    log_debug_printf(auth, "Check against CCR: %s", "\n");
    if (peer_principal_name != ctx_principal) {
        throw std::runtime_error(SB() << "Verify Credentials: Kerberos name does not match name in CCR: " << peer_principal_name << " != " << ctx_principal);
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
    authenticated_expiration_date = now + peer_lifetime;
    // Don't check the not_after date because we will only return VALID status while authorized

    // MIC Verification
    auto public_key = ccr["pub_key"].as<std::string>();
    gss_buffer_desc pubkey_buffer;
    pubkey_buffer.value = reinterpret_cast<void *>(const_cast<char *>(public_key.c_str()));
    pubkey_buffer.length = public_key.size();

    auto mic_shared = ccr["verifier.mic"].as<shared_array<const uint8_t>>();
    gss_buffer_desc mic_buffer;
    mic_buffer.value = reinterpret_cast<void *>(const_cast<uint8_t *>(mic_shared.data()));
    mic_buffer.length = mic_shared.size();

    OM_uint32 qop_state;
    major_status = gss_verify_mic(&minor_status, context, &pubkey_buffer, &mic_buffer, &qop_state);
    if (GSS_ERROR(major_status)) {
        throw std::runtime_error(SB() << "MIC verification failed: " << gssErrorDescription(major_status, minor_status));
    }
    log_debug_printf(auth, "MIC verification succeeded%s", "\n");

    // Optionally, clean up the security context if it is no longer needed.
    // gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);

    return true;
}

/**
 * @brief Get the principal info from the kerberos ticket
 *
 * This function gets the principal info from the kerberos ticket.
 *
 * It acquires credentials from the kerberos ticket and then gets the
 * principal name and lifetime from the credentials.
 *
 * @return the principal info from the kerberos ticket
 */
PrincipalInfo AuthNKrb::getPrincipalInfo() {
    OM_uint32 minor_status = 0;
    auto name = GSS_C_NO_NAME;
    gss_buffer_desc name_buffer = GSS_C_EMPTY_BUFFER;
    auto cred_handle = GSS_C_NO_CREDENTIAL;
    OM_uint32 lifetime = 0;

    log_debug_printf(auth, "gss_acquire_cred: GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE%s", "\n");
    OM_uint32 major_status = gss_acquire_cred(&minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred_handle, nullptr, nullptr);
    if (major_status != GSS_S_COMPLETE)
        throw std::runtime_error(SB() << "getPrincipalInfo: Failed to acquire credentials: " << gssErrorDescription(major_status, minor_status));

    log_debug_printf(auth, "gss_inquire_cred%s", "\n");
    major_status = gss_inquire_cred(&minor_status, cred_handle, &name, &lifetime, nullptr, nullptr);
    if (major_status != GSS_S_COMPLETE) {
        const auto error_description = gssErrorDescription(major_status, minor_status, true);
        gss_release_cred(&minor_status, &cred_handle);
        throw std::runtime_error(SB() << "getPrincipalInfo: Failed to inquire credentials: " << error_description);
    }

    log_debug_printf(auth, "gss_display_name%s", "\n");
    major_status = gss_display_name(&minor_status, name, &name_buffer, nullptr);
    if (major_status != GSS_S_COMPLETE) {
        const auto error_description = gssErrorDescription(major_status, minor_status);
        gss_release_name(&minor_status, &name);
        gss_release_cred(&minor_status, &cred_handle);
        throw std::runtime_error(SB() << "getPrincipalInfo: Failed to display principal name: " << error_description);
    }

    std::string principal(static_cast<char *>(name_buffer.value), name_buffer.length);

    // Clean up GSSAPI objects.
    gss_release_buffer(&minor_status, &name_buffer);
    gss_release_name(&minor_status, &name);
    gss_release_cred(&minor_status, &cred_handle);

    return {principal, lifetime};
}

}  // namespace certs
}  // namespace pvxs
