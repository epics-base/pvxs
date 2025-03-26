/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnldap.h"

#include <configldap.h>

#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#else
#ifndef LDAP_DEPRECATED
#define LDAP_DEPRECATED 1
#endif
#endif

#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <ldap.h>

#include <openssl/evp.h>

#include "auth.h"
#include "authregistry.h"

DEFINE_LOGGER(auth, "pvxs.auth.ldap");

namespace pvxs {
namespace certs {

/**
 * @brief Registrar for the LDAP authenticator
 *
 * This will register the LDAP authenticator with the AuthRegistry.
 * This allows it to be found by PVACMS to authenticate LDAP certificate
 * creation requests (CCRs).
 */
struct AuthNLdapRegistrar {
    AuthNLdapRegistrar() {  // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_LDAP_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNLdap()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_ldap_registrar;

/**
 * @brief Get the credentials for the LDAP authenticator
 *
 * This will get the credentials for the LDAP authenticator.
 *
 * - The LDAP username is copied from the configuration using the
 * EPICS_PVA_AUTH_NAME environment variable if it is set, otherwise
 * it defaults to the logged in user.
 *
 * - The password is copied from the configuration using the
 * EPICS_AUTH_LDAP_ACCOUNT_PWD_FILE environment variable if it is set to
 * read it from a file, otherwise it is read from the command line.
 *
 * - The organization is copied from the configuration using the
 * EPICS_PVA_AUTH_ORGANIZATION environment variable if it is set, otherwise
 * it defaults to the logged in user's organization.
 * Note: The organisation is used in LDAP by splitting the string on '.'
 * and using the parts as the components of the DN. e.g. epics.org ->
 * dc=epics,dc=org
 *
 * - The LDAP server and port are copied from the configuration, defaulting to
 * the EPICS_AUTH_LDAP_HOST and EPICS_AUTH_LDAP_PORT environment variables.
 *
 * @param config the configuration for the authenticator
 * @param for_client true when getting gredentials for a client, false for server
 * @return the credentials for the LDAP authenticator
 */
std::shared_ptr<Credentials> AuthNLdap::getCredentials(const client::Config &config, const bool for_client) const {
    const auto ldap_config = dynamic_cast<const ConfigLdap &>(config);

    log_debug_printf(auth,
                     "\n******************************************\n"
                     "LDAP Authenticator: %s\n",
                     "Begin acquisition");

    auto ldap_credentials = std::make_shared<LdapCredentials>();

    // Set the expiration time of the certificate
    const time_t now = time(nullptr);
    ldap_credentials->not_before = now;
    ldap_credentials->not_after = now + 365 * 24 * 60 * 60;

    ldap_credentials->name = for_client ? ldap_config.name : ldap_config.server_name;
    ldap_credentials->organization = for_client ? ldap_config.organization : ldap_config.server_organization;
    ldap_credentials->ldap_server = ldap_config.ldap_host;
    ldap_credentials->ldap_port = ldap_config.ldap_port;
    ldap_credentials->password = ldap_config.ldap_account_password;

    return ldap_credentials;
}

std::shared_ptr<CertCreationRequest> AuthNLdap::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage,
const ConfigAuthN &config) const {
    // Cast to LDAP-specific credentials
    auto ldap_credentials = castAs<LdapCredentials, Credentials>(credentials);

    // First, set up the common CCR fields using the base class.
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage, config);
    log_debug_printf(auth, "LDAP CCR: created%s", "\n");

    std::string user_dn = getDn(credentials->name, credentials->organization);

    // Initialize an LDAP connection.
    std::string ldap_url = "ldap://" + ldap_credentials->ldap_server + ":" + std::to_string(ldap_credentials->ldap_port);
    LDAP *ld = nullptr;
    int rc = ldap_initialize(&ld, ldap_url.c_str());
    if (rc != LDAP_SUCCESS) {
        throw std::runtime_error("ldap_initialize failed: " + std::string(ldap_err2string(rc)));
    }

    int ldap_version = LDAP_VERSION3;
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("ldap_set_option failed: " + std::string(ldap_err2string(rc)));
    }

    berval cred{};
    cred.bv_val = const_cast<char *>(ldap_credentials->password.c_str());
    cred.bv_len = ldap_credentials->password.size();
    rc = ldap_sasl_bind_s(ld, user_dn.c_str(), nullptr, &cred, nullptr, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error(SB() << "LDAP simple bind failed to bind to " << ldap_credentials->ldap_server << ":" << ldap_credentials->ldap_port << " for "
                                      << user_dn << ":" << ldap_err2string(rc));
    }

    // Search for the client’s LDAP entry and retrieve the "epicsPublicKey" attribute.
    LDAPMessage *result = nullptr;

    char *attrs[] = {(char *)PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE, nullptr};
    rc = ldap_search_ext_s(ld, user_dn.c_str(), LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, nullptr, nullptr, nullptr, 0, &result);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error(SB() << "LDAP search failed: " << ldap_err2string(rc));
    }

    // Check whether the attribute exists.
    LDAPMessage *entry = ldap_first_entry(ld, result);
    std::string currentPublicKey;
    if (entry) {
        berval **pub_key_val_ptr = ldap_get_values_len(ld, entry, PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
        if (pub_key_val_ptr && pub_key_val_ptr[0]) currentPublicKey = std::string(pub_key_val_ptr[0]->bv_val, pub_key_val_ptr[0]->bv_len);
        if (pub_key_val_ptr) ldap_value_free_len(pub_key_val_ptr);
    }
    ldap_msgfree(result);

    // The new public key is taken from the key pair.
    // (Assume key_pair->public_key is already the base64 encoded PEM version.)
    std::string newPublicKey = key_pair->public_key;

    // If the public key is not present or is different, add or modify it.
    if (currentPublicKey.empty()) {
        // Add the attribute.
        LDAPMod addMod;
        char *addVals[2];
        addVals[0] = const_cast<char *>(newPublicKey.c_str());
        addVals[1] = nullptr;
        addMod.mod_op = LDAP_MOD_ADD;
        addMod.mod_type = const_cast<char *>(PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
        addMod.mod_values = addVals;
        LDAPMod *mods[2] = {&addMod, nullptr};

        rc = ldap_modify_ext_s(ld, user_dn.c_str(), mods, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) {
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            throw std::runtime_error(SB() << "LDAP add epicsPublicKey failed: " << ldap_err2string(rc));
        }
        log_debug_printf(auth, "LDAP: Added epicsPublicKey for %s", user_dn.c_str());
    } else if (currentPublicKey != newPublicKey) {
        // Modify the attribute.
        LDAPMod mod;
        char *modVals[2];
        modVals[0] = const_cast<char *>(newPublicKey.c_str());
        modVals[1] = nullptr;
        mod.mod_op = LDAP_MOD_REPLACE;
        mod.mod_type = const_cast<char *>(PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
        mod.mod_values = modVals;
        LDAPMod *mods[2] = {&mod, nullptr};

        rc = ldap_modify_ext_s(ld, user_dn.c_str(), mods, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) {
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            throw std::runtime_error(SB() << "LDAP modify epicsPublicKey failed: " << ldap_err2string(rc));
        }
        log_debug_printf(auth, "LDAP: Updated epicsPublicKey for %s", user_dn.c_str());
    } else {
        log_debug_printf(auth, "LDAP: epicsPublicKey for %s is up-to-date", user_dn.c_str());
    }
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    // --- Create the Digital Signature ---
    std::string payload = ccrToString(cert_creation_request, usage);

    // Use the private key from key_pair->private_key to sign the payload with SHA-256.
    ossl_ptr<EVP_MD_CTX> message_digest_context(EVP_MD_CTX_new(), false);
    if (!message_digest_context) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(message_digest_context.get(), nullptr, EVP_sha256(), nullptr, key_pair->pkey.get()) <= 0) {
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(message_digest_context.get(), payload.data(), payload.size()) <= 0) {
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(message_digest_context.get(), nullptr, &sig_len) <= 0) {
        throw std::runtime_error("EVP_DigestSignFinal (get length) failed");
    }
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(message_digest_context.get(), signature.data(), &sig_len) <= 0) {
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    // base64-encode the signature so it can be represented as a string.
    std::string signature_base64 = Credentials::base64Encode(reinterpret_cast<char *>(signature.data()), sig_len);

    // Add the signature to the CCR
    cert_creation_request->ccr["verifier.signature"] = signature_base64;

    return cert_creation_request;
}

bool AuthNLdap::verify(const Value ccr) const {
    // Verify that the signature provided in the CCR was signed with the user's private key
    auto signature = Credentials::base64Decode(ccr["verifier.signature"].as<std::string>());
    auto payload = ccrToString(ccr);

    // Get public key
    auto uid = ccr["name"].as<std::string>();
    auto organization = ccr["organization"].as<std::string>();  // e.g., "epics.org"
    std::string public_key_str = getPublicKeyFromLDAP(ldap_server, ldap_port, uid, organization);

    KeyPair key_pair(public_key_str);
    return CertFactory::verifySignature(key_pair.pkey, payload, signature);
}

// A simple helper to split a string by a delimiter.
std::vector<std::string> AuthNLdap::split(const std::string &s, const char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string AuthNLdap::getDn(const std::string &uid, const std::string &organization) {
    // Convert organization (e.g., "epics.org") to a DN component "dc=epics,dc=org".
    const std::vector<std::string> dc_parts = split(organization, '.');
    std::string dc_string;
    for (size_t i = 0; i < dc_parts.size(); i++) {
        if (i > 0) {
            dc_string += ",";
        }
        dc_string += "dc=" + dc_parts[i];
    }

    // Compose the full DN for the user.
    // The DN format is: "uid=<uid>,ou=People,<dc_string>"
    std::string dn = "uid=" + uid + ",ou=" + PVXS_LDAP_AUTH_PEOPLE_GROUP + "," + dc_string;
    return dn;
}

/**
 *  @brief Retrieve the epicsPublicKey from LDAP for a given uid and organization.
 *
 * @param ldap_server the ldap server ip or hostname
 * @param ldap_port the ldap server port
 * @param uid the username in LDAP
 * @param organization the user org e.g. epics.org
 * @return the public key string
 */
std::string AuthNLdap::getPublicKeyFromLDAP(const std::string &ldap_server, const int ldap_port, const std::string &uid, const std::string &organization) {
    const std::string ldap_url = "ldap://" + ldap_server + ":" + std::to_string(ldap_port);
    LDAP *ld = nullptr;
    int rc = ldap_initialize(&ld, ldap_url.c_str());
    if (rc != LDAP_SUCCESS) {
        throw std::runtime_error("ldap_initialize failed: " + std::string(ldap_err2string(rc)));
    }

    constexpr int ldap_version = LDAP_VERSION3;
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("ldap_set_option failed: " + std::string(ldap_err2string(rc)));
    }

    // Perform an anonymous simple bind
    rc = ldap_simple_bind_s(ld, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("ldap_simple_bind_s failed: " + std::string(ldap_err2string(rc)));
    }

    // Convert uid and organization (e.g., "epics.org") to a DN component "uid=<uid>, ou=People, dc=epics,dc=org".
    const std::string dn = getDn(uid, organization);

    // We want only the epicsPublicKey attribute.
    char *attrs[] = {const_cast<char *>(PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE), nullptr};

    LDAPMessage *result = nullptr;
    rc = ldap_search_ext_s(ld, dn.c_str(), LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, nullptr, nullptr, nullptr, 0, &result);
    if (rc != LDAP_SUCCESS) {
        if (result) ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("ldap_search_ext_s failed: " + std::string(ldap_err2string(rc)));
    }

    LDAPMessage *entry = ldap_first_entry(ld, result);
    if (!entry) {
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("No entry found for DN: " + dn);
    }

    berval **pub_key_val_ptr = ldap_get_values_len(ld, entry, PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
    if (!pub_key_val_ptr || !pub_key_val_ptr[0]) {
        if (pub_key_val_ptr) ldap_value_free_len(pub_key_val_ptr);
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("epicsPublicKey attribute not found for DN: " + dn);
    }

    const std::string public_key_string(pub_key_val_ptr[0]->bv_val, pub_key_val_ptr[0]->bv_len);
    ldap_value_free_len(pub_key_val_ptr);
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    return public_key_string;
}

}  // namespace certs
}  // namespace pvxs

#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
