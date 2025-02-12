/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnldap.h"

#include <configldap.h>

#include <ldap.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <string>
#include <vector>
#include <memory>

#include <pvxs/config.h>

#include "auth.h"
#include "authregistry.h"

DEFINE_LOGGER(auth, "pvxs.auth.ldap");

#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace pvxs {
namespace certs {

struct AuthNLdapRegistrar {
    AuthNLdapRegistrar() { // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_LDAP_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNLdap()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_ldap_registrar;

std::shared_ptr<Credentials> AuthNLdap::getCredentials(const client::Config &config) const {
    auto ldap_config = dynamic_cast<const ConfigLdap&>(config);

    log_debug_printf(auth,
                     "\n******************************************\n"
                     "LDAP Authenticator: %s\n",
                     "Begin acquisition");

    auto ldap_credentials = std::make_shared<LdapCredentials>();
    ldap_credentials->name = ldap_config.name;
    ldap_credentials->organization = ldap_config.organization;
    ldap_credentials->ldap_server = ldap_config.ldap_host;
    ldap_credentials->ldap_port = ldap_config.ldap_port;
    ldap_credentials->password = ldap_config.ldap_account_password;
    return ldap_credentials;
};

std::shared_ptr<CertCreationRequest> AuthNLdap::createCertCreationRequest(
    const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage) const {

    // Cast to LDAP-specific credentials
    auto ldap_credentials = castAs<LdapCredentials, Credentials>(credentials);

    // First, set up the common CCR fields using the base class.
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage);
    log_debug_printf(auth, "LDAP CCR: created%s", "\n");

    std::string user_dn = getDn(credentials->name, credentials->organization);

    // Initialize an LDAP connection.
    // (ldap_credentials is assumed to provide the LDAP server hostname and port.)
    LDAP *ld = ldap_init(ldap_credentials->ldap_server.c_str(), ldap_credentials->ldap_port);
    if (!ld) {
        throw std::runtime_error("Failed to initialize LDAP connection");
    }
    // Set LDAP protocol version (LDAPv3).
    int ldap_version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);

    // Bind to LDAP using SASL/GSSAPI.
    // (You could also use ldap_simple_bind_s if you prefer, using ldap_credentials->password.)
    int rc = ldap_sasl_interactive_bind_s(ld,
                                          user_dn.c_str(),
                                          "GSSAPI",    // Use GSSAPI SASL mechanism.
                                          nullptr,        // Server controls.
                                          nullptr,        // Client controls.
                                          LDAP_SASL_QUIET,
                                          nullptr,        // Callback (if needed).
                                          nullptr);       // Defaults.
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error(SB() << "LDAP failed to bind to " << ldap_credentials->ldap_server << ":" << ldap_credentials->ldap_port << " for " << user_dn << ":" << ldap_err2string(rc));
    }

    // Search for the client’s LDAP entry and retrieve the "epicsPublicKey" attribute.
    LDAPMessage *result = nullptr;

    char *attrs[] = { (char *)PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE, nullptr };
    rc = ldap_search_ext_s(ld,
                           user_dn.c_str(),
                           LDAP_SCOPE_BASE,
                           "(objectClass=*)",
                           attrs,
                           0,
                           nullptr,
                           nullptr,
                           nullptr,
                           0,
                           &result);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error(SB() << "LDAP search failed: " << ldap_err2string(rc));
    }

    // Check whether the attribute exists.
    char **vals = nullptr;
    LDAPMessage *entry = ldap_first_entry(ld, result);
    std::string currentPublicKey;
    if (entry) {
        vals = ldap_get_values(ld, entry, PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
        if (vals && vals[0])
            currentPublicKey = vals[0];
        if (vals)
            ldap_value_free(vals);
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
        addVals[0] = const_cast<char*>(newPublicKey.c_str());
        addVals[1] = nullptr;
        addMod.mod_op = LDAP_MOD_ADD;
        addMod.mod_type = const_cast<char*>(PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
        addMod.mod_values = addVals;
        LDAPMod *mods[2] = { &addMod, nullptr };

        rc = ldap_modify_ext_s(ld, user_dn.c_str(), mods, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) {
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            throw std::runtime_error(SB() << "LDAP add epicsPublicKey failed: " << ldap_err2string(rc));
        }
        log_debug_printf(auth, "LDAP: Added epicsPublicKey for %s", user_dn.c_str());
    }
    else if (currentPublicKey != newPublicKey) {
        // Modify the attribute.
        LDAPMod mod;
        char *modVals[2];
        modVals[0] = const_cast<char*>(newPublicKey.c_str());
        modVals[1] = nullptr;
        mod.mod_op = LDAP_MOD_REPLACE;
        mod.mod_type = const_cast<char*>(PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
        mod.mod_values = modVals;
        LDAPMod *mods[2] = { &mod, nullptr };

        rc = ldap_modify_ext_s(ld, user_dn.c_str(), mods, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) {
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            throw std::runtime_error(SB() << "LDAP modify epicsPublicKey failed: " << ldap_err2string(rc));
        }
        log_debug_printf(auth, "LDAP: Updated epicsPublicKey for %s", user_dn.c_str());
    }
    else {
        log_debug_printf(auth, "LDAP: epicsPublicKey for %s is up-to-date", user_dn.c_str());
    }
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    // --- Create the Digital Signature ---
    std::string payload = ccrToString(cert_creation_request, usage);

    // Use the private key from key_pair->private_key to sign the payload with SHA-256.
    ossl_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_new(), false);
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, key_pair->pkey.get()) <= 0) {
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(mdctx.get(), payload.data(), payload.size()) <= 0) {
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) <= 0) {
        throw std::runtime_error("EVP_DigestSignFinal (get length) failed");
    }
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(mdctx.get(), signature.data(), &sig_len) <= 0) {
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    // base64-encode the signature so it can be represented as a string.
    std::string signature_base64 = Credentials::base64Encode(reinterpret_cast<char *>(signature.data()), sig_len);

    // Add the signature to the CCR
    cert_creation_request->ccr["verifier.signature"] = signature_base64;

    return cert_creation_request;
};

bool AuthNLdap::verify(const Value ccr) const {
    // Verify that the signature provided in the CCR was signed with the user's private key
    auto signature = ccr["verifier.signature"].as<std::string>();
    auto payload = ccrToString(ccr);

    // Get public key
    std::string uid = ccr["name"].as<std::string>();
    std::string organization = ccr["organization"].as<std::string>();   // e.g., "epics.org"
    std::string public_key_str = getPublicKeyFromLDAP(ldap_server, ldap_port, uid, organization);

    KeyPair key_pair(public_key_str);
    return CertFactory::verifySignature(key_pair.pkey, signature, payload);
}

// A simple helper to split a string by a delimiter.
std::vector<std::string> AuthNLdap::split(const std::string& s, char delimiter) const {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string AuthNLdap::getDn(const std::string &uid, const std::string &organization) const {
    // Convert organization (e.g., "epics.org") to a DN component "dc=epics,dc=org".
    std::vector<std::string> dc_parts = split(organization, '.');
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
 * @param uid the user name in LDAP
 * @param organization the user org e.g. epics.org
 * @return the public key string
 */
std::string AuthNLdap::getPublicKeyFromLDAP(const std::string &ldap_server,
                                            int ldap_port,
                                            const std::string &uid,
                                            const std::string &organization) const {
    LDAP *ld = nullptr;
    // Build the LDAP URL, e.g., "ldap://ldap_server:ldap_port"
    std::string ldap_url = "ldap://" + ldap_server + ":" + std::to_string(ldap_port);

    // Initialize the LDAP connection.
    int rc = ldap_initialize(&ld, ldap_url.c_str());
    if (rc != LDAP_SUCCESS) {
        throw std::runtime_error("ldap_initialize failed: " + std::string(ldap_err2string(rc)));
    }

    // Use anonymous bind (assuming ACLs allow anonymous read).
    rc = ldap_simple_bind_s(ld, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("ldap_simple_bind_s failed: " + std::string(ldap_err2string(rc)));
    }

    // Convert uid and organization (e.g., "epics.org") to a DN component "dc=epics,dc=org".
    std::string dn = getDn(uid, organization);

    // We want only the epicsPublicKey attribute.
    char *attrs[] = { const_cast<char*>(PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE), nullptr };
    LDAPMessage *result = nullptr;

    // Search with scope BASE for this DN.
    rc = ldap_search_ext_s(ld,
                           dn.c_str(),
                           LDAP_SCOPE_BASE,
                           "(objectClass=*)",
                           attrs,
                           0,   // return values (not types)
                           nullptr,
                           nullptr,
                           nullptr,
                           0,
                           &result);
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

    // Retrieve the attribute value.
    char **values = ldap_get_values(ld, entry, PVXS_LDAP_AUTH_PUB_KEY_ATTRIBUTE);
    if (!values || !values[0]) {
        if (values) ldap_value_free(values);
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        throw std::runtime_error("epicsPublicKey attribute not found for DN: " + dn);
    }

    std::string publicKeyString = values[0];

    ldap_value_free(values);
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    return publicKeyString;
}

}  // namespace security
}  // namespace pvxs

#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
