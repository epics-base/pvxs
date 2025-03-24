/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <stdexcept>

#include <epicsMutex.h>

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>

#include <pvxs/sslinit.h>
#include <pvxs/version.h>

namespace pvxs {
namespace ossl {

// Custom OIDs
PVXS_API int NID_SPvaCertStatusURI = NID_undef;
PVXS_API int NID_SPvaCertConfigURI = NID_undef;

// SSL library initialization lock
epicsMutex ssl_init_lock;

/**
 * @brief Initializes the SSL library and sets up the custom certificate status URI OID
 *
 * This is idempotent
 *
 * It will do all the one time SSL library initialization that is required, including
 * SSL_library_init(), OpenSSL_add_all_algorithms(), ERR_load_crypto_strings(),
 * OpenSSL_add_all_ciphers(), and OpenSSL_add_all_digests().
 *
 * It will also create and register the custom certificate status and config URI OIDs.
 */
PVXS_API void sslInit() {
    Guard G(ssl_init_lock);

    // Initialize SSL
    if (NID_SPvaCertStatusURI == NID_undef) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();

        // Create the custom certificate status URI OID
        NID_SPvaCertStatusURI = OBJ_create(NID_SPvaCertStatusURIID, SN_SPvaCertStatusURI, LN_SPvaCertStatusURI);
        if (NID_SPvaCertStatusURI == NID_undef) {
            throw std::runtime_error("Failed to create NID for " SN_SPvaCertStatusURI ": " LN_SPvaCertStatusURI);
        }

        // Create the custom certificate config URI OID
        NID_SPvaCertConfigURI = OBJ_create(NID_SPvaCertConfigURIID, SN_SPvaCertConfigURI, LN_SPvaCertConfigURI);
        if (NID_SPvaCertConfigURI == NID_undef) {
            throw std::runtime_error("Failed to create NID for " SN_SPvaCertConfigURI ": " LN_SPvaCertConfigURI);
        }
    }
}

}  // namespace ossl
}  // namespace pvxs
