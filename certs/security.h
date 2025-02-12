/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SEC_SECURITY_H
#define PVXS_SEC_SECURITY_H

#include <pvxs/nt.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

/**
 * @class Credentials
 * @brief Represents the credentials for an abstract authentication type.
 *
 * This structure provides the principal name.
 */
struct Credentials {
    virtual ~Credentials() {};

    // Principal's name - e.g. username, or device name, or IP address.
    std::string name;
    std::string country;
    std::string organization;
    std::string organization_unit;

    // Validity
    time_t not_before;
    time_t not_after;

    static std::string base64Encode(const char * data, const size_t len) {
        BUF_MEM *buffer_ptr;

        BIO *b64 = BIO_new(BIO_f_base64());         // Create a base64 filter
        BIO *bio = BIO_new(BIO_s_mem());            // Create a memory BIO
        BIO_push(b64, bio);                       // Chain them
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newline breaks
        BIO_write(b64, data, len);                       // Write the input string
        BIO_flush(b64);                                  // Ensure all data is written
        BIO_get_mem_ptr(b64, &buffer_ptr);               // Get the output buffer

        std::string out(buffer_ptr->data, buffer_ptr->length);  // Create a string from the buffer

        BIO_free_all(b64);   // Free the BIOs

        return out;
    }

    static std::string base64Decode(const std::string &input) {
        int inputLength = input.size();
        // Create a BIO chain: base64 filter + memory buffer.
        BIO *b64 = BIO_new(BIO_f_base64());
        // Disable newline processing
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO *bio = BIO_new_mem_buf(input.data(), inputLength);
        bio = BIO_push(b64, bio);

        // Allocate enough memory to hold the decoded data.
        // Base64 encoding expands data by roughly 4/3.
        const int max_decoded_length = inputLength * 3 / 4;
        std::string decoded;
        decoded.resize(max_decoded_length);

        const int decodedLength = BIO_read(bio, &decoded[0], inputLength);
        if(decodedLength < 0)
        {
            BIO_free_all(bio);
            throw std::runtime_error("Base64 decoding failed");
        }
        decoded.resize(decodedLength);

        BIO_free_all(bio);
        return decoded;
    }

    static std::string base64Encode(const std::string &in) {
        return base64Encode(in.data(), in.size());
    }
};

#define CCR_PROTOTYPE(VERIFIER)                \
    {                                          \
        members::String("type"),               \
        members::String("name"),               \
        members::String("country"),            \
        members::String("organization"),       \
        members::String("organization_unit"),  \
        members::UInt16("usage"),              \
        members::UInt64("not_before"),         \
        members::UInt64("not_after"),          \
        members::String("pub_key"),            \
        members::Struct("verifier", VERIFIER), \
    }

struct CertCreationRequest final {
    std::shared_ptr<Credentials> credentials;

    // Type of authenticator to use to verify this certificate creation request:
    // "std", "krb", etc
    std::string type;

    // PVStructure containing the authentication type specific CSR to be
    // transmitted over the wire.  The type field is used to in the server side
    // switch to correctly decode and verify the ccr.
    //
    // The verification structure will be filled by the authenticator subtypes
    // based on their verification needs. If your authentication method can use
    // just a string token to pass verification information then use this
    // definition directly, otherwise replace the definition with a similar
    // structure definition except that the verifier substructure will be your
    // custom verification structure.  The server will recognise the type and
    // understand how to decode it.
    //
    // Note: Only the claims in the certificate are significant when it comes to
    // verification.  The other fields are included for information, fail fast
    // optimisations, and debugging.
    //
    Value ccr;
    std::vector<Member> verifier_fields;

    // Constructor
    CertCreationRequest(const std::string &auth_type, std::vector<Member> verifier_fields) : type(auth_type), verifier_fields(verifier_fields) {
        ccr = TypeDef(TypeCode::Struct, CCR_PROTOTYPE(verifier_fields)).create();
    }
};

struct KeyPair final {
    std::string public_key;
    ossl_ptr<EVP_PKEY> pkey;

    // Default constructor
    KeyPair() = default;

    explicit KeyPair(ossl_ptr<EVP_PKEY> new_pkey) : pkey(std::move(new_pkey)) {
        const ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()));

        if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
            throw std::runtime_error("Failed to write public key to BIO");
        }

        BUF_MEM *bptr;                      // to hold pointer to data in the BIO object.
        BIO_get_mem_ptr(bio.get(), &bptr);  // set to point into BIO object

        // Create a string from the BIO
        std::string result(bptr->data, bptr->length);
        public_key = result;
    }

    // Constructor that takes a std::string for public_key
    // @note private key is not set with this constructor
    explicit KeyPair(const std::string &public_key_string) : public_key(public_key_string) {
        BIO *bio = BIO_new_mem_buf((void *)public_key_string.c_str(), -1);
        pkey.reset(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr));
        BIO_free(bio);

        if (!pkey) {
            throw std::runtime_error(SB() << "Failed to create public key from string: \n" << public_key_string);
        }
    }

    ossl_ptr<EVP_PKEY> getPublicKey() const {
        const ossl_ptr<BIO> bio(BIO_new_mem_buf(public_key.c_str(), public_key.size()));
        if (!bio) {
            throw std::runtime_error("Unable to create BIO");
        }

        ossl_ptr<EVP_PKEY> key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), false);
        if (!key) {
            throw std::runtime_error("Unable to read public key");
        }

        return key;
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_SEC_SECURITY_H
