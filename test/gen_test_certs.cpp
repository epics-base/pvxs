/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#endif

#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>
#include <iomanip>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/stack.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <epicsGetopt.h>

#include "ownedptr.h"
#include "openssl.h"
#include "opensslgbl.h"

constexpr std::uint64_t TEST_FIRST_SERIAL = 9876543210;

namespace {

struct SSLError : public std::runtime_error {
    explicit
    SSLError(const std::string& msg)
        :std::runtime_error([&msg]() -> std::string {
            std::ostringstream strm;
            const char *file = nullptr;
            int line = 0;
            const char *data = nullptr;
            int flags = 0;
            while(auto err = ERR_get_error_all(&file, &line, nullptr, &data, &flags)) {
                strm<<file<<':'<<line<<':'<<ERR_reason_error_string(err);
                if(data && (flags&ERR_TXT_STRING))
                    strm<<':'<<data;
                strm<<", ";
            }
            strm<<msg;
            return strm.str();
    }())
    {}
    virtual ~SSLError() {}
};

struct SB {
    std::ostringstream strm;
    SB() {}
    operator std::string() const { return strm.str(); }
    std::string str() const { return strm.str(); }
    template<typename T>
    SB& operator<<(const T& i) { strm<<i; return *this; }
};

std::vector<unsigned char> computeSkidFromKey(EVP_PKEY* pkey) {
    std::vector<unsigned char> skid;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    const pvxs::ossl_ptr<EVP_MD_CTX> mdctx(EVP_MD_CTX_new(), false);
    if (!mdctx) throw SSLError("Failed to create MD context");

    if (!EVP_DigestInit_ex(mdctx.get(), EVP_sha1(), nullptr)) {
        throw SSLError("Failed to init SHA1 digest");
    }

    const int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0) throw SSLError("Failed to get public key DER length");

    std::vector<unsigned char> der_data(len);
    unsigned char* der_ptr = der_data.data();
    if (i2d_PUBKEY(pkey, &der_ptr) != len) {
        throw SSLError("Failed to encode public key");
    }

    const unsigned char* der_data_ptr = der_data.data();
    const pvxs::ossl_ptr<X509_PUBKEY> pubkey_struct(d2i_X509_PUBKEY(nullptr, &der_data_ptr, len), false);
    if (!pubkey_struct) throw SSLError("Failed to parse X509_PUBKEY");

    ASN1_OBJECT* alg = nullptr;
    const unsigned char* pk_data = nullptr;
    int pk_len = 0;
    X509_ALGOR* algor = nullptr;
    if (!X509_PUBKEY_get0_param(&alg, &pk_data, &pk_len, &algor, pubkey_struct.get())) {
        throw SSLError("Failed to extract public key");
    }

    if (!EVP_DigestUpdate(mdctx.get(), pk_data, pk_len)) {
        throw SSLError("Failed to update digest");
    }

    if (!EVP_DigestFinal_ex(mdctx.get(), hash, &hash_len)) {
        throw SSLError("Failed to finalize digest");
    }

    skid.assign(hash, hash + hash_len);
    return skid;
}

// many openssl calls return 1 (or sometimes zero) on success.
void _must_equal(int expect, int actual, const char *expr)
{
    if(expect!=actual)
        throw SSLError(SB()<<expect<<"!="<<actual<<" : "<<expr);
}
#define _STR(STR) #STR
#define MUST(EXPECT, ...) _must_equal(EXPECT, __VA_ARGS__, _STR(__VA_ARGS__))

#ifdef NID_oracle_jdk_trustedkeyusage
// OpenSSL 3.2 will add the ability to set the Java specific trustedkeyusage bag attribute
static int jdk_trust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept {
    try {
        // Only add trustedkeyusage when bag is an X509 cert. with an associated key
        // (when localKeyID is present) which does not already have trustedkeyusage.
        if(PKCS12_SAFEBAG_get_nid(bag)!=NID_certBag
                || PKCS12_SAFEBAG_get_bag_nid(bag)!=NID_x509Certificate
                || !!PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)
                || !!PKCS12_SAFEBAG_get0_attr(bag, NID_oracle_jdk_trustedkeyusage))
            return 1;

        auto curattrs(PKCS12_SAFEBAG_get0_attrs(bag));
        // PKCS12_SAFEBAG_get0_attrs() returns const.  Make a paranoia copy.
        pvxs::ossl_ptr<STACK_OF(X509_ATTRIBUTE)> newattrs(sk_X509_ATTRIBUTE_deep_copy(curattrs,
                                                                                 &X509_ATTRIBUTE_dup,
                                                                                 &X509_ATTRIBUTE_free));

        pvxs::ossl_ptr<ASN1_OBJECT> trust(OBJ_txt2obj("anyExtendedKeyUsage", 0));
        pvxs::ossl_ptr<X509_ATTRIBUTE> attr(X509_ATTRIBUTE_create(NID_oracle_jdk_trustedkeyusage,
                                                             V_ASN1_OBJECT, trust.get()));

        MUST(1, sk_X509_ATTRIBUTE_push(newattrs.get(), attr.get()));
        attr.release();

        PKCS12_SAFEBAG_set0_attrs(bag, newattrs.get());
        newattrs.release();

        return 1;
    } catch(std::exception& e){
        std::cerr<<"Error: unable to add JDK trust attribute: "<<e.what()<<"\n";
        return 0;
    }
}
#else // !NID_oracle_jdk_trustedkeyusage
static int jdk_trust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept {return 0;}
static inline
PKCS12 *PKCS12_create_ex2(const char *pass, const char *name, EVP_PKEY *pkey,
                          X509 *cert, STACK_OF(X509) *cert_auth_chain_ptr, int nid_key, int nid_cert,
                          int iter, int mac_iter, int keytype,
                          OSSL_LIB_CTX *ctx, const char *propq,
                          int (*cb)(PKCS12_SAFEBAG *bag, void *cbarg), void *cbarg)
{
    return PKCS12_create_ex(pass, name, pkey, cert, cert_auth_chain_ptr,
                            nid_key, nid_cert, iter, mac_iter, keytype,
                            ctx, propq);
}
#endif // NID_oracle_jdk_trustedkeyusage

/* Understanding X509_EXTENSION in openssl...
 * Each NID_* has a corresponding const X509V3_EXT_METHOD
 * in a crypto/x509/v3_*.c which defines the expected type of the void* value arg.
 *
 * NID_subject_key_identifier   <-> ASN1_OCTET_STRING
 * NID_authority_key_identifier <-> AUTHORITY_KEYID
 * NID_basic_constraints        <-> BASIC_CONSTRAINTS
 * NID_key_usage                <-> ASN1_BIT_STRING
 * NID_ext_key_usage            <-> EXTENDED_KEY_USAGE
 *
 * Use X509V3_CTX automates building these values in the correct way,
 * and than calls low level X509_add1_ext_i2d()
 *
 * see also "man x509v3_config" for explaination of "expr" string.
 */
void add_extension(X509* cert, int nid, const char *expr,
                   const X509* subject = nullptr, const X509* issuer = nullptr)
{
    X509V3_CTX xctx; // well, this is different...
    X509V3_set_ctx_nodb(&xctx);
    X509V3_set_ctx(&xctx, const_cast<X509*>(issuer), const_cast<X509*>(subject), nullptr, nullptr, 0);

    pvxs::ossl_ptr<X509_EXTENSION> ext(X509V3_EXT_conf_nid(nullptr, &xctx, nid,
                                                      expr));
    MUST(1, X509_add_ext(cert, ext.get(), -1));
}

void add_skid_extension(X509* cert, EVP_PKEY* pkey) {
    auto skid = computeSkidFromKey(pkey);

    ASN1_OCTET_STRING* skid_asn1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(skid_asn1, skid.data(), skid.size());

    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid_asn1);
    MUST(1, X509_add_ext(cert, ext, -1));
    X509_EXTENSION_free(ext);
}

/**
 * @brief Get the Certificate Status PV base.
 * e.g., CERT:STATUS
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @return the Certificate Status PV base string
 */
std::string getCertStatusPvBase(const std::string &cert_pv_prefix) {
    std::string pv = cert_pv_prefix;
    pv += ":STATUS";
    return pv;
}

/**
 * @brief Generates a serial number string as used in a certificate ID.
 *
 * Left pad with zeros in 20 characters
 *
 * @param serial The serial number of the certificate.
 * @return The serial number string.
 *
 * @see SB
 */
std::string getSerialString(const uint64_t &serial) {
    std::ostringstream oss;
    oss << std::setw(20)
        << std::setfill('0')
        << serial;
    return oss.str();
}

/**
 * @brief Generates a unique certificate ID based on the issuer ID and serial number.
 *
 * This function takes the issuer ID and serial number as input and combines them
 * into a unique certificate ID. The certificate ID is generated by concatenating
 * the issuer ID and serial number with a ":" separator.
 *
 * @param issuer_id The issuer ID of the certificate.
 * @param serial The serial number of the certificate.
 * @return The unique certificate ID.
 *
 * @see SB
 */
std::string getCertId(const std::string &issuer_id, const uint64_t &serial) {
    std::ostringstream oss;
    oss << issuer_id
        << ":"
        << getSerialString(serial);
    return oss.str();
}

/**
 * @brief Generates the Certificate URI to write into the certificate given the configuration to determine the prefix, the issuer and the serial number
 *
 * @param cert_pv_prefix the prefix for PVACMS PVs.  Default `CERT`
 * @param issuer_id the issuer id
 * @param serial the certificate's serial number
 * @return the certificate URI to write into the certificate
 */
std::string getCertStatusURI(const std::string &cert_pv_prefix, const std::string &issuer_id, const uint64_t &serial) {
    auto cert_uri = getCertStatusPvBase(cert_pv_prefix);
    cert_uri += ":";
    cert_uri += getCertId(issuer_id, serial);
    return cert_uri;
}


// for writing a PKCS#12 file
struct PKCS12Writer {
    const std::string& outdir;
    const char* friendlyName = nullptr;
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;
    pvxs::ossl_ptr<STACK_OF(X509)> cacerts;

    explicit PKCS12Writer(const std::string& outdir)
        :outdir(outdir)
        ,cacerts(sk_X509_new_null())
    {}

    void write(const char* fname,
               const char *passwd = "") const {
        const pvxs::ossl_ptr<PKCS12> p12(PKCS12_create_ex2(passwd,
                                                friendlyName,
                                                key,
                                                cert,
                                                cacerts.get(),
                                                0, 0, 0, 0, 0,
                                                nullptr, nullptr,
                                                &jdk_trust, nullptr));

        const std::string output_path(SB()<<outdir<<fname);
        const pvxs::file_ptr out(fopen(output_path.c_str(), "wb"), false);
        if(!out) {
            const auto err = errno;
            throw std::runtime_error(SB()<<"Error opening for write : "<<output_path<<" : "<<strerror(err));
        }

        MUST(1, i2d_PKCS12_fp(out.get(), p12.get()));
    }
};

struct CertCreator {
    // commonName string
    const char *CN = nullptr;
    // Root cert (we'll use this as if the CMS is serving this root cert and not some intermediary)
    const X509 *root = nullptr;
    // NULL for self-signed
    const X509 *issuer = nullptr;
    EVP_PKEY *ikey = nullptr;
    // expiration
    unsigned expire_days = 365*10;
    // cert. serial number
    serial_number_t serial = 0;
    // extensions
    const char *key_usage = nullptr;
    const char *extended_key_usage = nullptr;
    // Cert. Authority
    bool isCA = false;
    // algorithm attributes
    int keytype = EVP_PKEY_RSA;
    size_t keylen = 2048;
    const EVP_MD* sig = EVP_sha256();

    /**
     * Add a string extension by NID to certificate.
     *
     */
    void addCustomExtensionByNid(const pvxs::ossl_ptr<X509> &certificate, const int nid, const std::string &value) {

        // wrap string value as IA5 string
        const pvxs::ossl_ptr<ASN1_IA5STRING> ival(__FILE__, __LINE__, s2i_ASN1_IA5STRING(nullptr, nullptr, value.c_str()));

        // encode as DER to byte buffer
        unsigned char *dbuf = nullptr;
        const auto dbuflen = i2d_ASN1_IA5STRING(ival.get(), &dbuf); // encode
        if (dbuflen < 0)
            throw pvxs::ossl::SSLError("Adding custom extension: Failed to create ASN1_IA5STRING object");

        // ensure OPENSSL_free()
        const pvxs::ossl_ptr<unsigned char> dholder(__FILE__, __LINE__, dbuf);

        // wrap byte buffer as OCTET string
        // can't use s2i_ASN1_OCTET_STRING() as DER is not nil terminated string
        const pvxs::ossl_ptr<ASN1_OCTET_STRING> idval(__FILE__, __LINE__, ASN1_OCTET_STRING_new());
        if (!ASN1_OCTET_STRING_set(idval.get(), dbuf, dbuflen))
            throw pvxs::ossl::SSLError("Adding custom extension: Failed to set ASN1_OCTET_STRING");

        // Create a new non-critical extension using wrapped, encoded, PV name as value
        const pvxs::ossl_ptr<X509_EXTENSION> ext(X509_EXTENSION_create_by_NID(nullptr, nid, false, idval.get()), false);
        if (!ext) {
            throw pvxs::ossl::SSLError("Adding custom extension: Failed to create X509_EXTENSION");
        }

        // Add the extension to the certificate
        if (!X509_add_ext(certificate.get(), ext.get(), -1)) {
            throw pvxs::ossl::SSLError("Failed to add X509_EXTENSION to certificate");
        }
    }

    std::tuple<pvxs::ossl_ptr<EVP_PKEY>, pvxs::ossl_ptr<X509>> create(const bool add_status_extension=true)
    {
        pvxs::ossl::osslInit();

        // generate a public/private key pair
        pvxs::ossl_ptr<EVP_PKEY> key;
        {
            const pvxs::ossl_ptr<EVP_PKEY_CTX> kCtx(EVP_PKEY_CTX_new_id(keytype, nullptr));
            MUST(1, EVP_PKEY_keygen_init(kCtx.get()));
            MUST(1, EVP_PKEY_CTX_set_rsa_keygen_bits(kCtx.get(), keylen));
            MUST(1, EVP_PKEY_keygen(kCtx.get(), key.acquire()));
        }

        // start assembling certificate
        pvxs::ossl_ptr<X509> cert(X509_new());
        MUST(1, X509_set_version(cert.get(), 2));

        MUST(1, X509_set_pubkey(cert.get(), key.get()));

        // symbolic name for this cert.  Could have multiple entries.
        // but we only add commonName (CN)
        {
            const auto sub(X509_get_subject_name(cert.get()));
            if(CN) {
                MUST(1, X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC,
                                                  reinterpret_cast<const unsigned char*>(CN),
                                                  -1, -1, 0));
            }
            MUST(1, X509_NAME_add_entry_by_txt(sub, "C", MBSTRING_ASC,
                                               reinterpret_cast<const unsigned char*>("US"),
                                               -1, -1, 0));
            MUST(1, X509_NAME_add_entry_by_txt(sub, "O", MBSTRING_ASC,
                                               reinterpret_cast<const unsigned char *>("certs.epics.org"),
                                               -1, -1, 0));
            MUST(1, X509_NAME_add_entry_by_txt(sub, "OU", MBSTRING_ASC,
                                               reinterpret_cast<const unsigned char*>("epics.org Certificate Authority"),
                                               -1, -1, 0));
        }
        if(!issuer) {
            issuer = cert.get(); // self-signed
            ikey = key.get();

        } else if(!ikey) {
            throw std::runtime_error("no issuer key");
        }

        // symbolic name of certificate which issues this new cert.
        MUST(1, X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer)));

        // set valid time range
        {
            time_t now(time(nullptr));
            pvxs::ossl_ptr<ASN1_TIME> before(ASN1_TIME_new());
            ASN1_TIME_set(before.get(), now);
            pvxs::ossl_ptr<ASN1_TIME> after(ASN1_TIME_new());
            ASN1_TIME_set(after.get(), now+(expire_days*24*60*60));
            MUST(1, X509_set1_notBefore(cert.get(), before.get()));
            MUST(1, X509_set1_notAfter(cert.get(), after.get()));
        }

        // issuer serial number
        if(serial) {
            const pvxs::ossl_ptr<ASN1_INTEGER> sn(ASN1_INTEGER_new());
            MUST(1, ASN1_INTEGER_set_uint64(sn.get(), serial));
            MUST(1, X509_set_serialNumber(cert.get(), sn.get()));
        }

        // certificate extensions...
        // see RFC5280

        // Compute SKID manually to ensure consistency across platforms
        add_skid_extension(cert.get(), ikey);

        // store hash and name of issuer certificate (or issuer's issuer?)
        // RFC5280 mandates this for all certificates.
        add_extension(cert.get(), NID_authority_key_identifier, "keyid:always,issuer:always", nullptr, issuer);

        // certificate usage constraints.

        // most basic.  Can this certificate be an issuer to other certificates?
        // RFC5280 mandates this for a Certificate Authority certificate.  (CA:TRUE)  Optional for others, but common
        add_extension(cert.get(), NID_basic_constraints, isCA ? "critical,CA:TRUE" : "CA:FALSE");

        if (key_usage)
            add_extension(cert.get(), NID_key_usage, key_usage);

        if(extended_key_usage)
            add_extension(cert.get(), NID_ext_key_usage, extended_key_usage);

        if ( add_status_extension) {
            const auto issuer_id = pvxs::certs::CertStatus::getSkId(root ? root : issuer);
            addCustomExtensionByNid(cert, pvxs::ossl::NID_SPvaCertStatusURI, getCertStatusURI("CERT", issuer_id, serial));
        }

        auto nbytes(X509_sign(cert.get(), ikey, sig));
        if(nbytes==0)
            throw SSLError("Failed to sign cert");

        return std::make_tuple(std::move(key), std::move(cert));
    }
};

void usage(const char* argv0) {
    std::cerr<<"Usage: "<<argv0<<" [-O <outdir>]\n"
               "\n"
               "    Write out a set of keychain files for testing.\n"
               "\n"
               "    -O <outdir>  - Write files to this directory.  (default: .)\n"
               ;
}
} // namespace

int main(int argc, char *argv[])
{
    try {
        std::string outdir(".");
        {
            int opt;
            while ((opt = getopt(argc, argv, "hO:")) != -1) {
                switch(opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                case 'O':
                    outdir = optarg;
                    if(outdir.empty())
                        throw std::runtime_error("-O argument must not be empty");
                    break;
                default:
                    usage(argv[0]);
                    std::cerr<<"\nUnknown argument: "<<char(opt)<<std::endl;
                    return 1;
                }
            }
        }

        outdir.push_back('/');

        if(optind!=argc) {
            usage(argv[0]);
            std::cerr<<"\nUnexpected arguments\n";
            return 1;
        }

        serial_number_t serial = TEST_FIRST_SERIAL;

        // The root certificate authority
        pvxs::ossl_ptr<X509> root_cert;
        pvxs::ossl_ptr<EVP_PKEY> root_key;
        {
            CertCreator cc;
            cc.CN = "EPICS Root Certificate Authority";
            cc.serial = serial++;
            cc.isCA = true;
            cc.key_usage = "cRLSign,keyCertSign";

            std::tie(root_key, root_cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;

            // This can be used for server-only connections as the client p12 file containing only the Certificate Authority certificate
            // Properly labelled in the p12 file in the correct bag
            MUST(1, sk_X509_push(p12.cacerts.get(), root_cert.get()));
            p12.write("cert_authcert.p12");

            // This contains the Certificate Authority certificate as well as the keys - used when we need a Certificate Authority certificate for CMS and other signing roles
            p12.key = root_key.get();
            p12.write("cert_auth.p12");
        }

        // a server-type cert. issued directly from the root
        {
            CertCreator cc;
            cc.CN = "superserver1";
            cc.root = root_cert.get();
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            cc.extended_key_usage = "serverAuth";
            cc.issuer = root_cert.get();
            cc.ikey = root_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create(false); // Don't add extension so this can be used as Mock PVACMS cert in tests

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;
            p12.key = key.get();
            p12.cert = cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), root_cert.get()));
            p12.write("superserver1.p12");
        }

        // a chain/intermediate certificate authority
        pvxs::ossl_ptr<X509> i_cert;
        pvxs::ossl_ptr<EVP_PKEY> i_key;
        {
            CertCreator cc;
            cc.root = root_cert.get();
            cc.CN = "intermediateCA";
            cc.serial = serial++;
            cc.issuer = root_cert.get();
            cc.ikey = root_key.get();
            cc.isCA = true;
            cc.key_usage = "digitalSignature,cRLSign,keyCertSign";
            // on a Certificate Authority certificate. this is a mask of usages which it is allowed to delegate.
            cc.extended_key_usage = "serverAuth,clientAuth,OCSPSigning";

            std::tie(i_key, i_cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;
            p12.key = i_key.get();
            p12.cert = i_cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), root_cert.get()));
            p12.write("intermediateCA.p12");
        }

        // from this point, the EPICS Root Certificate Authority key is no longer needed.
        root_key.reset();

        // remaining certificates issued by intermediate.
        // extendedKeyUsage derived from name: client, server, or IOC (both client and server)
        for(const char *name : {"server1", "server2", "ioc1", "client1", "client2"}) {
            CertCreator cc;
            cc.root = root_cert.get();
            cc.CN = name;
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            if(strstr(name, "server"))
                cc.extended_key_usage = "serverAuth";
            else if(strstr(name, "client"))
                cc.extended_key_usage = "clientAuth";
            else if(strstr(name, "ioc"))
                cc.extended_key_usage = "clientAuth,serverAuth";
            cc.issuer = i_cert.get();
            cc.ikey = i_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;
            p12.key = key.get();
            p12.cert = cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), i_cert.get()));
            MUST(2, sk_X509_push(p12.cacerts.get(), root_cert.get()));
            std::string fname(SB()<<name<<".p12");

            const char *pw = "";
            if(strcmp(name, "client2")==0)
                pw = "oraclesucks"; // java keytool forces non-interactive IOCs to deal with passwords...

            p12.write(fname.c_str(), pw);
        }

        // ============================================================
        // Alternate certificate hierarchy for trust anchor mismatch tests
        // This creates an independent root CA that doesn't link to the main root
        // ============================================================

        // Alternate root certificate authority (independent from main root)
        pvxs::ossl_ptr<X509> alt_root_cert;
        pvxs::ossl_ptr<EVP_PKEY> alt_root_key;
        {
            CertCreator cc;
            cc.CN = "EPICS Alternate Root Certificate Authority";
            cc.serial = serial++;
            cc.isCA = true;
            cc.key_usage = "cRLSign,keyCertSign";

            std::tie(alt_root_key, alt_root_cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;

            // alt_cert_auth.p12 - contains only the alternate root CA (no keys)
            // Used for server-only auth tests where client trusts alternate root
            MUST(1, sk_X509_push(p12.cacerts.get(), alt_root_cert.get()));
            p12.write("alt_cert_auth.p12");
        }

        // Alternate intermediate certificate authority (signed by alt_root)
        pvxs::ossl_ptr<X509> alt_i_cert;
        pvxs::ossl_ptr<EVP_PKEY> alt_i_key;
        {
            CertCreator cc;
            cc.root = alt_root_cert.get();
            cc.CN = "alternateIntermediateCA";
            cc.serial = serial++;
            cc.issuer = alt_root_cert.get();
            cc.ikey = alt_root_key.get();
            cc.isCA = true;
            cc.key_usage = "digitalSignature,cRLSign,keyCertSign";
            cc.extended_key_usage = "serverAuth,clientAuth,OCSPSigning";

            std::tie(alt_i_key, alt_i_cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;
            p12.key = alt_i_key.get();
            p12.cert = alt_i_cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), alt_root_cert.get()));
            p12.write("alternateIntermediateCA.p12");
        }

        // Destroy alt root key - no longer needed, remaining certs signed by intermediate
        alt_root_key.reset();

        // Alternate server certificate (signed by alt_intermediate)
        {
            CertCreator cc;
            cc.root = alt_root_cert.get();
            cc.CN = "alt_server1";
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            cc.extended_key_usage = "serverAuth";
            cc.issuer = alt_i_cert.get();
            cc.ikey = alt_i_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;
            p12.key = key.get();
            p12.cert = cert.get();
            // Chain: alt_server1 -> alt_intermediate -> alt_root
            MUST(1, sk_X509_push(p12.cacerts.get(), alt_i_cert.get()));
            MUST(2, sk_X509_push(p12.cacerts.get(), alt_root_cert.get()));
            p12.write("alt_server1.p12");
        }

        // Alternate client certificate (signed by alt_intermediate)
        {
            CertCreator cc;
            cc.root = alt_root_cert.get();
            cc.CN = "alt_client1";
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            cc.extended_key_usage = "clientAuth";
            cc.issuer = alt_i_cert.get();
            cc.ikey = alt_i_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create();

            PKCS12Writer p12(outdir);
            p12.friendlyName = cc.CN;
            p12.key = key.get();
            p12.cert = cert.get();
            // Chain: alt_client1 -> alt_intermediate -> alt_root
            MUST(1, sk_X509_push(p12.cacerts.get(), alt_i_cert.get()));
            MUST(2, sk_X509_push(p12.cacerts.get(), alt_root_cert.get()));
            p12.write("alt_client1.p12");

            // alt_client1_with_main_root.p12 - entity cert with mismatched trust anchor
            // Used for testing "server rejects client" scenario:
            // - Client entity: alt_client1 (signed by alt_root)
            // - Client trust store: main_root (so client trusts server with main_root cert)
            // - Server rejects because its trust store (main_root) doesn't link to alt_client1's chain
            {
                PKCS12Writer p12_alt(outdir);
                p12_alt.friendlyName = cc.CN;
                p12_alt.key = key.get();
                p12_alt.cert = cert.get();
                // Client's trust store will be main_root
                // But entity cert is signed by alt_root, so server won't find a trust path
                MUST(1, sk_X509_push(p12_alt.cacerts.get(), root_cert.get()));
                p12_alt.write("alt_client1_with_main_root.p12");
            }
        }

        // ============================================================
        // Fake certificate hierarchy for name-matching attack tests
        // These certificates have the SAME CNs as the real certificates
        // but are signed by different (fake) CAs.
        // This tests that TLS verification is cryptographic, not just CN-based.
        // ============================================================

        // Fake root CA (completely independent, not trusted by real CAs)
        pvxs::ossl_ptr<X509> fake_root_cert;
        pvxs::ossl_ptr<EVP_PKEY> fake_root_key;
        {
            CertCreator cc;
            // Same CN as real root CA
            cc.CN = "EPICS Root Certificate Authority";
            cc.serial = serial++;
            cc.isCA = true;
            cc.key_usage = "cRLSign,keyCertSign";

            std::tie(fake_root_key, fake_root_cert) = cc.create();

            PKCS12Writer p12(outdir);
            static const char FAKE_PREFIX[] = "FAKE - ";
            static char fake_name[256];
            snprintf(fake_name, sizeof(fake_name), "%s%s", FAKE_PREFIX, cc.CN);
            p12.friendlyName = fake_name;
            p12.key = fake_root_key.get();
            p12.cert = fake_root_cert.get();

            // fake_cert_auth.p12 - contains only the fake root CA (no keys)
            // Used for testing that clients with fake CAs don't authenticate
            MUST(1, sk_X509_push(p12.cacerts.get(), fake_root_cert.get()));
            p12.write("fake_cert_auth.p12");
        }

        // Fake intermediate CA (signed by fake root, same CN as real intermediate)
        pvxs::ossl_ptr<X509> fake_i_cert;
        pvxs::ossl_ptr<EVP_PKEY> fake_i_key;
        {
            CertCreator cc;
            cc.root = fake_root_cert.get();
            // Same CN as real intermediate CA
            cc.CN = "intermediateCA";
            cc.serial = serial++;
            cc.issuer = fake_root_cert.get();
            cc.ikey = fake_root_key.get();
            cc.isCA = true;
            cc.key_usage = "digitalSignature,cRLSign,keyCertSign";
            cc.extended_key_usage = "serverAuth,clientAuth,OCSPSigning";

            std::tie(fake_i_key, fake_i_cert) = cc.create();

            PKCS12Writer p12(outdir);
            static const char FAKE_PREFIX[] = "FAKE - ";
            static char fake_name[256];
            snprintf(fake_name, sizeof(fake_name), "%s%s", FAKE_PREFIX, cc.CN);
            p12.friendlyName = fake_name;
            p12.key = fake_root_key.get();
            p12.cert = fake_root_cert.get();
            p12.key = fake_i_key.get();
            p12.cert = fake_i_cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), fake_root_cert.get()));
            p12.write("fake_intermediateCA.p12");
        }

        // Destroy fake root key - remaining certs signed by fake intermediate
        fake_root_key.reset();

        // Fake superserver certificate (signed by fake intermediate, same CN as real superserver)
        {
            CertCreator cc;
            cc.root = fake_root_cert.get();
            // Same CN as real superserver
            cc.CN = "superserver1";
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            cc.extended_key_usage = "serverAuth";
            cc.issuer = fake_i_cert.get();
            cc.ikey = fake_i_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create();

            PKCS12Writer p12(outdir);
            static const char FAKE_PREFIX[] = "FAKE - ";
            static char fake_name[256];
            snprintf(fake_name, sizeof(fake_name), "%s%s", FAKE_PREFIX, cc.CN);
            p12.friendlyName = fake_name;
            p12.key = fake_root_key.get();
            p12.cert = fake_root_cert.get();
            p12.key = key.get();
            p12.cert = cert.get();
            // Chain: fake_superserver1 -> fake_intermediate -> fake_root
            MUST(1, sk_X509_push(p12.cacerts.get(), fake_i_cert.get()));
            MUST(2, sk_X509_push(p12.cacerts.get(), fake_root_cert.get()));
            p12.write("fake_superserver1.p12");
        }

        // Fake server1 certificate (signed by fake intermediate, same CN as real server1)
        {
            CertCreator cc;
            cc.root = fake_root_cert.get();
            // Same CN as real server1
            cc.CN = "server1";
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            cc.extended_key_usage = "serverAuth";
            cc.issuer = fake_i_cert.get();
            cc.ikey = fake_i_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create();

            PKCS12Writer p12(outdir);
            static const char FAKE_PREFIX[] = "FAKE - ";
            static char fake_name[256];
            snprintf(fake_name, sizeof(fake_name), "%s%s", FAKE_PREFIX, cc.CN);
            p12.friendlyName = fake_name;
            p12.key = fake_root_key.get();
            p12.cert = fake_root_cert.get();
            p12.key = key.get();
            p12.cert = cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), fake_i_cert.get()));
            MUST(2, sk_X509_push(p12.cacerts.get(), fake_root_cert.get()));
            p12.write("fake_server1.p12");
        }

        // Fake client1 certificate (signed by fake intermediate, same CN as real client1)
        {
            CertCreator cc;
            cc.root = fake_root_cert.get();
            // Same CN as real client1
            cc.CN = "client1";
            cc.serial = serial++;
            cc.key_usage = "digitalSignature";
            cc.extended_key_usage = "clientAuth";
            cc.issuer = fake_i_cert.get();
            cc.ikey = fake_i_key.get();

            pvxs::ossl_ptr<X509> cert;
            pvxs::ossl_ptr<EVP_PKEY> key;
            std::tie(key, cert) = cc.create();

            PKCS12Writer p12(outdir);
            static const char FAKE_PREFIX[] = "FAKE - ";
            static char fake_name[256];
            snprintf(fake_name, sizeof(fake_name), "%s%s", FAKE_PREFIX, cc.CN);
            p12.friendlyName = fake_name;
            p12.key = fake_root_key.get();
            p12.cert = fake_root_cert.get();
            p12.key = key.get();
            p12.cert = cert.get();
            MUST(1, sk_X509_push(p12.cacerts.get(), fake_i_cert.get()));
            MUST(2, sk_X509_push(p12.cacerts.get(), fake_root_cert.get()));
            p12.write("fake_client1.p12");
        }

        return 0;
    }catch(std::exception& e){
        std::cerr<<"Error: "<<typeid(e).name()<<" : "<<e.what()<<"\n";
        return 1;
    }
}
