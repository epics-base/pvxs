/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The PVAccess Certificate Management Service.
 *
 *   pvacms
 *
 */

#include "pvacms.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <list>
#include <locale>
#include <memory>
#include <random>
#include <thread>
#include <tuple>

#include <epicsGetopt.h>
#include <epicsThread.h>
#include <epicsTime.h>
#include <epicsVersion.h>
#include <ifaddrs.h>
#include <osiProcess.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>

#include "certfactory.h"
#include "certmgmtservice.h"
#include "configcms.h"
#include "evhelper.h"
#include "keychainfactory.h"
#include "ownedptr.h"
#include "sqlite3.h"
#include "sqlite3ext.h"
#include "utilpvt.h"

DEFINE_LOGGER(pvacms, "pvxs.certs.cms");

namespace pvxs {
namespace certs {

const uint64_t k64BitOffset = 1ULL << 63;  // This is 2^63

// The current partition number
uint16_t partition_number = 0;

// The current number of partitions
uint16_t num_partitions = 1;

// The organization name to use for the pvacms cerrificate if it needs to be created
std::string pvacms_org_name;

// Forward decls

/**
 * @brief Reads command line options and sets corresponding variables.
 *
 * This function reads the command line options provided by the user and
 * sets the corresponding members in the given config. The options include
 * verbose mode, keychain file location, and a database file among others.
 *
 * @param config the configuration object to update with the commandline values
 * @param argc The number of command line arguments.
 * @param argv The array of command line arguments.
 * @param verbose Reference to a boolean variable to enable verbose mode.
 * @return 0 if successful, 1 if successful but need to exit immediately on
 * return, >1 if there is any error.
 */
int readOptions(ConfigCms &config, int argc, char *argv[], bool &verbose) {
    int opt;
    while ((opt = getopt(argc, argv, "a:c:d:hk:n:m:o:p:s:u:vV")) != -1) {
        switch (opt) {
            case 'a':
                config.ensureDirectoryExists(config.ca_acf_filename = optarg);
                break;
            case 'c':
                config.ensureDirectoryExists(config.ca_keychain_filename = optarg);
                break;
            case 'd':
                config.ensureDirectoryExists(config.ca_db_filename = optarg);
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            case 'k':
                config.ensureDirectoryExists(config.tls_keychain_filename = optarg);
                break;
            case 'n':
                config.ca_name = optarg;
                break;
            case 'm':
                pvacms_org_name = optarg;
                break;
            case 'o':
                config.ca_organization = optarg;
                break;
            case 'p': {
                std::string filepath = optarg;
                if (filepath == "-") {
                    config.ca_keychain_password = "";
                } else {
                    config.ensureDirectoryExists(filepath);
                    config.tls_keychain_password = config.getFileContents(filepath);
                }
            } break;
            case 's': {
                std::string filepath = optarg;
                if (filepath == "-") {
                    config.ca_keychain_password = "";
                } else {
                    config.ensureDirectoryExists(filepath);
                    config.ca_keychain_password = config.getFileContents(filepath);
                }
            } break;
            case 'u':
                config.ca_organizational_unit = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'V':
                std::cout << version_information;
                return 1;
            default:
                usage(argv[0]);
                std::cerr << "\nUnknown argument: " << char(opt) << std::endl;
                return 2;
        }
    }

    // Set default for organisation name
    if (config.ca_organization.empty()) {
        // Default the organisation to the hostname
        char hostname[PVXS_HOSTNAME_MAX];
        if (!!gethostname(hostname, PVXS_HOSTNAME_MAX)) {
            // If no hostname then try to get IP address
            strcpy(hostname, getIPAddress().c_str());
        }
        config.ca_organization = hostname;  // copy
    }
    if (pvacms_org_name.empty()) pvacms_org_name = config.ca_organization;

    // Override some PVACMS mandatory settings
    config.tls_stop_if_no_cert = true;
    config.tls_client_cert_required = ConfigCommon::Optional;

    return 0;
}

/**
 * @brief  The prototype of the returned data from a create certificate operation
 * @return  the prototype to use for create certificate operations
 */
Value getCreatePrototype() {
    using namespace members;
    return TypeDef(TypeCode::Struct,
                   {
                       Member(TypeCode::UInt64, "serial"),
                       Member(TypeCode::String, "issuer"),
                       Member(TypeCode::String, "certid"),
                       Member(TypeCode::String, "cert"),
                       Struct("alarm", "alarm_t",
                              {
                                  Int32("severity"),
                                  Int32("status"),
                                  String("message"),
                              }),
                   })
        .create();
}

Value getStatusPrototype() {
    using namespace members;
    return TypeDef(TypeCode::Struct,
                   {
                       Member(TypeCode::UInt8, "value"),
                       Member(TypeCode::UInt64, "serial"),
                       Struct("alarm", "alarm_t",
                              {
                                  Int32("severity"),
                                  Int32("status"),
                                  String("message"),
                              }),
                   })
        .create();
}

Value getRevokePrototype() { return nt::NTScalar{TypeCode::Bool}.create(); }

Value getPartitionPrototype() {
    return nt::NTTable{}
        .add_column(TypeCode::UInt64, "serial", "Serial Number")
        .add_column(TypeCode::String, "C", "Country")
        .add_column(TypeCode::String, "O", "Organization")
        .add_column(TypeCode::String, "OU", "Organizational Unit")
        .add_column(TypeCode::UInt32, "not_before", "Not Valid Before")
        .add_column(TypeCode::UInt32, "not_after", "Not Valid After")
        .add_column(TypeCode::UInt8, "status", "Status")
        .add_column(TypeCode::UInt32, "status_date", "Status Date")
        .create();
}

Value getScaleUpPrototype() { return nt::NTScalar{TypeCode::UInt16}.create(); }

Value getScaleDownPrototype() { return nt::NTScalar{TypeCode::UInt16}.create(); }

/**
 * @brief Initializes the certificates database by opening the specified
 * database file.
 *
 * @param ca_db A shared pointer to the SQLite database object.
 * @param db_file The path to the SQLite database file.
 *
 * @throws std::runtime_error if the database can't be opened or initialised
 */
void initCertsDatabase(sql_ptr &ca_db, std::string &db_file) {
    if ((sqlite3_open(db_file.c_str(), ca_db.acquire()) != SQLITE_OK)) {
        throw std::runtime_error(SB() << "Can't open certs db file: " << sqlite3_errmsg(ca_db.get()));
    } else {
        int rc = sqlite3_exec(ca_db.get(), SQL_CREATE_DB_FILE, 0, 0, 0);
        if (rc != SQLITE_OK && rc != SQLITE_DONE) {
            throw std::runtime_error(SB() << "Can't initialise certs db file: " << sqlite3_errmsg(ca_db.get()));
        }
    }
}

/**
 * @brief Retrieves the status of a certificate from the database.
 *
 * This function retrieves the status of a certificate with the given serial
 * number from the specified database.
 *
 * @param ca_db A reference to the SQLite database connection.
 * @param serial The serial number of the certificate.
 *
 * @return The status of the certificate.
 *
 * @throw std::runtime_error If there is an error preparing the SQL statement or
 * retrieving the certificate status.
 */
int getCertificateStatus(sql_ptr &ca_db, uint64_t serial) {
    int cert_status;
    uint64_t db_serial = serial - k64BitOffset;
    sqlite3_stmt *sql_statement;
    int sql_status;
    if ((sql_status = sqlite3_prepare_v2(ca_db.get(), SQL_CERT_STATUS, -1, &sql_statement, 0)) == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, 1, db_serial);

        if ((sql_status = sqlite3_step(sql_statement)) == SQLITE_ROW) {
            cert_status = sqlite3_column_int(sql_statement, 0);
        }
    }
    sqlite3_finalize(sql_statement);

    if (sql_status != SQLITE_ROW) {
        throw std::runtime_error(SB() << "Failed to get cert status: " << sqlite3_errmsg(ca_db.get()));
    }

    return cert_status;
}

/**
 * @brief Generates a random serial number.
 *
 * This function generates a random serial number using the Mersenne Twister
 * algorithm. The generated serial number is a 64-bit unsigned integer.
 *
 * @return The generated serial number.
 *
 * @note The random number generator is seeded with a random value from
 * hardware. It is important to note that the quality of the randomness may vary
 *       depending on the hardware and operating system.
 */
uint64_t generateSerial() {
    std::random_device random_from_device;                 // Obtain a random number from hardware
    std::mt19937_64 seed(random_from_device());            // Seed the generator
    std::uniform_int_distribution<uint64_t> distribution;  // Define the range

    uint64_t random_serial_number = distribution(seed);  // Generate a random number
    return random_serial_number;
}

/**
 * @brief Convert from ASN1_TIME found in certificates to time_t format
 * @param time the ASN1_TIME to convert
 *
 * @return the time_t representation of the given ASN1_TIME value
 */
time_t ASN1_TIME_to_time_t(ASN1_TIME *time) {
    BIO *bio;
    char read_time[256];
    struct tm tm;

    // Create a memory buffer BIO
    bio = BIO_new(BIO_s_mem());
    if (!bio) throw std::runtime_error("Failed to create a BIO");

    // Convert the time to readable form
    ASN1_TIME_print(bio, time);
    memset(read_time, 0, sizeof(read_time));

    // Read from BIO to string
    BIO_gets(bio, read_time, sizeof(read_time) - 1);
    BIO_free(bio);

    // Parse the string (e.g., "Feb 13 09:14:07 2019 GMT") to tm
    char *to_return = strptime(read_time, "%b %d %H:%M:%S %Y", &tm);
    if (to_return == NULL) {
        throw std::runtime_error("Failed to parse time from ASN1_TIME");
    }

    // Convert tm to time_t
    return mktime(&tm);
}

/**
 * @brief Store the certificate in the database
 *
 * This function stores the certificate details in the database provided
 *
 * @param[in] ca_db The SQL database connection
 * @param[in] cert_factory The certificate factory used to build the certificate
 *
 * @throws std::runtime_error If failed to create the certificate in the
 * database
 */
void storeCertificate(sql_ptr &ca_db, CertFactory &cert_factory) {
    auto db_serial = (int64_t)(cert_factory.serial_ - k64BitOffset);  // db stores as signed int so convert to and from

    sqlite3_stmt *sql_statement;
    auto current_time = std::time(nullptr);
    auto sql_status = sqlite3_prepare_v2(ca_db.get(), SQL_CREATE_CERT, -1, &sql_statement, NULL);
    if (sql_status == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, 1, db_serial);
        sqlite3_bind_text(sql_statement, 2, cert_factory.name_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, 3, cert_factory.country_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, 4, cert_factory.org_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, 5, cert_factory.org_unit_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(sql_statement, 6, (int)cert_factory.not_before_);
        sqlite3_bind_int(sql_statement, 7, (int)cert_factory.not_after_);
        sqlite3_bind_int(sql_statement, 8, VALID);
        sqlite3_bind_int(sql_statement, 9, (int)current_time);

        sql_status = sqlite3_step(sql_statement);
    }

    sqlite3_finalize(sql_statement);

    if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
        throw std::runtime_error(SB() << "Failed to create certificate: " << sqlite3_errmsg(ca_db.get()));
    }
}

/**
 * @brief The function that does the actual certificate creation in PVACMS
 *
 * Dont forget to cleanup `chain_ptr` after use with sk_X509_free()
 *
 * @param ca_db the database to write the certificate to
 * @param certificate_factory the certificate factory to use to build the certificate
 *
 * @return the PEM string that contains the Cert, its chain and the root cert
 */
ossl_ptr<X509> createCertificate(sql_ptr &ca_db, CertFactory &certificate_factory) {
    // Verify if there is an outstanding un-revoked certificate out there
    //    ensureCertificateDoesntAlreadyExist(name, country, organization,
    //    organization_unit);

    // Check validity falls within acceptable range
    if (certificate_factory.issuer_certificate_ptr_) ensureValidityCompatible(certificate_factory);

    auto certificate = certificate_factory.create();

    // Store certificate in database
    storeCertificate(ca_db, certificate_factory);

    // Print info about certificate creation
    std::string from = std::ctime(&certificate_factory.not_before_);
    std::string to = std::ctime(&certificate_factory.not_after_);
    std::cout
        << "--------------------------------------\n"
        << "X.509 "
        << (IS_USED_FOR_(certificate_factory.usage_, ssl::kForIntermediateCa)
                ? "INTERMEDIATE CA"
                : (IS_USED_FOR_(certificate_factory.usage_, ssl::kForClientAndServer)
                       ? "CLIENT & SERVER"
                       : (IS_USED_FOR_(certificate_factory.usage_, ssl::kForClient)
                              ? "CLIENT"
                              : (IS_USED_FOR_(certificate_factory.usage_, ssl::kForServer)
                                     ? "SERVER"
                                     : (IS_USED_FOR_(certificate_factory.usage_, ssl::kForCMS)
                                            ? "PVACMS"
                                            : (IS_USED_FOR_(certificate_factory.usage_, ssl::kForCa) ? "CA"
                                                                                                     : "STRANGE"))))))
        << " certificate \n"
        << "NAME: " << certificate_factory.name_ << "\n"
        << "ORGANIZATION: " << certificate_factory.org_ << "\n"
        << "ORGANIZATIONAL UNIT: " << certificate_factory.org_unit_ << "\n"
        << "VALIDITY: " << from.substr(0, from.size() - 1) << " to " << to.substr(0, to.size() - 1) << "\n"
        << "--------------------------------------\n\n";

    return certificate;
}

std::string createCertificatePemString(sql_ptr &ca_db, CertFactory &cert_factory) {
    ossl_ptr<X509> cert;

    cert = createCertificate(ca_db, cert_factory);

    // Write out as PEM string for return to client
    return CertFactory::certAndCasToPemString(cert, cert_factory.certificate_chain_.get());
}

/**
 * @brief  Get the issuer ID which is the first 8 hex digits of the hex SKI
 *
 * Note that the given cert must contain the ski extension in the first place
 *
 * @param ca_cert  the cert from which to get the subject key identifier extension
 * @return first 8 hex digits of the hex SKI
 */
std::string getIssuerId(const ossl_ptr<X509> &ca_cert) {
    ossl_ptr<ASN1_OCTET_STRING> skid(reinterpret_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(ca_cert.get(), NID_subject_key_identifier, nullptr, nullptr)));
    if(!skid.get()) {
        throw std::runtime_error("Failed to get Subject Key Identifier.");
    }

    // Convert first 8 chars to hex
    auto buf = const_cast<unsigned char*>(skid->data);
    std::stringstream ss;
    for (int i = 0; i < skid->length && ss.tellp() < 8; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
    }

    return ss.str();
}

/**
 * @brief CERT:CREATE Handles the creation of a certificate.
 *
 * This function handles the creation of a certificate based on the provided
 * certificate creation request (ccr). It extracts the necessary information
 * from the ccr, creates a reply containing the certificate data, and sends it
 * back to the client.
 *
 * @param pv The shared PV object.
 * @param operation The unique pointer to the execution operation.
 * @param ccr The certificate creation request (input) value.
 */
void rpcHandler(sql_ptr &ca_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&operation, Value &&args,
                const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key,
                const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    auto ccr = args["query"];
    auto type = ccr["type"].as<const std::string>();
    auto name = ccr["name"].as<const std::string>();
    auto organization = ccr["organization"].as<const std::string>();

    try {
        /*
                // Call the authenticator specific verifier if not the default type
                if (type.compare(PVXS_DEFAULT_AUTH_TYPE) != 0) {
                    const auto &authenticator = KeychainFactory::getAuth(type);
                    if (!authenticator->verify(ccr, [&ca_pub_key](const std::string &data, const std::string &signature)
           { return CertFactory::verifySignature(ca_pub_key, data, signature);
                        })) {
                        throw std::runtime_error("CCR claims are invalid");
                    }
                }
        */

        ///////////////////
        // Make Certificate
        ///////////////////

        // Get Public Key to use
        auto public_key = ccr["pub_key"].as<const std::string>();
        const std::shared_ptr<KeyPair> key_pair(new KeyPair(public_key));

        // Generate a new serial number
        auto serial = generateSerial();

        // Get other certificate parameters from request
        auto country = ccr["country"].as<const std::string>();
        auto organization_unit = ccr["organization_unit"].as<const std::string>();
        auto not_before = ccr["not_before"].as<time_t>();
        auto not_after = ccr["not_after"].as<time_t>();
        auto usage = ccr["usage"].as<uint16_t>();

        // Create a certificate factory
        auto certificate_factory =
            CertFactory(serial, key_pair, name, country, organization, organization_unit, not_before, not_after, usage,
                        ca_cert.get(), ca_pkey.get(), ca_chain.get());

        // Create the certificate using the certificate factory, store it in the database and return the PEM string
        auto pem_string = createCertificatePemString(ca_db, certificate_factory);

        // Construct and return the reply
        auto issuer_id = getIssuerId(ca_cert);
        auto reply(getCreatePrototype());
        reply["serial"] = serial;
        reply["issuer"] = issuer_id;
        reply["certid"] = (SB() << issuer_id << ":" << serial).str();
        reply["cert"] = pem_string;
        operation->reply(reply);
    } catch (std::exception &e) {
        // For any type of error return an error to the caller
        operation->error(SB() << "Failed to create certificate for " << NAME_STRING(name, organization) << ": "
                              << e.what());
    }
}

/**
 * @brief Get or create a CA certificate.
 *
 * Check to see if a CA certificate is located where the configuration
 * references it and check if it is valid.
 *
 * If not then create a new certificate and store it at the configured location.
 *
 * If the certificate is invalid then make a backup, notify the user, then
 * create a new one.  A PVACMS only creates certificates with validity that
 * is within the lifetime of the CA certificate so if the CA cert has expired,
 * all certificates it has signed will also have expired, and will need to be
 * replaced.
 *
 * @param config the config to use to get CA creation parameters if needed
 * @param ca_db the certificate database to write the CA to if needed
 * @param ca_cert the reference to the returned certificate
 * @param ca_pkey the reference to the private key of the returned certificate
 * @param ca_chain reference to the certificate chain of the returned cert
 */
void getOrCreateCaCertificate(ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    try {
        // Check if the CA certificates exist
        auto keychain_data =
            KeychainFactory::getKeychainDataFromKeychainFile(config.ca_keychain_filename, config.ca_keychain_password);
        ca_pkey = std::move(keychain_data.pkey);
        ca_cert = std::move(keychain_data.cert);
        ca_chain = keychain_data.ca;
    } catch (std::exception &e) {
        // Error getting certs file, or certs file invalid
        // Make A new CA Certificate
        try {
            log_warn_printf(pvacms, "%s\n", e.what());
            createCaCertificate(config, ca_db);
            auto keychain_data = KeychainFactory::getKeychainDataFromKeychainFile(config.ca_keychain_filename,
                                                                                  config.ca_keychain_password);
            ca_pkey = std::move(keychain_data.pkey);
            ca_cert = std::move(keychain_data.cert);
            ca_chain = keychain_data.ca;
        } catch (std::exception &e) {
            throw(std::runtime_error(SB() << "Error creating CA certificate: " << e.what()));
        }
    }
}

/**
 * @brief Ensure that the PVACMS server has a valid certificate.
 *
 * This will check whether the configured certificate exists, can be opened,
 * whether a p12 object can be read from it, and whether the p12 object
 * can be parsed to extract the private key, certificate and certificate chain.
 * Whether we can extract the root certificate from the certificate
 * chain and finally whether we can verify the integrity of the certificate
 *
 * If any of these checks fail this function will create a new certificate
 * at the location referenced in the config, using the configured values
 * as parameters.
 *
 * @param config the config to determine the location of the certificate
 * @param ca_db the database to store a new certificate if necessary
 * @param ca_cert the CA certificate to use as the issuer of this certificate
 * if necessary
 * @param ca_pkey the CA certificate's private key used to sign the new
 * certificate if necessary
 */
void ensureServerCertificateExists(ConfigCms config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert,
                                   ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    // Get location of keychain file and password if any
    const std::string &keychain_filename = config.tls_keychain_filename, &password = config.tls_keychain_password;
    log_debug_printf(pvacms, "keychain_filename (PKCS12) %s;%s\n", keychain_filename.c_str(),
                     password.empty() ? "" : " w/ password");

    // Get variable to test the keychain file validity
    file_ptr fp(fopen(keychain_filename.c_str(), "rb"), false);
    ossl_ptr<PKCS12> p12;
    ossl_ptr<EVP_PKEY> key;
    ossl_ptr<X509> cert;
    ossl_ptr<STACK_OF(X509)> CAs(sk_X509_new_null());
    std::string error_reason;

    if (!fp) {
        // Try to open the certificate file
        error_reason = SB() << "Server certificate file not found: " << keychain_filename;
    } else if (!d2i_PKCS12_fp(fp.get(), p12.acquire())) {
        // and get a p12 object from it
        error_reason = SB() << "Can't acquire p12 object from server certificate: " << keychain_filename;
    } else if (!PKCS12_parse(p12.get(), password.c_str(), key.acquire(), cert.acquire(), CAs.acquire())) {
        // and parse the p12 object
        // and extract the private key, certificate and certificate chain
        // and extract the root certificate from the chain
        error_reason = SB() << "Can't parse p12 object from server certificate: " << keychain_filename;
    } else {
        return;
    }

    // If any of those fail then create a new server certificate
    log_warn_printf(pvacms, "%s\n", error_reason.c_str());
    createServerCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain);
}

/**
 * @brief Create a CA certificate
 *
 * This function creates a CA certificate based on the configured parameters
 * and stores it in the given database as well as writing it out to the
 * configured keychain file protected by the optionally specified password.
 *
 * @param config the configuration to use to get CA creation parameters
 * @param ca_db the reference to the certificate database to write the CA to
 */
void createCaCertificate(ConfigCms &config, sql_ptr &ca_db) {
    // Generate a key pair for this cert
    const auto key_pair(KeychainFactory::createKeyPair());

    // Set validity to 4 yrs
    time_t not_before(time(nullptr));
    time_t not_after(not_before + (4 * 365 + 1) * 24 * 60 * 60);  // 4yrs

    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial, key_pair, config.ca_name, getCountryCode(), config.ca_organization,
                                           config.ca_organizational_unit, not_before, not_after, ssl::kForCa);

    auto pem_string = createCertificatePemString(ca_db, certificate_factory);

    // Create PKCS#12 file containing certs, private key and null chain
    KeychainFactory keychain_factory(config.ca_keychain_filename, config.ca_keychain_password, key_pair, pem_string);

    keychain_factory.writePKCS12File();

    // Create the root certificate (overwrite existing)
    // The user must re-trust it if it already existed
    keychain_factory.writeRootPemFile(pem_string, true);
}

/**
 * @brief Create a PVACMS server certificate
 * @param config the configuration use to get the parameters to create cert
 * @param ca_db the db to store the certificate in
 * @param ca_pkey the CA's private key to sign the certificate
 * @param ca_cert the CA certificate
 */
void createServerCertificate(const ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert,
                             ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    // Create a key pair
    const auto key_pair(KeychainFactory::createKeyPair());

    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory =
        CertFactory(serial, key_pair, PVXS_SERVICE_NAME, getCountryCode(), pvacms_org_name, PVXS_SERVICE_ORG_UNIT_NAME,
                    getNotBeforeTimeFromCert(ca_cert.get()), getNotAfterTimeFromCert(ca_cert.get()), ssl::kForCMS,
                    ca_cert.get(), ca_pkey.get(), ca_chain.get());

    auto cert = createCertificate(ca_db, certificate_factory);

    // Create PKCS#12 file containing certs, private key and null chain
    KeychainFactory keychain_factory(config.tls_keychain_filename, config.tls_keychain_password, key_pair, cert.get(),
                                     certificate_factory.certificate_chain_.get());

    keychain_factory.writePKCS12File();
}

/**
 * @brief Ensure that start and end dates are within the validity of issuer cert
 *
 * @param cert_factory the cert factory to check
 */
void ensureValidityCompatible(CertFactory &cert_factory) {
    time_t ca_not_before = getNotBeforeTimeFromCert(cert_factory.issuer_certificate_ptr_);
    time_t ca_not_after = getNotAfterTimeFromCert(cert_factory.issuer_certificate_ptr_);

    if (cert_factory.not_before_ < ca_not_before) {
        throw std::runtime_error("Not before time is before CA's not before time");
    }
    if (cert_factory.not_after_ > ca_not_after) {
        throw std::runtime_error("Not after time is after CA's not after time");
    }
}

/**
 * @brief Get the current country code of where the process is running
 * This returns the two letter country code.  It is always upper case.
 * For example for the United States it returns US, and for France, FR.
 *
 * @return the current country code of where the process is running
 */
std::string getCountryCode() {
    std::locale loc;
    auto country_code(loc.name().substr(0, 2));
    if (country_code == "C") return "";

    std::transform(country_code.begin(), country_code.end(), country_code.begin(), ::toupper);
    return country_code;
}

/**
 * @brief Get the not after time from the given certificate
 * @param cert the certificate to look at for the not after time
 *
 * @return the time_t representation of the not after time in the certificate
 */
time_t getNotAfterTimeFromCert(const X509 *cert) {
    ASN1_TIME *cert_not_after = X509_get_notAfter(cert);
    time_t not_after = ASN1_TIME_to_time_t(cert_not_after);
    return not_after;
}

/**
 * @brief Get the not before time from the given certificate
 * @param cert the certificate to look at for the not before time
 *
 * @return the time_t representation of the not before time in the certificate
 */
time_t getNotBeforeTimeFromCert(const X509 *cert) {
    ASN1_TIME *cert_not_before = X509_get_notBefore(cert);
    time_t not_before = ASN1_TIME_to_time_t(cert_not_before);
    return not_before;
}

/**
 * @brief Get the IP address of the current process' host.
 *
 * This will return the IP address based on the following rules.  It will
 * look through all the network interfaces and will skip local and self
 * assigned addresses.  Then it will select any public IP address.
 * if no public IP addresses are found then it will return
 * the first private IP address that it finds
 *
 * @return the IP address of the current process' host
 */
std::string getIPAddress() {
    struct ifaddrs *if_addr_struct = nullptr;
    struct ifaddrs *ifa;
    void *tmp_addr_ptr;
    std::string chosen_ip;
    std::string private_ip;

    getifaddrs(&if_addr_struct);

    std::regex local_address_pattern(R"(^(127\.)|(169\.254\.))");
    std::regex private_address_pattern(R"(^(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.))");

    for (ifa = if_addr_struct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // is a valid IPv4 Address
            tmp_addr_ptr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char address_buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmp_addr_ptr, address_buffer, INET_ADDRSTRLEN);

            // Skip local or self-assigned address. If it's a private address,
            // remember it.
            if (!std::regex_search(address_buffer, local_address_pattern)) {
                if (std::regex_search(address_buffer, private_address_pattern)) {
                    if (private_ip.empty()) {
                        private_ip = address_buffer;
                    }
                } else {
                    chosen_ip = address_buffer;
                    break;  // If a public address is found, exit the loop
                }
            }
        }
    }
    if (if_addr_struct != nullptr) freeifaddrs(if_addr_struct);

    // If no public IP addresses were found, use the first private IP that was
    // found.
    if (chosen_ip.empty()) {
        chosen_ip = private_ip;
    }

    return chosen_ip;
}

/**
 * @brief Prints the usage message for the program.
 *
 * This function prints the usage message for the program, including
 * the available command line options and their descriptions.
 *
 * @param argv0 The name of the program (usually argv[0]).
 */
void usage(const char *argv0) {
    std::cerr << "Usage: " << argv0
              << " -a <acf> <opts> \n"
                 "\n"
                 " -a <acf>             Access Security configuration file\n"
                 " -c <CA keychain file> Specify CA keychain file location\n"
                 "                      Overrides EPICS_CA_TLS_KEYCHAIN \n"
                 "                      environment variables.\n"
                 "                      Default ca.p12\n"
                 " -d <cert db file>    Specify keychain file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_KEYCHAIN \n"
                 "                      environment variable.\n"
                 "                      Default ca.p12\n"
                 " -h                   Show this message.\n"
                 " -k <keychain file>   Specify keychain file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_KEYCHAIN \n"
                 "                      environment variable.\n"
                 "                      Default server.p12\n"
                 " -n <ca_name>         To specify the CA's name if we need\n"
                 "                      to create a root certificate.\n"
                 "                      Defaults to the CA\n"
                 " -m <pvacms org>      To specify the pvacms organization name if \n"
                 "                      we need to create a server certificate.\n"
                 "                      Defaults to the name of this executable "
                 "(pvacms)\n"
                 " -o <ca_org>          To specify the CA's organization if we need\n"
                 "                      to create a root certificate.\n"
                 "                      Defaults to the hostname.\n"
                 "                      Use '-' to leave unset.\n"
                 " -p <password file>   Specify keychain password file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"
                 "\n"
                 "                      environment variable.\n"
                 "                      '-' sets no password\n"
                 " -s <CA secret file>  Specify CA keychain password file\n"
                 "                      Overrides EPICS_CA_PWD_FILE \n"
                 "                      environment variables.\n"
                 "                      '-' sets no password\n"
                 " -u <ca_org_unit>     To specify the CA's organizational unit\n"
                 " -v                   Make more noise.\n"
                 " -V                   Print version and exit.\n";
}

}  // namespace certs
}  // namespace pvxs

int main(int argc, char *argv[]) {
    using namespace pvxs::certs;
    using namespace pvxs::server;

    try {
        // Logger config from environment
        pvxs::logger_config_env();

        bool verbose = false;
        pvxs::sql_ptr ca_db;

        // Get config
        auto config = ConfigCms::fromEnv();

        // Read commandline options
        int exit_status;
        if ((exit_status = readOptions(config, argc, argv, verbose))) {
            return exit_status - 1;
        }

        // Initialise the certificates database
        initCertsDatabase(ca_db, config.ca_db_filename);

        // Get the CA Certificate
        pvxs::ossl_ptr<EVP_PKEY> ca_pkey;
        pvxs::ossl_ptr<X509> ca_cert;
        pvxs::ossl_shared_ptr<STACK_OF(X509)> ca_chain;

        // Get or create CA certificate
        getOrCreateCaCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain);

        // Create this PVACMS server's certificate if it does not already exist
        ensureServerCertificateExists(config, ca_db, ca_cert, ca_pkey, ca_chain);

        // Create the PVs
        SharedPV create_pv(SharedPV::buildReadonly());
        SharedPV revoke_pv(SharedPV::buildReadonly());
        SharedPV status_pv(SharedPV::buildReadonly());
        SharedPV partition_pv(SharedPV::buildMailbox());
        SharedPV partition_scale_up_pv(SharedPV::buildReadonly());
        SharedPV partition_scaled_up_pv(SharedPV::buildReadonly());
        SharedPV partition_scale_down_pv(SharedPV::buildReadonly());
        SharedPV partition_scaled_down_pv(SharedPV::buildReadonly());

        // RPC handlers
        // Create Certificate: args: ccr (certificate creation request)
        // Get public key of ca certificate
        pvxs::ossl_ptr<EVP_PKEY> ca_pub_key(X509_get_pubkey(ca_cert.get()));
        create_pv.onRPC([&ca_db, &ca_pkey, &ca_cert, &ca_pub_key, &ca_chain](
                            const SharedPV &create_pv, std::unique_ptr<ExecOp> &&operation, pvxs::Value &&args) {
            rpcHandler(ca_db, create_pv, std::move(operation), std::move(args), ca_pkey, ca_cert, ca_pub_key, ca_chain);
        });

        // Revoke Certificate: args: crr (certificate revocation request)
        revoke_pv.onRPC(
            [&ca_db](const SharedPV &revoke_pv, std::unique_ptr<ExecOp> &&operation, pvxs::Value &&args) {});

        // Certificate Status: CERT:STATUS:*
        // where * is any valid certificate serial number,
        // e.g. CERT:STATUS:123456789
        // First connect - set up initial value and
        // status_pv.onFirstConnect(
        //     [&ca_db, &status_pv](const server::SharedPV&
        //     partition_scale_up_pv) {
        //         // Work out what partition was called by examining the pv
        //         called
        //         // TODO don't know how to do this!!!! Assumes wildcard
        //            functionality in epics-base uint16_t partition_number

        //         // Calculate the
        //         Value initial_partition_set;  // = getPartition

        //         // Notify listening clients
        //         status_pv.open(initial_partition_set);
        //     });
        status_pv.onLastDisconnect([&ca_db, &status_pv](const SharedPV &partition_scale_up_pv) { status_pv.close(); });

        partition_pv.onFirstConnect([&ca_db](const SharedPV &partition_scale_up_pv) {});
        partition_scale_up_pv.onRPC([&ca_db](const SharedPV &partition_scale_up_pv, std::unique_ptr<ExecOp> &&operation,
                                             pvxs::Value &&args) {});
        partition_scale_up_pv.onRPC([&ca_db](const SharedPV &partition_scale_up_pv, std::unique_ptr<ExecOp> &&operation,
                                             pvxs::Value &&args) {});

        partition_scaled_up_pv.onRPC([&ca_db](const SharedPV &partition_scaled_up_pv,
                                              std::unique_ptr<ExecOp> &&operation, pvxs::Value &&args) {});

        partition_scale_down_pv.onRPC([&ca_db](const SharedPV &partition_scale_down_pv,
                                               std::unique_ptr<ExecOp> &&operation, pvxs::Value &&args) {});

        partition_scaled_down_pv.onRPC([&ca_db](const SharedPV &partition_scaled_down_pv,
                                                std::unique_ptr<ExecOp> &&operation, pvxs::Value &&args) {});

        // Data type for the PV.
        create_pv.open(getCreatePrototype());

        // Build server which will serve this PV
        Server pva_server = Server(config)
                                .addPV(RPC_CERT_CREATE, create_pv)
                                .addPV(RPC_CERT_REVOKE, revoke_pv)
                                .addPV(GET_CERT_STATUS, status_pv)
                                .addPV(GET_PARTITION, partition_pv)
                                .addPV(RPC_PARTITION_SCALEUP, partition_scale_up_pv)
                                .addPV(RPC_PARTITION_SCALEDUP, partition_scaled_up_pv)
                                .addPV(RPC_PARTITION_SCALEDOWN, partition_scale_down_pv)
                                .addPV(RPC_PARTITION_SCALEDDOWN, partition_scaled_down_pv);

        if (verbose)
            // Print the configuration this server is using
            std::cout << "Effective config\n" << config;
        std::cout << "PVACMS Running\n";

        // Start server and run forever, or until Ctrl+c is pressed.
        // Returns on SIGINT or SIGTERM
        pva_server.run();

        std::cout << "PVACMS Exiting\n";

        return 0;
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error: %s\n", e.what());
        return 1;
    }
}
