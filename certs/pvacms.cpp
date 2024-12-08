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
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <list>
#include <locale>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <tuple>
#include <vector>

#include <asDbLib.h>
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
#include <pvxs/sharedwildcardpv.h>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "configcms.h"
#include "evhelper.h"
#include "openssl.h"
#include "ownedptr.h"
#include "sqlite3.h"
#include "utilpvt.h"

DEFINE_LOGGER(pvacms, "pvxs.certs.cms");
DEFINE_LOGGER(pvacmsmonitor, "pvxs.certs.stat");
DEFINE_LOGGER(pvafms, "pvxs.certs.fms");

namespace pvxs {
namespace certs {

/**
 * @brief These are the cumulative total days in a year at the start of each month,
 *
 * for example:
 * January 1st is the 0th day of the year (month_start_days[0] = 0)
 * February 1st is the 31st day of the year (month_start_days[1] = 31)
 * March 1st is the 59th (month_start_days[2] = 59)
 * and so on.
 *
 * This array does not consider leap years
 */
static const std::string kCertRoot("CERT:ROOT");

// The current partition number
uint16_t partition_number = 0;

// The current number of partitions
uint16_t num_partitions = 1;

// The organization name to use for the pvacms cerrificate if it needs to be created
std::string pvacms_org_name;

// Forward decls

/**
 * @brief  The prototype of the returned data from a create certificate operation
 * @return  the prototype to use for create certificate operations
 */
Value getCreatePrototype() {
    using namespace members;
    nt::NTEnum enum_value;
    auto value = TypeDef(TypeCode::Struct,
                         {
                             enum_value.build().as("status"),
                             Member(TypeCode::UInt64, "serial"),
                             Member(TypeCode::String, "state"),
                             Member(TypeCode::String, "issuer"),
                             Member(TypeCode::String, "certid"),
                             Member(TypeCode::String, "statuspv"),
                             Member(TypeCode::String, "cert"),
                             Struct("alarm", "alarm_t",
                                    {
                                        Int32("severity"),
                                        Int32("status"),
                                        String("message"),
                                    }),
                         })
                     .create();
    shared_array<const std::string> choices(CERT_STATES);
    value["status.value.choices"] = choices.freeze();
    return value;
}

/**
 * @brief  The value for a GET root certificate operation
 * @return  The value for a GET root certificate operation
 */
Value getRootValue(const std::string &issuer_id, const ossl_ptr<X509> &ca_cert, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    using namespace members;
    auto value = TypeDef(TypeCode::Struct,
                         {
                             Member(TypeCode::UInt64, "serial"),
                             Member(TypeCode::String, "issuer"),
                             Member(TypeCode::String, "name"),
                             Member(TypeCode::String, "org"),
                             Member(TypeCode::String, "org_unit"),
                             Member(TypeCode::String, "cert"),
                             Struct("alarm", "alarm_t",
                                    {
                                        Int32("severity"),
                                        Int32("status"),
                                        String("message"),
                                    }),
                         })
                     .create();
    auto subject_name(X509_get_subject_name(ca_cert.get()));
    auto subject_string(X509_NAME_oneline(subject_name, nullptr, 0));
    ossl_ptr<char> owned_subject(subject_string, false);
    if (!owned_subject) {
        throw std::runtime_error("Unable to get the subject of the CA certificate");
    }
    std::string subject(owned_subject.get());

    // Subject part extractor
    auto extractSubjectPart = [&subject](const std::string &key) -> std::string {
        std::size_t start = subject.find("/" + key + "=");
        if (start == std::string::npos) {
            throw std::runtime_error("Key not found: " + key);
        }
        start += key.size() + 2;                     // Skip over "/key="
        std::size_t end = subject.find("/", start);  // Find the end of the current value
        if (end == std::string::npos) {
            end = subject.size();
        }
        return subject.substr(start, end - start);
    };

    value["serial"] = pvxs::certs::CertStatusFactory::getSerialNumber(ca_cert);
    value["issuer"] = issuer_id;
    value["name"] = extractSubjectPart("CN");
    value["org"] = extractSubjectPart("O");
    value["org_unit"] = extractSubjectPart("OU");
    value["cert"] = CertFactory::certAndCasToPemString(ca_cert, ca_chain.get());

    return value;
}

/**
 * @brief Reads command line options and sets corresponding variables.
 *
 * This function reads the command line options provided by the user and
 * sets the corresponding members in the given config. The options include
 * verbose mode, P12 file location, and a database file among others.
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
                config.ensureDirectoryExists(config.ca_cert_filename = optarg);
                break;
            case 'e':
                config.ensureDirectoryExists(config.ca_private_key_filename = optarg);
                break;
            case 'd':
                config.ensureDirectoryExists(config.ca_db_filename = optarg);
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            case 'k':
                config.ensureDirectoryExists(config.tls_cert_filename = optarg);
                break;
            case 'l':
                config.ensureDirectoryExists(config.tls_private_key_filename = optarg);
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
                    config.tls_cert_password = "";
                } else {
                    config.ensureDirectoryExists(filepath);
                    config.tls_cert_password = config.getFileContents(filepath);
                }
            } break;
            case 'q': {
                std::string filepath = optarg;
                if (filepath == "-") {
                    config.tls_private_key_password = "";
                } else {
                    config.ensureDirectoryExists(filepath);
                    config.tls_private_key_password = config.getFileContents(filepath);
                }
            } break;
            case 's': {
                std::string filepath = optarg;
                if (filepath == "-") {
                    config.ca_cert_password = "";
                } else {
                    config.ensureDirectoryExists(filepath);
                    config.ca_cert_password = config.getFileContents(filepath);
                }
            } break;
            case 't': {
                std::string filepath = optarg;
                if (filepath == "-") {
                    config.ca_private_key_password = "";
                } else {
                    config.ensureDirectoryExists(filepath);
                    config.ca_private_key_password = config.getFileContents(filepath);
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
std::tuple<certstatus_t, time_t> getCertificateStatus(sql_ptr &ca_db, uint64_t serial) {
    int cert_status = UNKNOWN;
    time_t status_date = std::time(nullptr);

    int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    if (sqlite3_prepare_v2(ca_db.get(), SQL_CERT_STATUS, -1, &sql_statement, 0) == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);

        if (sqlite3_step(sql_statement) == SQLITE_ROW) {
            cert_status = sqlite3_column_int(sql_statement, 0);
            status_date = sqlite3_column_int64(sql_statement, 1);
        }
    } else {
        sqlite3_finalize(sql_statement);
        throw std::logic_error(SB() << "failed to prepare sqlite statement: " << sqlite3_errmsg(ca_db.get()));
    }

    return std::make_tuple((certstatus_t)cert_status, status_date);
}

std::tuple<time_t, time_t> getCertificateValidity(sql_ptr &ca_db, uint64_t serial) {
    time_t not_before, not_after;

    int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    if (sqlite3_prepare_v2(ca_db.get(), SQL_CERT_VALIDITY, -1, &sql_statement, 0) == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);

        if (sqlite3_step(sql_statement) == SQLITE_ROW) {
            not_before = sqlite3_column_int64(sql_statement, 0);
            not_after = sqlite3_column_int64(sql_statement, 1);
        }
    } else {
        sqlite3_finalize(sql_statement);
        throw std::logic_error(SB() << "failed to prepare sqlite statement: " << sqlite3_errmsg(ca_db.get()));
    }

    return std::make_tuple(not_before, not_after);
}

/**
 * @brief Generates a SQL clause for filtering valid certificate statuses.
 *
 * This function takes a vector of CertStatus values and generates a SQL clause that can be used to filter
 * records with matching statuses. Each status value in the vector is converted into a parameterized condition in the clause.
 * The generated clause starts with "AND (" and ends with " )" and contains multiple "OR" conditions for each status value.
 *
 * @param valid_status The vector of CertStatus values to be filtered.
 * @return A string representing the SQL clause for filtering valid certificate statuses. If the vector is empty, an empty string is returned.
 */
std::string getValidStatusesClause(const std::vector<certstatus_t> valid_status) {
    auto n_valid_status = valid_status.size();
    if (n_valid_status > 0) {
        auto valid_status_clauses = SB();
        valid_status_clauses << " AND (";
        for (auto i = 0; i < n_valid_status; i++) {
            if (i != 0) valid_status_clauses << " OR";
            valid_status_clauses << " status = :status" << i;
        }
        valid_status_clauses << " )";
        return valid_status_clauses.str();
    }
    return "";
}

/**
 * Binds the valid certificate status clauses to the given SQLite statement.
 *
 * @param sql_statement The SQLite statement to bind the clauses to.
 * @param valid_status A vector containing the valid certificate status values.
 */
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<certstatus_t> valid_status) {
    auto n_valid_status = valid_status.size();
    for (auto i = 0; i < n_valid_status; i++) {
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, (SB() << ":status" << i).str().c_str()), valid_status[i]);
    }
}

/**
 * @brief Updates the status of a certificate in the certificates database.
 *
 * This function updates the status of a certificate in the certificates database.
 * The status is specified by the CertStatus enum. The function compares
 * the specified certificate's status with the valid_status vector to ensure that
 * only certificates that are already in one of those states are allowed to move
 * to the new status. If the existing status is valid, it updates the status of the
 * certificate associated with the specified serial number to the new status.
 *
 * @param ca_db A reference to the certificates database, represented as a sql_ptr object.
 * @param serial The serial number of the certificate to update.
 * @param cert_status The new status to set for the certificate.
 * @param valid_status A vector containing the valid status values that are allowed to transition a certificate from.
 *
 * @return None
 */
epicsMutex status_update_lock;
void updateCertificateStatus(sql_ptr &ca_db, uint64_t serial, certstatus_t cert_status, int approval_status, const std::vector<certstatus_t> valid_status) {
    int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    int sql_status;
    std::string sql(approval_status == -1 ? SQL_CERT_SET_STATUS : SQL_CERT_SET_STATUS_W_APPROVAL);
    sql += getValidStatusesClause(valid_status);
    auto current_time = std::time(nullptr);
    Guard G(status_update_lock);
    if ((sql_status = sqlite3_prepare_v2(ca_db.get(), sql.c_str(), -1, &sql_statement, 0)) == SQLITE_OK) {
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"), cert_status);
        if (approval_status >= 0) sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":approved"), approval_status);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        bindValidStatusClauses(sql_statement, valid_status);
        sql_status = sqlite3_step(sql_statement);
    }
    sqlite3_finalize(sql_statement);

    // Check the number of rows affected
    if (sql_status == SQLITE_DONE) {
        int rows_affected = sqlite3_changes(ca_db.get());
        if (rows_affected == 0) {
            throw std::runtime_error("No certificate found");
        }
    } else {
        throw std::runtime_error(SB() << "Failed to set cert status: " << sqlite3_errmsg(ca_db.get()));
    }
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
 * @brief Store the certificate in the database
 *
 * This function stores the certificate details in the database provided
 *
 * @param[in] ca_db The SQL database connection
 * @param[in] cert_factory The certificate factory used to build the certificate
 * @return effective certificate status stored
 *
 * @throws std::runtime_error If failed to create the certificate in the
 * database
 */
certstatus_t storeCertificate(sql_ptr &ca_db, CertFactory &cert_factory) {
    auto db_serial = *reinterpret_cast<int64_t *>(&cert_factory.serial_);  // db stores as signed int so convert to and from
    auto current_time = std::time(nullptr);
    auto effective_status = cert_factory.initial_status_ != VALID     ? cert_factory.initial_status_
                            : current_time < cert_factory.not_before_ ? PENDING
                            : current_time >= cert_factory.not_after_ ? EXPIRED
                                                                      : cert_factory.initial_status_;

    checkForDuplicates(ca_db, cert_factory);

    sqlite3_stmt *sql_statement;
    auto sql_status = sqlite3_prepare_v2(ca_db.get(), SQL_CREATE_CERT, -1, &sql_statement, NULL);
    if (sql_status == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":skid"), cert_factory.skid_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":CN"), cert_factory.name_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":O"), cert_factory.org_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":OU"), cert_factory.org_unit_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":C"), cert_factory.country_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":not_before"), (int)cert_factory.not_before_);
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":not_after"), (int)cert_factory.not_after_);
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"), effective_status);
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":approved"), cert_factory.initial_status_ == VALID ? 1 : 0);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);

        sql_status = sqlite3_step(sql_statement);
    }

    sqlite3_finalize(sql_statement);

    if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
        throw std::runtime_error(SB() << "Failed to create certificate: " << sqlite3_errmsg(ca_db.get()));
    }
    return effective_status;
}

/**
 * @brief Checks for duplicates between certificates in the given database and the certificate that will be generated by the given certificate factory.
 *
 * This function takes a reference to a `sql_ptr` object representing a database
 * and a reference to a `CertFactory` object. It checks for duplicates in the
 * database by comparing the subject of the certificate that would be generated by the
 * certificate factory with the ones in the database and by comparing the subject key identifier
 * that would be produced by the certificate factory with any that are already present in the
 * database. If any duplicates are found, they are handled according
 * to the specified business logic.
 *
 * Certificates that are pending and pending approval are also included.  So a new certificate
 * that matches any certificates that are not yet valid (pending) or are awaiting
 * administrator approval (pending approval) will be rejected.
 *
 * @param ca_db A reference to a `sql_ptr` object representing the database to check for duplicates.
 * @param cert_factory A reference to a `CertFactory` object containing the certificate configuration to compare against the database.
 *
 * @return void
 *
 * @remark This function assumes that the database and certificate factory objects are properly initialized and accessible.
 *    It does not handle any exceptions or errors that might occur during the duplicate checking process.
 *    Users of this function should ensure that any required error handling and exception handling is implemented accordingly.
 */
void checkForDuplicates(sql_ptr &ca_db, CertFactory &cert_factory) {
    // Prepare SQL statements
    sqlite3_stmt *sql_statement;

    const std::vector<certstatus_t> valid_status{VALID, PENDING_APPROVAL, PENDING};

    // Check for duplicate subject
    std::string subject_sql(SQL_DUPS_SUBJECT);
    subject_sql += getValidStatusesClause(valid_status);
    if (sqlite3_prepare_v2(ca_db.get(), subject_sql.c_str(), -1, &sql_statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":CN"), cert_factory.name_.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":O"), cert_factory.org_.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":OU"), cert_factory.org_unit_.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":C"), cert_factory.country_.c_str(), -1, SQLITE_STATIC);
    bindValidStatusClauses(sql_statement, valid_status);
    auto subject_dup_status = sqlite3_step(sql_statement) == SQLITE_ROW && sqlite3_column_int(sql_statement, 0) > 0;
    sqlite3_finalize(sql_statement);
    if (subject_dup_status) {
        throw std::runtime_error(SB() << "Duplicate Certificate Subject: cn=" << cert_factory.name_ << ", o=" << cert_factory.org_
                                      << ", ou=" << cert_factory.org_unit_ << ", c=" << cert_factory.country_);
    }

    // Check for duplicate SKID
    std::string subject_key_sql(SQL_DUPS_SUBJECT_KEY_IDENTIFIER);
    subject_key_sql += getValidStatusesClause(valid_status);
    if (sqlite3_prepare_v2(ca_db.get(), subject_key_sql.c_str(), -1, &sql_statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":skid"), cert_factory.skid_.c_str(), -1, SQLITE_STATIC);
    bindValidStatusClauses(sql_statement, valid_status);

    auto skid_dup_status = sqlite3_step(sql_statement) == SQLITE_ROW && sqlite3_column_int(sql_statement, 0) > 0;
    sqlite3_finalize(sql_statement);
    if (skid_dup_status) {
        throw std::runtime_error("Duplicate Certificate Subject Key Identifier.  Use a distinct Key-Pair for each certificate");
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
    auto effective_status = storeCertificate(ca_db, certificate_factory);

    // Print info about certificate creation
    std::string from = std::ctime(&certificate_factory.not_before_);
    std::string to = std::ctime(&certificate_factory.not_after_);

    log_info_printf(pvacms, "--------------------------------------%s", "\n");
    auto cert_description = (SB() << "X.509 "
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
                                                                      : (IS_USED_FOR_(certificate_factory.usage_, ssl::kForCa) ? "CA" : "STRANGE"))))))
                                  << " certificate")
                                .str();
    log_info_printf(pvacms, "%s\n", cert_description.c_str());
    log_info_printf(
        pvacms, "%s\n",
        (SB() << "CERT_ID: " << getCertId(CertStatus::getIssuerId(certificate_factory.issuer_certificate_ptr_), certificate_factory.serial_)).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "NAME: " << certificate_factory.name_).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "ORGANIZATION: " << certificate_factory.org_).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "ORGANIZATIONAL UNIT: " << certificate_factory.org_unit_).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "STATUS: " << CERT_STATE(effective_status)).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "VALIDITY: " << from.substr(0, from.size() - 1) << " to " << to.substr(0, to.size() - 1)).str().c_str());
    log_info_printf(pvacms, "--------------------------------------%s", "\n");

    return certificate;
}

/**
 * @brief Creates a PEM string representation of a certificate.
 *
 * This function creates a PEM string representation of a certificate by creating the certificate using the provided
 * CA database and certificate factory, and then converting the certificate and CA chain to PEM format.
 *
 * @param ca_db The CA database.
 * @param cert_factory The certificate factory.
 * @return A PEM string representation of the certificate.
 */
std::string createCertificatePemString(sql_ptr &ca_db, CertFactory &cert_factory) {
    ossl_ptr<X509> cert;

    cert = createCertificate(ca_db, cert_factory);

    // Write out as PEM string for return to client
    return CertFactory::certAndCasToPemString(cert, cert_factory.certificate_chain_.get());
}

/**
 * This function is used to retrieve the value of a specified field from a given structure.
 *
 * @param src The structure from which to retrieve the field value.
 * @param field The name of the field whose value should be retrieved.
 * @return The value of the specified field in the given structure.
 *
 * @note This function assumes that the specified field exists in the structure and can be accessed using the dot notation.
 * @warning If the specified field does not exist or cannot be accessed, the function will throw a field not found exception.
 * @attention This function does not modify the given structure or its fields.
 * @see setStructureValue()
 */
template <typename T>
T getStructureValue(const Value &src, const std::string &field) {
    auto value = src[field];
    if (!value) {
        throw std::runtime_error(SB() << field << " field not provided");
    }
    return value.as<T>();
}

bool getPriorApprovalStatus(sql_ptr &ca_db, std::string &name, std::string &country, std::string &organization, std::string &organization_unit) {
    // Check for duplicate subject
    sqlite3_stmt *sql_statement;
    bool previously_approved{false};

    std::string approved_sql(SQL_PRIOR_APPROVAL_STATUS);
    if (sqlite3_prepare_v2(ca_db.get(), approved_sql.c_str(), -1, &sql_statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":CN"), name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":O"), organization.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":OU"), organization_unit.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":C"), country.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(sql_statement) == SQLITE_ROW) {
        previously_approved = sqlite3_column_int(sql_statement, 0) == 1;
    }

    return previously_approved;
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
 * @param op The unique pointer to the execution operation.
 * @param ccr The certificate creation request (input) value.
 */
void onCreateCertificate(ConfigCms &config, sql_ptr &ca_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args,
                         const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key,
                         const ossl_shared_ptr<STACK_OF(X509)> &ca_chain, std::string issuer_id) {
    auto ccr = args["query"];

    auto type = getStructureValue<const std::string>(ccr, "type");
    auto name = getStructureValue<const std::string>(ccr, "name");
    auto organization = getStructureValue<const std::string>(ccr, "organization");

    try {
        certstatus_t state = UNKNOWN;
        // Call the authenticator specific verifier if not the default type
        if (type.compare(PVXS_DEFAULT_AUTH_TYPE) != 0) {
            /*
                        const auto &authenticator = KeychainFactory::getAuth(type);
                        if (!authenticator->verify(ccr,
                                                   [&ca_pub_key](const std::string &data,
                                                                 const std::string &signature) {
                                                       return CertFactory::verifySignature(
                                                         ca_pub_key,
                                                         data,
                                                         signature);
                                                   })) {
                            throw std::runtime_error("CCR claims are invalid");
                        }
            */
            state = VALID;
        } else {
            state = PENDING_APPROVAL;
        }

        ///////////////////
        // Make Certificate
        ///////////////////

        // Get Public Key to use
        auto public_key = getStructureValue<const std::string>(ccr, "pub_key");
        const auto key_pair = std::make_shared<KeyPair>(public_key);

        // Generate a new serial number
        auto serial = generateSerial();

        // Get other certificate parameters from request
        auto country = getStructureValue<const std::string>(ccr, "country");
        auto organization_unit = getStructureValue<const std::string>(ccr, "organization_unit");
        auto not_before = getStructureValue<time_t>(ccr, "not_before");
        auto not_after = getStructureValue<time_t>(ccr, "not_after");
        auto usage = getStructureValue<uint16_t>(ccr, "usage");

        // If pending approval then check if it has already been approved
        if (state == PENDING_APPROVAL) {
            if (getPriorApprovalStatus(ca_db, name, country, organization, organization_unit)) {
                state = VALID;
            }
        }

        // Create a certificate factory
        auto certificate_factory = CertFactory(serial, key_pair, name, country, organization, organization_unit, not_before, not_after, usage,
                                               config.cert_status_subscription, ca_cert.get(), ca_pkey.get(), ca_chain.get(), state);

        // Create the certificate using the certificate factory, store it in the database and return the PEM string
        auto pem_string = createCertificatePemString(ca_db, certificate_factory);

        // Construct and return the reply
        auto cert_id = getCertId(issuer_id, serial);
        auto status_pv = getCertUri(GET_MONITOR_CERT_STATUS_ROOT, cert_id);
        auto reply(getCreatePrototype());
        auto now(time(nullptr));
        reply["status.value.index"] = state;
        reply["status.timeStamp.secondsPastEpoch"] = now;
        reply["state"] = CERT_STATE(state);
        reply["serial"] = serial;
        reply["issuer"] = issuer_id;
        reply["certid"] = cert_id;
        reply["statuspv"] = status_pv;
        reply["cert"] = pem_string;
        op->reply(reply);
    } catch (std::exception &e) {
        // For any type of error return an error to the caller
        auto cert_name = NAME_STRING(name, organization);
        log_err_printf(pvacms, "Failed to create certificate for %s: %s\n", cert_name.c_str(), e.what());
        op->error(SB() << "Failed to create certificate for " << cert_name << ": " << e.what());
    }
}

/**
 * Retrieves the status of the certificate identified by the pv_name.  Only called first time
 *
 * @param ca_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The SharedWildcardPV object to store the retrieved status.
 * @param pv_name The status pv requested.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param ca_pkey The CA's private key.
 * @param ca_cert The CA's certificate.
 * @param ca_chain The CA's certificate chain.
 *
 * @return void
 */
void onGetStatus(ConfigCms &config, sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, const std::string &pv_name,
                 const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
                 const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    uint64_t serial = 0;
    static auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        std::string issuer_id;
        std::tie(issuer_id, serial) = getParameters(parameters);
        log_debug_printf(pvacms, "GET STATUS: Certificate %s:%llu\n", issuer_id.c_str(), serial);

        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        // get status value
        certstatus_t status;
        time_t status_date;
        std::tie(status, status_date) = certs::getCertificateStatus(ca_db, serial);
        if (status == UNKNOWN) {
            throw std::runtime_error("Unable to determine certificate status");
        }

        auto now = std::time(nullptr);
        auto cert_status = cert_status_creator.createPVACertificateStatus(serial, status, now, status_date);
        postCertificateStatus(status_pv, pv_name, serial, cert_status);
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error getting status: %s\n", e.what());
        postCertificateStatus(status_pv, pv_name, serial);
    }
}

/**
 * Revokes the certificate identified by the pv_name
 *
 * @param ca_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The SharedWildcardPV object to update the status in.
 * @param op
 * @param pv_name The status PV to be updated to REVOKED.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param ca_pkey The CA's private key.
 * @param ca_cert The CA's certificate.
 * @param ca_chain The CA's certificate chain.
 *
 * @return void
 */
void onRevoke(ConfigCms &config, sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
              const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
              const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    static auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        std::string issuer_id;
        uint64_t serial;
        std::tie(issuer_id, serial) = getParameters(parameters);
        log_debug_printf(pvacms, "REVOKE: Certificate %s:%llu\n", issuer_id.c_str(), serial);

        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        // set status value
        certs::updateCertificateStatus(ca_db, serial, REVOKED, 0);

        auto revocation_date = std::time(nullptr);
        auto ocsp_status = cert_status_creator.createPVACertificateStatus(serial, REVOKED, revocation_date, revocation_date);
        postCertificateStatus(status_pv, pv_name, serial, ocsp_status);
        log_info_printf(pvacms, "Certificate %s:%llu has been REVOKED\n", issuer_id.c_str(), serial);
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error revoking certificate: %s\n", e.what());
        op->error(SB() << "Error revoking certificate: " << e.what());
    }
}

/**
 * Approves the certificate identified by the pv_name
 *
 * @param ca_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The SharedWildcardPV object to update the status in.
 * @param op
 * @param pv_name The status PV to be updated to APPROVED.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param ca_pkey The CA's private key.
 * @param ca_cert The CA's certificate.
 * @param ca_chain The CA's certificate chain.
 *
 * @return void
 */
void onApprove(ConfigCms &config, sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
               const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
               const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    static auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        std::string issuer_id;
        uint64_t serial;
        std::tie(issuer_id, serial) = getParameters(parameters);
        log_debug_printf(pvacms, "APPROVE: Certificate %s:%llu\n", issuer_id.c_str(), serial);

        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        // set status value
        auto status_date(time(nullptr));
        time_t not_before, not_after;
        std::tie(not_before, not_after) = getCertificateValidity(ca_db, serial);
        certstatus_t new_state = status_date < not_before ? PENDING : status_date >= not_after ? EXPIRED : VALID;
        certs::updateCertificateStatus(ca_db, serial, new_state, 1, {PENDING_APPROVAL});

        auto cert_status = cert_status_creator.createPVACertificateStatus(serial, new_state, status_date);
        postCertificateStatus(status_pv, pv_name, serial, cert_status);
        switch (new_state) {
            case VALID:
                log_info_printf(pvacms, "Certificate %s:%llu has been APPROVED\n", issuer_id.c_str(), serial);
                break;
            case EXPIRED:
                log_info_printf(pvacms, "Certificate %s:%llu has EXPIRED\n", issuer_id.c_str(), serial);
                break;
            case PENDING:
                log_info_printf(pvacms, "Certificate %s:%llu is now PENDING\n", issuer_id.c_str(), serial);
                break;
            default:
                break;
        }
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error approving certificate: %s\n", e.what());
        op->error(SB() << "Error approving certificate: " << e.what());
    }
}

/**
 * Denies the pending the certificate identified by the pv_name
 *
 * @param ca_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The SharedWildcardPV object to update the status in.
 * @param op
 * @param pv_name The status PV to be updated to DENIED.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param ca_pkey The CA's private key.
 * @param ca_cert The CA's certificate.
 * @param ca_chain The CA's certificate chain.
 *
 * @return void
 */
void onDeny(ConfigCms &config, sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
            const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
            const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    static auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        std::string issuer_id;
        uint64_t serial;
        std::tie(issuer_id, serial) = getParameters(parameters);
        log_debug_printf(pvacms, "DENY: Certificate %s:%llu\n", issuer_id.c_str(), serial);

        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        // set status value
        certs::updateCertificateStatus(ca_db, serial, REVOKED, 0, {PENDING_APPROVAL});

        auto revocation_date = std::time(nullptr);
        auto cert_status = cert_status_creator.createPVACertificateStatus(serial, REVOKED, revocation_date, revocation_date);
        postCertificateStatus(status_pv, pv_name, serial, cert_status);
        log_info_printf(pvacms, "Certificate %s:%llu request has been DENIED\n", issuer_id.c_str(), serial);
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error denying certificate request: %s\n", e.what());
        op->error(SB() << "Error denying certificate request: " << e.what());
    }
}

std::tuple<std::string, uint64_t> getParameters(const std::list<std::string> &parameters) {
    // get serial and issuer from URI parameters
    auto it = parameters.begin();
    const std::string &issuer_id = *it;

    const std::string &serial_string = *++it;
    uint64_t serial;
    try {
        serial = std::stoull(serial_string);
    } catch (const std::invalid_argument &e) {
        throw std::runtime_error(SB() << "Conversion error: Invalid argument. Serial in PV name is not a number: " << serial_string);
    } catch (const std::out_of_range &e) {
        throw std::runtime_error(SB() << "Conversion error: Out of range. Serial is too large: " << serial_string);
    }

    return std::make_tuple(issuer_id, serial);
}

/**
 * @brief Get or create a CA certificate.
 *
 * Check to see if a CA key and certificate are located where the configuration
 * references them and check if they are valid.
 *
 * If not then create a new key and/or certificate and store them at the configured locations.
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
    // Get key pair if specified
    std::shared_ptr<KeyPair> key_pair;
    try {
        if (!config.ca_private_key_filename.empty()) {
            // Check if the CA key exists
            key_pair = IdFileFactory::create(config.ca_private_key_filename, config.ca_private_key_password)->getKeyFromFile();
        }
    } catch (std::exception &e) {
        // Error getting key pair
        // Make a new key pair file
        try {
            log_warn_printf(pvafms, "%s\n", e.what());
            key_pair = createCaKey(config);
        } catch (std::exception &e) {
            throw(std::runtime_error(SB() << "Error creating CA key: " << e.what()));
        }
    }

    // At this point if a separate key was configured then we will have one, or we will have thrown an exception
    // If we don't have one then it's because it was configured to be in the same file as the certificate

    // Get certificate
    try {
        // Check if the CA certificates exist
        auto cert_data = IdFileFactory::create(config.ca_cert_filename, config.ca_cert_password)->getCertDataFromFile();
        if (!key_pair) key_pair = cert_data.key_pair;

        // If we have a key
        if (key_pair) {
            // And we have a cert
            if (cert_data.cert) {
                // all is ok
                ca_pkey = std::move(key_pair->pkey);
                ca_cert = std::move(cert_data.cert);
                ca_chain = cert_data.ca;
                return;
            }
            // We have keys but no cert then create the cert file
            throw(std::runtime_error("Certificate file does not contain a certificate: "));
        }
        // We don't have keys so create a key in a combined cert and key file
        key_pair = IdFileFactory::createKeyPair();
        throw(std::runtime_error("Certificate file does not contain a certificate: "));
    } catch (std::exception &e) {
        // Error getting certs file, or certs file invalid
        // Make a new CA Certificate
        try {
            log_warn_printf(pvafms, "%s\n", e.what());
            if (!key_pair) key_pair = IdFileFactory::createKeyPair();

            auto cert_data = createCaCertificate(config, ca_db, key_pair);
            // all is ok
            ca_pkey = std::move(key_pair->pkey);
            ca_cert = std::move(cert_data.cert);
            ca_chain = cert_data.ca;
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
void ensureServerCertificateExists(ConfigCms config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    // Get key pair if specified
    std::shared_ptr<KeyPair> key_pair;
    try {
        if (!config.tls_private_key_filename.empty()) {
            // Check if the server key pair exists
            key_pair = IdFileFactory::create(config.tls_private_key_filename, config.tls_private_key_password)->getKeyFromFile();
        }
    } catch (std::exception &e) {
        // Error getting key pair
        // Make a new key pair file
        try {
            log_warn_printf(pvacms, "%s\n", e.what());
            key_pair = createServerKey(config);
        } catch (std::exception &e) {
            throw(std::runtime_error(SB() << "Error creating server key: " << e.what()));
        }
    }

    // At this point if a separate key was configured then we will have one, or we will have thrown an exception
    // If we don't have one then it's because it was configured to be in the same file as the certificate

    // Get certificate
    try {
        // Check if the server certificates exist
        auto cert_data = IdFileFactory::create(config.tls_cert_filename, config.tls_cert_password)->getCertDataFromFile();
        if (!key_pair) key_pair = cert_data.key_pair;

        // If we have a key
        if (key_pair) {
            // And we have a cert
            if (cert_data.cert) {
                // all is ok
                return;
            }
            // We don't have keys so create a key in a combined cert and key file
            throw(std::runtime_error("Certificate file does not contain a certificate: "));
        }
        throw(std::runtime_error("Certificate file does not contain a private key: "));
    } catch (std::exception &e) {
        // Error getting certs file, or certs file invalid
        // Make a new server Certificate
        try {
            log_warn_printf(pvacms, "%s\n", e.what());
            if (!key_pair) key_pair = IdFileFactory::createKeyPair();

            createServerCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain, key_pair);
            // All is ok
        } catch (std::exception &e) {
            throw(std::runtime_error(SB() << "Error creating server certificate: " << e.what()));
        }
    }
}

std::shared_ptr<KeyPair> createCaKey(ConfigCms &config) {
    // Create a key pair
    const auto key_pair = IdFileFactory::createKeyPair();

    // Create key file containing private key
    IdFileFactory::create(config.ca_private_key_filename,
                          config.ca_private_key_password,
                          key_pair)->writeIdentityFile();
    return key_pair;
}

/**
 * @brief Create a CA certificate
 *
 * This function creates a CA certificate based on the configured parameters
 * and stores it in the given database as well as writing it out to the
 * configured P12 file protected by the optionally specified password.
 *
 * @param config the configuration to use to get CA creation parameters
 * @param ca_db the reference to the certificate database to write the CA to
 * @param key_pair the key pair to use for the certificate
 * @return a cert data structure containing the cert and chain and a copy of the key
 */
CertData createCaCertificate(ConfigCms &config, sql_ptr &ca_db, std::shared_ptr<KeyPair> &key_pair) {
    // Set validity to 4 yrs
    time_t not_before(time(nullptr));
    time_t not_after(not_before + (4 * 365 + 1) * 24 * 60 * 60);  // 4yrs

    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial, key_pair, config.ca_name, getCountryCode(), config.ca_organization, config.ca_organizational_unit,
                                           not_before, not_after, ssl::kForCa, config.cert_status_subscription);

    auto pem_string = createCertificatePemString(ca_db, certificate_factory);

    // Create PKCS#12 file containing certs, private key and chain
    auto cert_file_factory = IdFileFactory::create(config.ca_cert_filename, config.ca_cert_password, key_pair, nullptr, nullptr, "certificate", pem_string,
                                                   !config.ca_private_key_filename.empty());

    cert_file_factory->writeIdentityFile();

    // Create the root certificate (overwrite existing)
    // The user must re-trust it if it already trusted
    if (!cert_file_factory->writeRootPemFile(pem_string, true)) {
        exit(0);
    }
    return cert_file_factory->getCertData(key_pair);
}

/**
 * @brief Create a PVACMS server key
 * @param config the configuration use to get the parameters to create cert
 */
std::shared_ptr<KeyPair> createServerKey(const ConfigCms &config) {
    // Create a key pair
    const auto key_pair(IdFileFactory::createKeyPair());

    // Create PKCS#12 file containing private key
    IdFileFactory::create(config.tls_private_key_filename,
                          config.tls_private_key_password,
                          key_pair)->writeIdentityFile();
    return key_pair;
}

/**
 * @brief Create a PVACMS server certificate
 *
 * If private key file is configured then don't add key to cert file
 *
 * @param config the configuration use to get the parameters to create cert
 * @param ca_db the db to store the certificate in
 * @param ca_pkey the CA's private key to sign the certificate
 * @param ca_cert the CA certificate
 * @param ca_chain the CA certificate chain
 * @param key_pair the key pair to use to create the certificate
 */
void createServerCertificate(const ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &ca_chain, std::shared_ptr<KeyPair> &key_pair) {
    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory =
        CertFactory(serial, key_pair, PVXS_SERVICE_NAME, getCountryCode(), pvacms_org_name, PVXS_SERVICE_ORG_UNIT_NAME, getNotBeforeTimeFromCert(ca_cert.get()),
                    getNotAfterTimeFromCert(ca_cert.get()), ssl::kForCMS, config.cert_status_subscription, ca_cert.get(), ca_pkey.get(), ca_chain.get());

    auto cert = createCertificate(ca_db, certificate_factory);

    // Create PKCS#12 file containing certs, private key and null chain
    auto pem_string = CertFactory::certAndCasToPemString(cert, certificate_factory.certificate_chain_.get());
    auto cert_file_factory = IdFileFactory::create(config.tls_cert_filename, config.tls_cert_password, key_pair, nullptr, nullptr,
                                                   "PVACMS server certificate", pem_string, !config.tls_private_key_filename.empty());

    cert_file_factory->writeIdentityFile();
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
    time_t not_after = StatusDate::asn1TimeToTimeT(cert_not_after);
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
    time_t not_before = StatusDate::asn1TimeToTimeT(cert_not_before);
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
                 " -c <CA P12 file>     Specify CA certificate file location\n"
                 "                      Overrides EPICS_CA_TLS_KEYCHAIN \n"
                 "                      environment variables.\n"
                 "                      Default ca.p12\n"
                 " -e <CA key file>     Specify CA private key file location\n"
                 "                      Overrides EPICS_CA_TLS_PKEY \n"
                 "                      environment variables.\n"
                 " -d <cert db file>    Specify cert db file location\n"
                 "                      Overrides EPICS_CA_DB \n"
                 "                      environment variable.\n"
                 "                      Default certs.db\n"
                 " -h                   Show this message.\n"
                 " -k <P12 file>        Specify certificate file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_KEYCHAIN \n"
                 "                      environment variable.\n"
                 "                      Default server.p12\n"
                 " -l <P12 file>        Specify private key file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_PKEY \n"
                 "                      environment variable.\n"
                 "                      Default same as P12 file\n"
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
                 " -p <password file>   Specify certificate password file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE\n"
                 "                      environment variable.\n"
                 "                      '-' sets no password\n"
                 " -q <password file>   Specify private key password file location\n"
                 "                      Overrides EPICS_PVACMS_TLS_PKEY_PWD_FILE\n"
                 "                      environment variable.\n"
                 "                      '-' sets no password\n"
                 " -s <CA secret file>  Specify CA certificate password file\n"
                 "                      Overrides EPICS_CA_KEYCHAIN_PWD_FILE \n"
                 "                      environment variables.\n"
                 "                      '-' sets no password\n"
                 " -t <CA secret file>  Specify CA private key password file\n"
                 "                      Overrides EPICS_CA_PKEY_PWD_FILE \n"
                 "                      environment variables.\n"
                 "                      '-' sets no password\n"
                 " -u <ca_org_unit>     To specify the CA's organizational unit\n"
                 " -v                   Make more noise.\n"
                 " -V                   Print version and exit.\n";
}

template <typename T>
void setValue(Value &target, const std::string &field, const T &source) {
    auto current = target[field];
    if (current.as<T>() == source) {
        target[field].unmark();  // Assuming unmark is a valid method for indicating no change needed
    } else {
        target[field] = source;
    }
}

/**
 * @brief Posts the status of a certificate to the shared wildcard PV.
 *
 * This function posts the status of a certificate to a shared wildcard PV so that any listeners will be notified.
 * The shared wildcard PV is a data structure that can be accessed by multiple clients through a server.
 * The status of the certificate is represented by the CertStatus enum.
 *
 * @param status_pv The shared wildcard PV to post the status to.
 * @param pv_name The pv_name of the status to post.
 * @param serial The serial number of the certificate.
 * @param cert_status The status of the certificate (UNKNOWN, VALID, EXPIRED, REVOKED, PENDING_APPROVAL, PENDING).
 * @param open_only Specifies whether to close the shared wildcard PV again after setting the status if it was closed to begin with.
 */
epicsMutex status_pv_lock;
Value postCertificateStatus(server::SharedWildcardPV &status_pv, const std::string &pv_name, uint64_t serial, const PVACertificateStatus &cert_status) {
    Guard G(status_pv_lock);
    Value status_value;
    auto was_open = status_pv.isOpen(pv_name);
    if (was_open) {
        status_value = status_pv.fetch(pv_name);
    } else {
        status_value = CertStatus::getStatusPrototype();
    }
    setValue<uint64_t>(status_value, "serial", serial);
    setValue<uint32_t>(status_value, "status.value.index", cert_status.status.i);
    setValue<time_t>(status_value, "status.timeStamp.secondsPastEpoch", time(nullptr));
    setValue<std::string>(status_value, "state", cert_status.status.s);
    // Set OCSP state to default values even if bytes are not set
    setValue<uint32_t>(status_value, "ocsp_status.value.index", cert_status.ocsp_status.i);
    setValue<time_t>(status_value, "ocsp_status.timeStamp.secondsPastEpoch", time(nullptr));
    setValue<std::string>(status_value, "ocsp_state", SB() << "**UNCERTIFIED**: " << cert_status.ocsp_status.s);

    // Get ocsp info if specified
    if (!cert_status.ocsp_bytes.empty()) {
        setValue<uint32_t>(status_value, "ocsp_status.value.index", cert_status.ocsp_status.i);
        setValue<std::string>(status_value, "ocsp_state", cert_status.ocsp_status.s);
        setValue<std::string>(status_value, "ocsp_status_date", cert_status.status_date.s);
        setValue<std::string>(status_value, "ocsp_certified_until", cert_status.status_valid_until_date.s);
        setValue<std::string>(status_value, "ocsp_revocation_date", cert_status.revocation_date.s);
        auto ocsp_bytes = shared_array<const uint8_t>(cert_status.ocsp_bytes.begin(), cert_status.ocsp_bytes.end());
        status_value["ocsp_response"] = ocsp_bytes.freeze();
    }

    log_debug_printf(pvacms, "Posting Certificate Status: %s = %s\n", pv_name.c_str(), cert_status.status.s.c_str());
    if (was_open) {
        status_pv.post(pv_name, status_value);
    } else {
        status_pv.open(pv_name, status_value);
    }
    return status_value;
}

/**
 * @brief Posts the error status of a certificate to the shared wildcard PV.
 *
 * This function posts the error status of a certificate to a shared wildcard PV so that any listeners will be notified.
 * The shared wildcard PV is a data structure that can be accessed by multiple clients through a server.
 * The error status of the certificate error_status, error_severity and error_message parameters.
 *
 * @param status_pv The shared wildcard PV to post the error status to.
 * @param issuer_id The issuer ID of the certificate.
 * @param serial The serial number of the certificate.
 * @param error_status error status.
 * @param error_severity error severity
 * @param error_message The error message
 */
void postCertificateErrorStatus(server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op, const std::string &our_issuer_id,
                                const uint64_t &serial, const int32_t error_status, const int32_t error_severity, const std::string &error_message) {
    Guard G(status_pv_lock);
    std::string pv_name = getCertUri(GET_MONITOR_CERT_STATUS_ROOT, our_issuer_id, serial);
    Value status_value{CertStatus::getStatusPrototype()};
    auto cert_status = PVACertificateStatus();  // Create an UNKNOWN CertificateStatus
    setValue<uint64_t>(status_value, "serial", serial);
    setValue<uint32_t>(status_value, "status.value.index", cert_status.status.i);
    setValue<time_t>(status_value, "status.timeStamp.secondsPastEpoch", time(nullptr));
    setValue<std::string>(status_value, "state", cert_status.status.s);

    status_value["status.alarm.status"] = error_status;
    status_value["status.alarm.severity"] = error_severity;
    status_value["status.alarm.message"] = error_message;

    status_value["status.value.index"] = UNKNOWN;
    status_value["serial"] = serial;
    log_debug_printf(pvacms, "Posting Certificate Error Status: %s = %s\n", pv_name.c_str(), error_message.c_str());
    if (status_pv.isOpen(pv_name))
        status_pv.post(pv_name, status_value);
    else {
        status_pv.open(pv_name, status_value);
    }
    if (op != nullptr) op->error(error_message);
}

/**
 * @brief This function returns the certificate URI.
 *
 * The certificate URI is generated by concatenating the provided `prefix` with the certificate ID obtained
 * from the `issuer_id` and `serial`. The certificate ID is generated using the `getCertId` function.
 *
 * @param prefix The prefix used to construct the certificate URI.
 * @param issuer_id The issuer ID used to generate the certificate ID.
 * @param serial The serial number used to generate the certificate ID.
 * @return The certificate URI string.
 */
std::string getCertUri(const std::string &prefix, const std::string &issuer_id, const uint64_t &serial) {
    return getCertUri(prefix, getCertId(issuer_id, serial));
}

/**
 * @brief Returns the certificate URI.
 *
 * This function takes a prefix and a certificate ID as input parameters and returns the certificate URI.
 * The certificate URI is constructed by concatenating the prefix and the certificate ID using a colon (:) as a separator.
 *
 * @param prefix The prefix string for the certificate URI.
 * @param cert_id The certificate ID string.
 * @return The certificate URI string.
 */
std::string getCertUri(const std::string &prefix, const std::string &cert_id) {
    const std::string pv_name(SB() << prefix << ":" << cert_id);
    return pv_name;
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
    const std::string cert_id(SB() << issuer_id << ":" << serial);
    return cert_id;
}

bool statusMonitor(StatusMonitor &status_monitor_params) {
    log_debug_printf(pvacmsmonitor, "Certificate Monitor Thread Wake Up%s", "\n");
    auto cert_status_creator(CertStatusFactory(status_monitor_params.ca_cert_, status_monitor_params.ca_pkey_, status_monitor_params.ca_chain_,
                                               status_monitor_params.config_.cert_status_validity_mins));
    sqlite3_stmt *stmt;

    // Search for any certs that have become valid
    std::string valid_sql(SQL_CERT_TO_VALID);
    const std::vector<certstatus_t> valid_status{PENDING};
    valid_sql += getValidStatusesClause(valid_status);
    if (sqlite3_prepare_v2(status_monitor_params.ca_db_.get(), valid_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, valid_status);

        // Do one then reschedule the rest
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertUri(GET_MONITOR_CERT_STATUS_ROOT, status_monitor_params.issuer_id_, serial));
                updateCertificateStatus(status_monitor_params.ca_db_, serial, VALID, 1, {PENDING});
                auto status_date = std::time(nullptr);
                auto cert_status = cert_status_creator.createPVACertificateStatus(serial, VALID, status_date);
                postCertificateStatus(status_monitor_params.status_pv_, pv_name, serial, cert_status);
                log_info_printf(pvacmsmonitor, "Certificate %s:%llu has become VALID\n", status_monitor_params.issuer_id_.c_str(), serial);
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(status_monitor_params.ca_db_.get()));
    }

    // Search for any certs that have expired
    std::string expired_sql(SQL_CERT_TO_EXPIRED);
    const std::vector<certstatus_t> expired_status{VALID, PENDING_APPROVAL, PENDING};
    expired_sql += getValidStatusesClause(expired_status);
    if (sqlite3_prepare_v2(status_monitor_params.ca_db_.get(), expired_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, expired_status);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertUri(GET_MONITOR_CERT_STATUS_ROOT, status_monitor_params.issuer_id_, serial));
                updateCertificateStatus(status_monitor_params.ca_db_, serial, EXPIRED, -1, {VALID, PENDING_APPROVAL, PENDING});
                auto status_date = std::time(nullptr);
                auto cert_status = cert_status_creator.createPVACertificateStatus(serial, EXPIRED, status_date);
                postCertificateStatus(status_monitor_params.status_pv_, pv_name, serial, cert_status);
                log_info_printf(pvacmsmonitor, "Certificate %s:%llu has EXPIRED\n", status_monitor_params.issuer_id_.c_str(), serial);
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(status_monitor_params.ca_db_.get()));
    }

    log_debug_printf(pvacmsmonitor, "Certificate Monitor Thread Sleep%s", "\n");
    return true;  // We're not done - check files too
}

}  // namespace certs
}  // namespace pvxs

int main(int argc, char *argv[]) {
    using namespace pvxs::certs;
    using namespace pvxs::server;

    try {
        bool verbose = false;
        pvxs::sql_ptr ca_db;

        // Get config
        auto config = ConfigCms::fromEnv();

        // Read commandline options
        int exit_status;
        if ((exit_status = readOptions(config, argc, argv, verbose))) {
            return exit_status - 1;
        }
        if (verbose) logger_level_set("pvxs.certs.*", pvxs::Level::Info);

        // Initialize SSL
        pvxs::ossl::SSLContext::sslInit();

        // Set security if configured
        // TODO if not configured then provide a default and provide a VALID certificate for that default
        if (!config.ca_acf_filename.empty()) asSetFilename(config.ca_acf_filename.c_str());

        // Logger config from environment (so environment overrides verbose setting)
        pvxs::logger_config_env();

        // Initialize the certificates database
        initCertsDatabase(ca_db, config.ca_db_filename);

        // Get the CA Certificate
        pvxs::ossl_ptr<EVP_PKEY> ca_pkey;
        pvxs::ossl_ptr<X509> ca_cert;
        pvxs::ossl_shared_ptr<STACK_OF(X509)> ca_chain;

        // Get or create CA certificate
        getOrCreateCaCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain);
        auto our_issuer_id = CertStatus::getIssuerId(ca_cert);

        // Create this PVACMS server's certificate if it does not already exist
        ensureServerCertificateExists(config, ca_db, ca_cert, ca_pkey, ca_chain);

        // Create the PVs
        SharedPV create_pv(SharedPV::buildReadonly());
        SharedPV root_pv(SharedPV::buildReadonly());
        SharedWildcardPV status_pv(SharedWildcardPV::buildMailbox());

        // Create Root PV value which won't change
        // TODO what happens when it changes
        pvxs::Value root_pv_value = getRootValue(our_issuer_id, ca_cert, ca_chain);

        // RPC handlers
        pvxs::ossl_ptr<EVP_PKEY> ca_pub_key(X509_get_pubkey(ca_cert.get()));
        create_pv.onRPC(
            [&config, &ca_db, &ca_pkey, &ca_cert, &ca_pub_key, ca_chain, &our_issuer_id](const SharedPV &pv, std::unique_ptr<ExecOp> &&op, pvxs::Value &&args) {
                onCreateCertificate(config, ca_db, pv, std::move(op), std::move(args), ca_pkey, ca_cert, ca_pub_key, ca_chain, our_issuer_id);
            });

        // Client Connect handlers GET/MONITOR
        status_pv.onFirstConnect([&config, &ca_db, &ca_pkey, &ca_cert, &ca_chain, &our_issuer_id](SharedWildcardPV &pv, const std::string &pv_name,
                                                                                                  const std::list<std::string> &parameters) {
            onGetStatus(config, ca_db, our_issuer_id, pv, pv_name, parameters, ca_pkey, ca_cert, ca_chain);
        });
        status_pv.onLastDisconnect([](SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) { pv.close(pv_name); });

        // PUT handlers
        status_pv.onPut([&config, &ca_db, &our_issuer_id, &ca_pkey, &ca_cert, &ca_chain](SharedWildcardPV &pv, std::unique_ptr<ExecOp> &&op,
                                                                                         const std::string &pv_name, const std::list<std::string> &parameters,
                                                                                         pvxs::Value &&value) {
            // Make sure that pv is open before any put operation
            if (!pv.isOpen(pv_name)) {
                pv.open(pv_name, CertStatus::getStatusPrototype());
            }

            std::string issuer_id;
            uint64_t serial;
            std::tie(issuer_id, serial) = getParameters(parameters);

            // Get desired state
            auto state = value["state"].as<std::string>();
            std::transform(state.begin(), state.end(), state.begin(), ::toupper);

            if (state == "REVOKED") {
                onRevoke(config, ca_db, our_issuer_id, pv, std::move(op), pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            } else if (state == "APPROVED") {
                onApprove(config, ca_db, our_issuer_id, pv, std::move(op), pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            } else if (state == "DENIED") {
                onDeny(config, ca_db, our_issuer_id, pv, std::move(op), pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            } else {
                postCertificateErrorStatus(pv, std::move(op), our_issuer_id, serial, 1, 1, pvxs::SB() << "Invalid certificate state requested: " << state);
            }
        });

        StatusMonitor status_monitor_params(config, ca_db, our_issuer_id, status_pv, ca_cert, ca_pkey, ca_chain);

        // Create a server with a certificate monitoring function attached to the cert file monitor timer
        // Return true to indicate that we want the file monitor time to run after this
        Server pva_server = Server(config, [&status_monitor_params](short evt) { return statusMonitor(status_monitor_params); });

        pva_server.addPV(RPC_CERT_CREATE, create_pv).addPV(GET_MONITOR_CERT_STATUS_PV, status_pv).addPV(kCertRoot, root_pv);
        root_pv.open(root_pv_value);

        if (verbose) {
            std::cout << "Effective config\n" << config;
        }

        try {
            log_info_printf(pvacms, "PVACMS Running%s", "\n");
            pva_server.run();
            log_info_printf(pvacms, "PVACMS Exiting%s", "\n");
        } catch (const std::exception &e) {
            log_err_printf(pvacms, "PVACMS error: %s\n", e.what());
        }

        return 0;
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error: %s\n", e.what());
        return 1;
    }
}
