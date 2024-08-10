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
#include <vector>

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
#include "certmgmtservice.h"
#include "configcms.h"
#include "evhelper.h"
#include "ocsphelper.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "sqlite3.h"
#include "sqlite3ext.h"
#include "utilpvt.h"

DEFINE_LOGGER(pvacms, "pvxs.certs.cms");
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
static const int kMonthStartDays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
static const std::string kCertRevokePrefix("CERT:REVOKE");
static const std::string kCertStatusPrefix("CERT:STATUS");
static Value kStatusPrototype(certs::getStatusPrototype());

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
    return TypeDef(TypeCode::Struct,
                   {
                       Member(TypeCode::UInt64, "serial"),
                       Member(TypeCode::String, "issuer"),
                       Member(TypeCode::String, "certid"),
                       Member(TypeCode::String, "statuspv"),
                       Member(TypeCode::String, "revokepv"),
                       Member(TypeCode::String, "rotatepv"),
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

/**
 * @brief The prototype of the data returned for a certificate status request
 * Essentially an enum, a serial number and the ocsp response
 *
 * @return The prototype of the data returned for a certificate status request
 */
Value getStatusPrototype() {
    using namespace members;
    nt::NTEnum enum_value;

    auto value = TypeDef(TypeCode::Struct,
                         {
                             enum_value.build().as("status"),
                             Member(TypeCode::UInt64, "serial"),
                             Member(TypeCode::UInt8A, "ocsp"),
                         })
                     .create();
    shared_array<const std::string> choices({"UNKNOWN", "VALID", "EXPIRED", "REVOKED", "PENDING_APPROVAL", "PENDING"});
    value["status.value.choices"] = choices.freeze();
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
std::tuple<CertificateStatus, time_t> getCertificateStatus(sql_ptr &ca_db, uint64_t serial) {
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

    return std::make_tuple((CertificateStatus)cert_status, status_date);
}

/**
 * @brief Generates a SQL clause for filtering valid certificate statuses.
 *
 * This function takes a vector of CertificateStatus values and generates a SQL clause that can be used to filter
 * records with matching statuses. Each status value in the vector is converted into a parameterized condition in the clause.
 * The generated clause starts with "AND (" and ends with " )" and contains multiple "OR" conditions for each status value.
 *
 * @param valid_status The vector of CertificateStatus values to be filtered.
 * @return A string representing the SQL clause for filtering valid certificate statuses. If the vector is empty, an empty string is returned.
 */
std::string getValidStatusesClause(const std::vector<CertificateStatus> valid_status) {
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
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<CertificateStatus> valid_status) {
    auto n_valid_status = valid_status.size();
    for (auto i = 0; i < n_valid_status; i++) {
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, (SB() << ":status" << i).str().c_str()), valid_status[i]);
    }
}

/**
 * @brief Updates the status of a certificate in the certificates database.
 *
 * This function updates the status of a certificate in the certificates database.
 * The status is specified by the CertificateStatus enum. The function compares
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
void updateCertificateStatus(sql_ptr &ca_db, uint64_t serial, CertificateStatus cert_status, const std::vector<CertificateStatus> valid_status) {
    int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    int sql_status;
    std::string sql(SQL_CERT_SET_STATUS);
    sql += getValidStatusesClause(valid_status);

    if ((sql_status = sqlite3_prepare_v2(ca_db.get(), sql.c_str(), -1, &sql_statement, 0)) == SQLITE_OK) {
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"), cert_status);
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
 * @brief  Manual calculation of time since epoch
 *
 * Gets round problematic timezone issues by relying on tm being in UTC beforehand
 *
 * @param tm tm struct in UTC
 * @return time_t seconds since epoch
 */
time_t tmToTimeTUTC(std::tm &tm) {
    int year = 1900 + tm.tm_year;
    time_t days = (year - 1970) * 365;
    days += (year - 1969) / 4;
    days -= (year - 1901) / 100;
    days += (year - 1601) / 400;
    if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) && tm.tm_mon < 2) {
        days--;
    }
    days += tm.tm_mday - 1;
    days += kMonthStartDays[tm.tm_mon];  // month_start_days should be an array list with amount of days since beginning
                                         // of year for each month
    return ((days * 24 + tm.tm_hour) * 60 + tm.tm_min) * 60 + tm.tm_sec;
}

/**
 * @brief Convert from ASN1_TIME found in certificates to time_t format
 * @param time the ASN1_TIME to convert
 *
 * @return the time_t representation of the given ASN1_TIME value
 */
time_t ASN1_TIMEToTimeT(ASN1_TIME *time) {
    std::tm t{};
    ASN1_TIME_to_tm(time, &t);
    return tmToTimeTUTC(t);
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
    auto db_serial = *reinterpret_cast<int64_t *>(&cert_factory.serial_);  // db stores as signed int so convert to and from

    checkForDuplicates(ca_db, cert_factory);

    sqlite3_stmt *sql_statement;
    auto current_time = std::time(nullptr);
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
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"),
                         current_time < cert_factory.not_before_   ? PENDING
                         : current_time >= cert_factory.not_after_ ? EXPIRED
                                                                   : VALID);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);

        sql_status = sqlite3_step(sql_statement);
    }

    sqlite3_finalize(sql_statement);

    if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
        throw std::runtime_error(SB() << "Failed to create certificate: " << sqlite3_errmsg(ca_db.get()));
    }
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

    const std::vector<CertificateStatus> valid_status{VALID, PENDING_APPROVAL, PENDING};

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
    storeCertificate(ca_db, certificate_factory);

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
    log_info_printf(pvacms, "%s\n",
                    (SB() << "CERT_ID: " << getCertId(getIssuerId(certificate_factory.issuer_certificate_ptr_), certificate_factory.serial_)).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "NAME: " << certificate_factory.name_).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "ORGANIZATION: " << certificate_factory.org_).str().c_str());
    log_info_printf(pvacms, "%s\n", (SB() << "ORGANIZATIONAL UNIT: " << certificate_factory.org_unit_).str().c_str());
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
 * @brief  Get the issuer ID which is the first 8 hex digits of the hex SKI
 *
 * Note that the given cert must contain the skid extension in the first place
 *
 * @param ca_cert  the cert from which to get the subject key identifier extension
 * @return first 8 hex digits of the hex SKI
 */
std::string getIssuerId(const ossl_ptr<X509> &ca_cert) { return getIssuerId(ca_cert.get()); }

std::string getIssuerId(X509 *ca_cert_ptr) {
    ossl_ptr<ASN1_OCTET_STRING> skid(reinterpret_cast<ASN1_OCTET_STRING *>(X509_get_ext_d2i(ca_cert_ptr, NID_subject_key_identifier, nullptr, nullptr)));
    if (!skid.get()) {
        throw std::runtime_error("Failed to get Subject Key Identifier.");
    }

    // Convert first 8 chars to hex
    auto buf = const_cast<unsigned char *>(skid->data);
    std::stringstream ss;
    for (int i = 0; i < skid->length && ss.tellp() < 8; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]);
    }

    return ss.str();
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
void onCreateCertificate(sql_ptr &ca_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args, const ossl_ptr<EVP_PKEY> &ca_pkey,
                         const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain,
                         std::string issuer_id) {
    auto ccr = args["query"];

    auto type = getStructureValue<const std::string>(ccr, "type");
    auto name = getStructureValue<const std::string>(ccr, "name");
    auto organization = getStructureValue<const std::string>(ccr, "organization");

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
        auto public_key = getStructureValue<const std::string>(ccr, "pub_key");
        const std::shared_ptr<KeyPair> key_pair(new KeyPair(public_key));

        // Generate a new serial number
        auto serial = generateSerial();

        // Get other certificate parameters from request
        auto country = getStructureValue<const std::string>(ccr, "country");
        auto organization_unit = getStructureValue<const std::string>(ccr, "organization_unit");
        auto not_before = getStructureValue<time_t>(ccr, "not_before");
        auto not_after = getStructureValue<time_t>(ccr, "not_after");
        auto usage = getStructureValue<uint16_t>(ccr, "usage");

        // Create a certificate factory
        auto certificate_factory = CertFactory(serial, key_pair, name, country, organization, organization_unit, not_before, not_after, usage, ca_cert.get(),
                                               ca_pkey.get(), ca_chain.get());

        // Create the certificate using the certificate factory, store it in the database and return the PEM string
        auto pem_string = createCertificatePemString(ca_db, certificate_factory);

        // Construct and return the reply
        auto cert_id = getCertId(issuer_id, serial);
        auto status_pv = getCertUri(kCertStatusPrefix, cert_id);
        auto revoke_pv = getCertUri(kCertRevokePrefix, cert_id);
        auto rotate_pv = RPC_CERT_ROTATE_PV;
        auto reply(getCreatePrototype());
        reply["serial"] = serial;
        reply["issuer"] = issuer_id;
        reply["certid"] = cert_id;
        reply["statuspv"] = status_pv;
        reply["revokepv"] = revoke_pv;
        reply["rotatepv"] = rotate_pv;
        reply["cert"] = pem_string;
        op->reply(reply);
    } catch (std::exception &e) {
        // For any type of error return an error to the caller
        op->error(SB() << "Failed to create certificate for " << NAME_STRING(name, organization) << ": " << e.what());
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
void onGetStatus(sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, const std::string &pv_name,
                 const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
                 const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(kStatusPrototype.clone());
    uint64_t serial = 0;
    try {
        // get serial and issuer from called pv
        auto it = parameters.begin();
        const std::string &issuer_id = *it;
        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        const std::string &serial_string = *++it;
        try {
            serial = std::stoull(serial_string);
        } catch (const std::invalid_argument &e) {
            throw std::runtime_error(SB() << "Conversion error: Invalid argument. Serial in PV name is not a number: " << serial_string);
        } catch (const std::out_of_range &e) {
            throw std::runtime_error(SB() << "Conversion error: Out of range. Serial is too large: " << serial_string);
        }

        // get status value
        CertificateStatus status;
        time_t status_date;
        std::tie(status, status_date) = certs::getCertificateStatus(ca_db, serial);
        if (status == UNKNOWN) {
            status_value["status.alarm.status"] = 1;
            status_value["status.alarm.severity"] = 1;
            status_value["status.alarm.message"] = "Unable to determine certificate status";
        }

        auto ocsp_response = createAndSignOCSPResponse(serial, status, status_date, ca_cert, ca_pkey, ca_chain);
        auto ocsp_bytes = shared_array<uint8_t>(ocsp_response.begin(), ocsp_response.end());
        postCertificateStatus(status_pv, pv_name, serial, status, ocsp_bytes, true);
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error getting status: %s\n", e.what());
        postCertificateErrorStatus(status_pv, our_issuer_id, serial, 1, 1, e.what());
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
void onRevoke(sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
              const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
              const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(kStatusPrototype.clone());
    try {
        // get serial and issuer from called pv
        auto it = parameters.begin();
        const std::string &issuer_id = *it;
        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        const std::string &serial_string = *++it;
        uint64_t serial;
        try {
            serial = std::stoull(serial_string);
        } catch (const std::invalid_argument &e) {
            throw std::runtime_error(SB() << "Conversion error: Invalid argument. Serial in PV name is not a number: " << serial_string);
        } catch (const std::out_of_range &e) {
            throw std::runtime_error(SB() << "Conversion error: Out of range. Serial is too large: " << serial_string);
        }

        // set status value
        certs::updateCertificateStatus(ca_db, serial, REVOKED);

        auto ocsp_response = createAndSignOCSPResponse(serial, REVOKED, time(nullptr), ca_cert, ca_pkey, ca_chain);
        auto ocsp_bytes = shared_array<uint8_t>(ocsp_response.begin(), ocsp_response.end());
        postCertificateStatus(status_pv, pv_name, serial, REVOKED, ocsp_bytes);
        op->reply(status_value);
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error revoking certificate: %s\n", e.what());
        op->error(SB() << "Error revoking certificate: " << e.what());
    }
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
    // Get key pair
    std::shared_ptr<KeyPair> key_pair;
    try {
        // Check if the CA key pair exists
        key_pair = P12FileFactory::getKeyFromFile(config.ca_private_key_filename, config.ca_private_key_password);
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

    // Get certificate
    try {
        // Check if the CA certificates exist
        auto cert_data = P12FileFactory::getCertDataFromFile(config.ca_cert_filename, config.ca_cert_password);
        ca_cert = std::move(cert_data.cert);
        ca_chain = cert_data.ca;
    } catch (std::exception &e) {
        // Error getting certs file, or certs file invalid
        // Make a new CA Certificate
        try {
            log_warn_printf(pvafms, "%s\n", e.what());
            createCaCertificate(config, ca_db, key_pair);
            auto cert_data = P12FileFactory::getCertDataFromFile(config.ca_cert_filename, config.ca_cert_password);
            ca_cert = std::move(cert_data.cert);
            ca_chain = cert_data.ca;
        } catch (std::exception &e) {
            throw(std::runtime_error(SB() << "Error creating CA certificate: " << e.what()));
        }
    }
    ca_pkey = std::move(key_pair->pkey);
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
    // Get key pair
    std::shared_ptr<KeyPair> key_pair;
    try {
        // Check if the server key pair exists
        key_pair = P12FileFactory::getKeyFromFile(config.tls_private_key_filename, config.tls_private_key_password);
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

    // Get certificate
    try {
        // Check if the server certificates exist and can be read
        P12FileFactory::getCertDataFromFile(config.tls_cert_filename, config.tls_cert_password);
    } catch (std::exception &e) {
        // Error getting certs file, or certs file invalid
        // Make a new server Certificate
        try {
            log_warn_printf(pvacms, "%s\n", e.what());
            createServerCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain, key_pair);
        } catch (std::exception &e) {
            throw(std::runtime_error(SB() << "Error creating server certificate: " << e.what()));
        }
    }
}

std::shared_ptr<KeyPair> createCaKey(ConfigCms &config) {
    // Create a key pair
    const auto key_pair = P12FileFactory::createKeyPair();

    // Create PKCS#12 file containing private key
    P12FileFactory p12file_factory(config.ca_private_key_filename, config.ca_private_key_password, key_pair);
    p12file_factory.writePKCS12File();
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
 */
void createCaCertificate(ConfigCms &config, sql_ptr &ca_db, std::shared_ptr<KeyPair> &key_pair) {
    // Set validity to 4 yrs
    time_t not_before(time(nullptr));
    time_t not_after(not_before + (4 * 365 + 1) * 24 * 60 * 60);  // 4yrs

    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial, key_pair, config.ca_name, getCountryCode(), config.ca_organization, config.ca_organizational_unit,
                                           not_before, not_after, ssl::kForCa);

    auto pem_string = createCertificatePemString(ca_db, certificate_factory);

    // Create PKCS#12 file containing certs, private key and chain
    P12FileFactory p12file_factory(config.ca_cert_filename, config.ca_cert_password, key_pair, pem_string);

    p12file_factory.writePKCS12File();

    // Create the root certificate (overwrite existing)
    // The user must re-trust it if it already existed
    p12file_factory.writeRootPemFile(pem_string, true);
}

/**
 * @brief Create a PVACMS server key
 * @param config the configuration use to get the parameters to create cert
 */
std::shared_ptr<KeyPair> createServerKey(const ConfigCms &config) {
    // Create a key pair
    const auto key_pair(P12FileFactory::createKeyPair());

    // Create PKCS#12 file containing private key
    P12FileFactory p12file_factory(config.tls_private_key_filename, config.tls_private_key_password, key_pair, nullptr, nullptr);
    p12file_factory.writePKCS12File();
    return key_pair;
}

/**
 * @brief Create a PVACMS server certificate
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
                    getNotAfterTimeFromCert(ca_cert.get()), ssl::kForCMS, ca_cert.get(), ca_pkey.get(), ca_chain.get());

    auto cert = createCertificate(ca_db, certificate_factory);

    // Create PKCS#12 file containing certs, private key and null chain
    P12FileFactory p12file_factory(config.tls_cert_filename, config.tls_cert_password, key_pair, cert.get(), certificate_factory.certificate_chain_.get());

    p12file_factory.writePKCS12File();
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
    time_t not_after = ASN1_TIMEToTimeT(cert_not_after);
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
    time_t not_before = ASN1_TIMEToTimeT(cert_not_before);
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

/**
 * @brief Posts the status of a certificate to the shared wildcard PV.
 *
 * This function posts the status of a certificate to a shared wildcard PV so that any listeners will be notified.
 * The shared wildcard PV is a data structure that can be accessed by multiple clients through a server.
 * The status of the certificate is represented by the CertificateStatus enum.
 *
 * @param status_pv The shared wildcard PV to post the status to.
 * @param pv_name The pv_name of the status to post.
 * @param serial The serial number of the certificate.
 * @param status The status of the certificate (UNKNOWN, VALID, EXPIRED, REVOKED, PENDING_APPROVAL, PENDING).
 * @param ocsp_bytes The OCSP response status
 * @param open_only Specifies whether to close the shared wildcard PV again after setting the status if it was closed to begin with.
 */
void postCertificateStatus(server::SharedWildcardPV &status_pv, const std::string &pv_name, const uint64_t &serial, const CertificateStatus &status,
                           shared_array<uint8_t> &ocsp_bytes, bool open_only) {
    Value status_value;
    if (status_pv.isOpen(pv_name))
        status_value = status_pv.fetch(pv_name);
    else
        status_value = getStatusPrototype().clone();

    status_value["status.value.index"] = status;
    status_value["serial"] = serial;
    if (!ocsp_bytes.empty()) status_value["ocsp"] = ocsp_bytes.freeze();

    if (status_pv.isOpen(pv_name)) {
        status_pv.post(pv_name, status_value);
    } else {
        status_pv.open(pv_name, status_value);
        if (!open_only) status_pv.close(pv_name);
    }
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
void postCertificateErrorStatus(server::SharedWildcardPV &status_pv, const std::string &our_issuer_id, const uint64_t &serial, const int32_t error_status,
                                const int32_t error_severity, const std::string &error_message) {
    std::string pv_name = getCertUri(kCertStatusPrefix, our_issuer_id, serial);
    Value status_value;
    if (status_pv.isOpen(pv_name))
        status_value = status_pv.fetch(pv_name);
    else
        status_value = getStatusPrototype().clone();

    status_value["status.alarm.status"] = error_status;
    status_value["status.alarm.severity"] = error_severity;
    status_value["status.alarm.message"] = error_message;

    status_value["status.value.index"] = UNKNOWN;
    status_value["serial"] = serial;
    if (status_pv.isOpen(pv_name))
        status_pv.post(pv_name, status_value);
    else {
        status_pv.open(pv_name, status_value);
        status_pv.post(pv_name, status_value);
        status_pv.close(pv_name);
    }
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

/**
 * @brief Monitors the certificate status and updates the shared wildcard status pv when any become valid or expire.
 *
 * This function monitors the certificate status by connecting to the Certificate database, and searching
 * for all certificates that have just expired and all certificates that have just become valid.  If any
 * are found then the associated shared wildcard PV is updated and the new status stored in the database.
 *
 * @param ca_db The certificates database object.
 * @param issuer_id The issuer ID.
 * @param status_pv The shared wildcard PV to notify.
 *
 * @note This function assumes that the CA database and the status PV have been properly configured and initialized.
 * @note The status_pv parameter must be a valid SharedWildcardPV object.
 */
void certificateStatusMonitor(sql_ptr &ca_db, std::string &issuer_id, server::SharedWildcardPV &status_pv, pvxs::ossl_ptr<X509> &ca_cert,
                              pvxs::ossl_ptr<EVP_PKEY> &ca_pkey, pvxs::ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    std::cout << "Certificate Monitor Thread Started\n";
    epicsMutex lock;
    while (true) {
        Guard G(lock);
        sqlite3_stmt *stmt;

        // Search for all certs that have become valid
        std::string valid_sql(SQL_CERT_TO_VALID);
        const std::vector<CertificateStatus> valid_status{PENDING};
        valid_sql += getValidStatusesClause(valid_status);
        if (sqlite3_prepare_v2(ca_db.get(), valid_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            bindValidStatusClauses(stmt, valid_status);

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int64_t db_serial = sqlite3_column_int64(stmt, 0);
                uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
                try {
                    const std::string pv_name(getCertUri(kCertStatusPrefix, issuer_id, serial));
                    updateCertificateStatus(ca_db, serial, VALID, {PENDING});
                    auto ocsp_response = createAndSignOCSPResponse(serial, PENDING, time(nullptr), ca_cert, ca_pkey, ca_chain);
                    auto ocsp_bytes = shared_array<uint8_t>(ocsp_response.begin(), ocsp_response.end());
                    postCertificateStatus(status_pv, pv_name, serial, VALID, ocsp_bytes);
                    log_info_printf(pvacms, "Certificate %s:%llu has become VALID\n", issuer_id.c_str(), serial);
                } catch (const std::runtime_error &e) {
                    log_err_printf(pvacms, "PVACMS Certificate Monitor Error: %s\n", e.what());
                }
            }
            sqlite3_finalize(stmt);
        } else {
            log_err_printf(pvacms, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(ca_db.get()));
        }

        // Search for all certs that have expired
        std::string expired_sql(SQL_CERT_TO_EXPIRED);
        const std::vector<CertificateStatus> expired_status{VALID, PENDING_APPROVAL, PENDING};
        expired_sql += getValidStatusesClause(expired_status);
        if (sqlite3_prepare_v2(ca_db.get(), expired_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            bindValidStatusClauses(stmt, expired_status);

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int64_t db_serial = sqlite3_column_int64(stmt, 0);
                uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
                try {
                    const std::string pv_name(getCertUri(kCertStatusPrefix, issuer_id, serial));
                    updateCertificateStatus(ca_db, serial, EXPIRED, {VALID, PENDING_APPROVAL, PENDING});
                    auto ocsp_response = createAndSignOCSPResponse(serial, EXPIRED, time(nullptr), ca_cert, ca_pkey, ca_chain);
                    auto ocsp_bytes = shared_array<uint8_t>(ocsp_response.begin(), ocsp_response.end());
                    postCertificateStatus(status_pv, pv_name, serial, EXPIRED, ocsp_bytes);
                    log_info_printf(pvacms, "Certificate %s:%llu has EXPIRED\n", issuer_id.c_str(), serial);
                } catch (const std::runtime_error &e) {
                    log_err_printf(pvacms, "PVACMS Certificate Monitor Error: %s\n", e.what());
                }
            }
            sqlite3_finalize(stmt);
        } else {
            log_err_printf(pvacms, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(ca_db.get()));
        }

        UnGuard U(G);

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
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

        // Logger config from environment ( so environment overrides verbose setting )
        pvxs::logger_config_env();

        // Initialise the certificates database
        initCertsDatabase(ca_db, config.ca_db_filename);

        // Get the CA Certificate
        pvxs::ossl_ptr<EVP_PKEY> ca_pkey;
        pvxs::ossl_ptr<X509> ca_cert;
        pvxs::ossl_shared_ptr<STACK_OF(X509)> ca_chain;

        // Get or create CA certificate
        getOrCreateCaCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain);
        auto our_issuer_id = getIssuerId(ca_cert);

        // Create this PVACMS server's certificate if it does not already exist
        ensureServerCertificateExists(config, ca_db, ca_cert, ca_pkey, ca_chain);

        // Create the PVs
        SharedPV create_pv(SharedPV::buildReadonly());
        SharedWildcardPV revoke_pv(SharedWildcardPV::buildMailbox());
        SharedWildcardPV status_pv(SharedWildcardPV::buildReadonly());

        // RPC handlers
        // Create Certificate: args: ccr (certificate creation request)
        // Get public key of ca certificate
        pvxs::ossl_ptr<EVP_PKEY> ca_pub_key(X509_get_pubkey(ca_cert.get()));
        create_pv.onRPC(
            [&ca_db, &ca_pkey, &ca_cert, &ca_pub_key, ca_chain, &our_issuer_id](const SharedPV &pv, std::unique_ptr<ExecOp> &&op, pvxs::Value &&args) {
                onCreateCertificate(ca_db, pv, std::move(op), std::move(args), ca_pkey, ca_cert, ca_pub_key, ca_chain, our_issuer_id);
            });

        // Status PV
        status_pv.onFirstConnect(
            [&ca_db, &ca_pkey, &ca_cert, ca_chain, &our_issuer_id](SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
                onGetStatus(ca_db, our_issuer_id, pv, pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            });

        status_pv.onLastDisconnect([](SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) { pv.close(pv_name); });

        // Revoke Certificate
        revoke_pv.onRPC([&ca_db, &status_pv, &our_issuer_id, &ca_pkey, &ca_cert, ca_chain](SharedWildcardPV &pv, std::unique_ptr<ExecOp> &&op,
                                                                                           const std::string &revoke_pv_name,
                                                                                           const std::list<std::string> &parameters, pvxs::Value &&args) {
            auto status_pv_name(revoke_pv_name);
            status_pv_name.replace(0, kCertRevokePrefix.length(), kCertStatusPrefix);
            onRevoke(ca_db, our_issuer_id, status_pv, std::move(op), status_pv_name, parameters, ca_pkey, ca_cert, ca_chain);
        });

        // Build server which will serve this PV
        Server pva_server = Server(config);

        // Add functional PVs
        pva_server.addPV(RPC_CERT_CREATE, create_pv).addPV(RPC_CERT_REVOKE_PV, revoke_pv).addPV(GET_MONITOR_CERT_STATUS_PV, status_pv);

        // Certificate Status Monitor
        std::thread certificate_status_monitor_worker(certificateStatusMonitor, std::ref(ca_db), std::ref(our_issuer_id), std::ref(status_pv),
                                                      std::ref(ca_cert), std::ref(ca_pkey), std::ref(ca_chain));

        if (verbose)
            // Print the configuration this server is using
            std::cout << "Effective config\n" << config;
        std::cout << "PVACMS Running\n";

        // Start server and run forever, or until Ctrl+c is pressed.
        // Returns on SIGINT or SIGTERM
        pva_server.run();

        std::cout << "PVACMS Exiting\n";
        certificate_status_monitor_worker.detach();

        return 0;
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error: %s\n", e.what());
        return 1;
    }
}
