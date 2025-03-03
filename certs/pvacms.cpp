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
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
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
#include <pvxs/sslinit.h>

#include <CLI/CLI.hpp>

#include "auth.h"
#include "authregistry.h"
#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "configcms.h"
#include "credentials.h"
#include "evhelper.h"
#include "openssl.h"
#include "ownedptr.h"
#include "securityclient.h"
#include "sqlite3.h"
#include "utilpvt.h"

DEFINE_LOGGER(pvacms, "pvxs.certs.cms");
DEFINE_LOGGER(pvacmsmonitor, "pvxs.certs.stat");

namespace pvxs {
namespace certs {

bool postUpdateToNextCertToExpire(const CertStatusFactory &cert_status_creator, server::SharedWildcardPV &status_pv, const sql_ptr &ca_db,
                                  const std::string &issuer_id, const std::string &full_skid = {});

epicsMutex status_pv_lock;
epicsMutex status_update_lock;

struct ASMember {
    std::string name{};
    ASMEMBERPVT mem{};
    ASMember() : ASMember("DEFAULT") {}
    explicit ASMember(const std::string &n) : name(n) {
        if (asAddMember(&mem, name.c_str())) throw std::runtime_error(SB() << "Unable to create ASMember " << n);
        // mem references name.c_str()
    }
    ~ASMember() {
        // all clients must be disconnected...
        if (asRemoveMember(&mem)) log_err_printf(pvacms, "Unable to cleanup ASMember %s\n", name.c_str());
    }
};

static const std::string kCertRoot("CERT:ROOT");

// The current partition number
uint16_t partition_number = 0;

// The current number of partitions
uint16_t num_partitions = 1;

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

    value["serial"] = CertStatusFactory::getSerialNumber(ca_cert);
    value["issuer"] = issuer_id;
    value["name"] = extractSubjectPart("CN");
    value["org"] = extractSubjectPart("O");
    value["org_unit"] = extractSubjectPart("OU");
    value["cert"] = CertFactory::certAndCasToPemString(ca_cert, ca_chain.get());

    return value;
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
void initCertsDatabase(sql_ptr &ca_db, const std::string &db_file) {
    if ((sqlite3_open(db_file.c_str(), ca_db.acquire()) != SQLITE_OK)) {
        throw std::runtime_error(SB() << "Can't open certs db file for writing: " << sqlite3_errmsg(ca_db.get()));
    } else {
        sqlite3_stmt *statement;
        if (sqlite3_prepare_v2(ca_db.get(), SQL_CHECK_EXISTS_DB_FILE, -1, &statement, nullptr) != SQLITE_OK) {
            throw std::runtime_error(SB() << "Failed to check if certs db exists: " << sqlite3_errmsg(ca_db.get()));
        }

        bool table_exists = (sqlite3_step(statement) == SQLITE_ROW);  // table exists if a row was returned
        sqlite3_finalize(statement);

        if (!table_exists) {
            auto sql_status = sqlite3_exec(ca_db.get(), SQL_CREATE_DB_FILE, nullptr, nullptr, nullptr);
            if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
                throw std::runtime_error(SB() << "Can't initialize certs db file: " << sqlite3_errmsg(ca_db.get()));
            }
            std::cout << "Certificate DB created  : " << db_file << std::endl;
        }
    }
}

/**
 * @brief Get the worst certificate status from the database for the given serial number
 *
 * This is used to compare the retrieved status with the worst so far so
 * that we can iteratively determine the worst status for a set of certificates.
 * The set we are interested in is the set of CA certificates.
 *
 * When we return the status of a Certificate we also check the status of the
 * CA certificates and send the worst status to the client.
 *
 * @param ca_db The database to get the certificate status from
 * @param serial The serial number of the certificate
 * @param worst_status_so_far The worst certificate status so far
 * @param worst_status_time_so_far The time of the worst certificate status so far
 * @return The worst certificate status for the given serial number
 */
void getWorstCertificateStatus(const sql_ptr &ca_db, const serial_number_t serial, certstatus_t &worst_status_so_far, time_t &worst_status_time_so_far) {
    certstatus_t status;
    time_t status_date;
    std::tie(status, status_date) = certs::getCertificateStatus(ca_db, serial);
    // if worse
    if (status != UNKNOWN && status > worst_status_so_far) {
        worst_status_so_far = status;
        worst_status_time_so_far = status_date;
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
std::tuple<certstatus_t, time_t> getCertificateStatus(const sql_ptr &ca_db, serial_number_t serial) {
    int cert_status = UNKNOWN;
    time_t status_date = std::time(nullptr);

    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    if (sqlite3_prepare_v2(ca_db.get(), SQL_CERT_STATUS, -1, &sql_statement, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);

        if (sqlite3_step(sql_statement) == SQLITE_ROW) {
            cert_status = sqlite3_column_int(sql_statement, 0);
            status_date = sqlite3_column_int64(sql_statement, 1);
        }
    } else {
        sqlite3_finalize(sql_statement);
        throw std::logic_error(SB() << "failed to prepare sqlite statement: " << sqlite3_errmsg(ca_db.get()));
    }

    return std::make_tuple(static_cast<certstatus_t>(cert_status), status_date);
}

/**
 * @brief Get the validity of a certificate from the database
 *
 * @param ca_db The database to get the certificate validity from
 * @param serial The serial number of the certificate
 * @return The tuple containing the not before and not after times which describe the validity of the certificate
 */
std::tuple<time_t, time_t> getCertificateValidity(const sql_ptr &ca_db, serial_number_t serial) {
    time_t not_before{}, not_after{};

    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    if (sqlite3_prepare_v2(ca_db.get(), SQL_CERT_VALIDITY, -1, &sql_statement, nullptr) == SQLITE_OK) {
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
std::string getValidStatusesClause(const std::vector<certstatus_t> &valid_status) {
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
 * @brief Generates a SQL clause for filtering valid certificate serials
 *
 * It will generate an IN clause for the supplied serials
 *
 * @param serials The vector of serial numbers to filter
 * @return The SQL clause for filtering valid certificate serials
 */
std::string getSelectedSerials(const std::vector<serial_number_t> &serials) {
    auto n_serials = serials.size();
    if (n_serials > 0) {
        bool first = true;
        auto serials_clauses = SB();
        serials_clauses << " serial IN (";
        for (auto serial : serials) {
            int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
            if (!first)
                serials_clauses << ", ";
            else
                first = false;
            serials_clauses << db_serial;
        }
        serials_clauses << ")";
        return serials_clauses.str();
    }
    return "";
}

/**
 * Binds the valid certificate status clauses to the given SQLite statement.
 *
 * @param sql_statement The SQLite statement to bind the clauses to.
 * @param valid_status A vector containing the valid certificate status values.
 */
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<certstatus_t> &valid_status) {
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
 * @param approval_status the status to apply after approval
 * @param valid_status A vector containing the valid status values that are allowed to transition a certificate from.
 *
 * @return None
 */
void updateCertificateStatus(const sql_ptr &ca_db, serial_number_t serial, const certstatus_t cert_status, const int approval_status,
                             const std::vector<certstatus_t> &valid_status) {
    int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    int sql_status;
    std::string sql(approval_status == -1 ? SQL_CERT_SET_STATUS : SQL_CERT_SET_STATUS_W_APPROVAL);
    sql += getValidStatusesClause(valid_status);
    auto current_time = std::time(nullptr);
    if ((sql_status = sqlite3_prepare_v2(ca_db.get(), sql.c_str(), -1, &sql_statement, nullptr)) == SQLITE_OK) {
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
            throw std::runtime_error("Invalid state transition or invalid serial number");
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
serial_number_t generateSerial() {
    std::random_device random_from_device;                        // Obtain a random number from hardware
    std::mt19937_64 seed(random_from_device());                // Seed the generator
    std::uniform_int_distribution<serial_number_t> distribution;  // Define the range

    const serial_number_t random_serial_number = distribution(seed);  // Generate a random number
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
certstatus_t storeCertificate(const sql_ptr &ca_db, CertFactory &cert_factory) {
    const auto db_serial = *reinterpret_cast<int64_t *>(&cert_factory.serial_);  // db stores as signed int so convert to and from
    const auto current_time = std::time(nullptr);
    const auto effective_status = cert_factory.initial_status_ != VALID     ? cert_factory.initial_status_
                            : current_time < cert_factory.not_before_ ? PENDING
                            : current_time >= cert_factory.not_after_ ? EXPIRED
                                                                      : cert_factory.initial_status_;

    checkForDuplicates(ca_db, cert_factory);

    sqlite3_stmt *sql_statement;
    auto sql_status = sqlite3_prepare_v2(ca_db.get(), SQL_CREATE_CERT, -1, &sql_statement, nullptr);
    if (sql_status == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":skid"), cert_factory.skid_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":CN"), cert_factory.name_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":O"), cert_factory.org_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":OU"), cert_factory.org_unit_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":C"), cert_factory.country_.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":not_before"), static_cast<int>(cert_factory.not_before_));
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":not_after"), static_cast<int>(cert_factory.not_after_));
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
void checkForDuplicates(const sql_ptr &ca_db, const CertFactory &cert_factory) {
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
        throw std::runtime_error("Duplicate Certificate Subject Key Identifier.  Best-practices require use of a distinct Key-Pair for each certificate");
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
    // Check validity falls within acceptable range
    if (certificate_factory.issuer_certificate_ptr_) ensureValidityCompatible(certificate_factory);

    auto certificate = certificate_factory.create();

    // Store certificate in database
    auto effective_status = storeCertificate(ca_db, certificate_factory);

    // Print info about certificate creation
    std::string from = std::ctime(&certificate_factory.not_before_);
    std::string to = std::ctime(&certificate_factory.not_after_);

    auto const issuer_id = CertStatus::getSkId(certificate_factory.issuer_certificate_ptr_);
    auto cert_id = getCertId(issuer_id, certificate_factory.serial_);
    log_info_printf(pvacms, "%s *=> %s\n", cert_id.c_str(), CERT_STATE(effective_status));
    log_debug_printf(pvacms, "--------------------------------------%s", "\n");
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
    log_debug_printf(pvacms, "%s\n", cert_description.c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "NAME: " << certificate_factory.name_).str().c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "CERT_ID: " << cert_id).str().c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "ORGANIZATION: " << certificate_factory.org_).str().c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "ORGANIZATIONAL UNIT: " << certificate_factory.org_unit_).str().c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "COUNTRY: " << certificate_factory.country_).str().c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "STATUS: " << CERT_STATE(effective_status)).str().c_str());
    log_debug_printf(pvacms, "%s\n", (SB() << "VALIDITY: " << from.substr(0, from.size() - 1) << " to " << to.substr(0, to.size() - 1)).str().c_str());
    log_debug_printf(pvacms, "--------------------------------------%s", "\n");

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
    auto cert = createCertificate(ca_db, cert_factory);

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

/**
 * @brief Get the prior approval status of a certificate
 *
 * Determines if the certificate has been previously approved by checking the database for one that
 * matches the name, country, organization and organization unit
 *
 * @param ca_db The database to get the certificate status from
 * @param name The name of the certificate
 * @param country The country of the certificate
 * @param organization The organization of the certificate
 * @param organization_unit The organizational unit of the certificate
 * @return True if the certificate has been previously approved, false otherwise
 */
bool getPriorApprovalStatus(const sql_ptr &ca_db, const std::string &name, const std::string &country, const std::string &organization, const std::string &organization_unit) {
    // Check for duplicate subject
    sqlite3_stmt *sql_statement;
    bool previously_approved{false};

    const std::string approved_sql(SQL_PRIOR_APPROVAL_STATUS);
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
 * certificate creation parameters. It creates a reply containing the certificate data, and sends it
 * back to the client.
 *
 * @param config the config to use to create the certificate creation factory
 * @param ca_db the DB to write the certificate registration information
 * @param shared_status_pv
 * @param op The unique pointer to the execution operation.
 * @param args the RPC aruments
 * @param ca_pkey the public/private key of the CA certificate
 * @param ca_cert the CA certificate
 * @param ca_chain the CA certificate chain
 * @param issuer_id the issuer ID to be encoded in the certificate
 */
void onCreateCertificate(ConfigCms &config, sql_ptr &ca_db, server::SharedWildcardPV &shared_status_pv, std::unique_ptr<server::ExecOp> &&op, Value &&args,
                         const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert, const ossl_shared_ptr<stack_st_X509> &ca_chain, std::string issuer_id) {
    auto ccr = args["query"];

    // First make sure that we've updated any expired cert first
    auto pub_key = ccr["pub_key"].as<std::string>();
    auto const full_skid = CertStatus::getFullSkId(pub_key);
    auto cert_status_factory(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    postUpdateToNextCertToExpire(cert_status_factory, shared_status_pv, ca_db, issuer_id, full_skid);

    auto type = getStructureValue<const std::string>(ccr, "type");
    auto name = getStructureValue<const std::string>(ccr, "name");
    auto organization = getStructureValue<const std::string>(ccr, "organization");
    auto usage = getStructureValue<uint16_t>(ccr, "usage");

    try {
        certstatus_t state = UNKNOWN;
        // Call the authenticator specific verifier if not the default type
        if (type.compare(PVXS_DEFAULT_AUTH_TYPE) != 0) {
            const auto authenticator = certs::Auth::getAuth(type);
            if (!authenticator->verify(ccr)) throw std::runtime_error("CCR claims are invalid");
            state = VALID;
        } else {
            state = PENDING_APPROVAL;
            if ((IS_USED_FOR_(usage, ssl::kForClientAndServer) && !config.cert_hybrid_require_approval) ||
                (IS_USED_FOR_(usage, ssl::kForClient) && !config.cert_client_require_approval) ||
                (IS_USED_FOR_(usage, ssl::kForServer) && !config.cert_server_require_approval)) {
                state = VALID;
            }
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

        // If pending approval then check if it has already been approved
        if (state == PENDING_APPROVAL) {
            if (getPriorApprovalStatus(ca_db, name, country, organization, organization_unit)) {
                state = VALID;
            }
        }

        // If config uri base provided then use it
        std::string config_uri_base = ccr["config_uri_base"].as<std::string>();

        // Create a certificate factory
        auto certificate_factory = CertFactory(serial, key_pair, name, country, organization, organization_unit, not_before, not_after, usage, config_uri_base,
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
 * Retrieves the status of the certificate identified by the pv_name.
 * This will verify the certificate chain back to the root certificate for all certificates that are managed by this PVACMS
 * so the status returned will certify that the entity cert (and its whole chain)
 * is valid
 *
 * @param config
 * @param ca_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The SharedWildcardPV object to store the retrieved status.
 * @param pv_name The status pv requested.
 * @param serial
 * @param issuer_id
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param ca_pkey The CA's private key.
 * @param ca_cert The CA's certificate.
 * @param ca_chain The CA's certificate chain.
 *
 * @return void
 */
void onGetStatus(const ConfigCms &config, const sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, const std::string &pv_name,
                 const serial_number_t serial, const std::string &issuer_id, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
                 const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        std::vector<serial_number_t> ca_serial_numbers;
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

        // Get all other serial numbers to check (CA and CA chain)
        ca_serial_numbers.push_back(CertStatusFactory::getSerialNumber(ca_cert));
        for (auto i = 0u; i < sk_X509_num(ca_chain.get()); ++i) {
            ca_serial_numbers.push_back(CertStatusFactory::getSerialNumber(sk_X509_value(ca_chain.get(), i)));
        }

        for (auto ca_serial_number : ca_serial_numbers) {
            getWorstCertificateStatus(ca_db, ca_serial_number, status, status_date);
        }

        auto now = std::time(nullptr);
        auto cert_status = cert_status_creator.createPVACertificateStatus(serial, status, now, status_date);
        postCertificateStatus(status_pv, pv_name, serial, cert_status);
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS: %s\n", e.what());
        postCertificateStatus(status_pv, pv_name, serial);
    }
}

/**
 * Revokes the certificate identified by the pv_name
 *
 * @param config
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
void onRevoke(const ConfigCms &config, const sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
              const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
              const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        Guard G(status_update_lock);
        std::string issuer_id;
        serial_number_t serial;
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
        log_info_printf(pvacms, "%s ==> REVOKED\n", getCertId(issuer_id, serial).c_str());
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error revoking certificate: %s\n", e.what());
        op->error(SB() << "Error revoking certificate: " << e.what());
    }
}

/**
 * Approves the certificate identified by the pv_name
 *
 * @param config
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
void onApprove(const ConfigCms &config, const sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
               const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
               const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        Guard G(status_update_lock);
        std::string issuer_id;
        serial_number_t serial;
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
        updateCertificateStatus(ca_db, serial, new_state, 1, {PENDING_APPROVAL});

        auto cert_status = cert_status_creator.createPVACertificateStatus(serial, new_state, status_date);
        postCertificateStatus(status_pv, pv_name, serial, cert_status);
        switch (new_state) {
            case VALID:
            case EXPIRED:
            case PENDING:
                log_info_printf(pvacms, "%s ==> %s\n", getCertId(issuer_id, serial).c_str(), CERT_STATE(new_state));
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
 * @param config
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
void onDeny(const ConfigCms &config, const sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op,
            const std::string &pv_name, const std::list<std::string> &parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert,
            const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    Value status_value(CertStatus::getStatusPrototype());
    const auto cert_status_creator(CertStatusFactory(ca_cert, ca_pkey, ca_chain, config.cert_status_validity_mins));
    try {
        Guard G(status_update_lock);
        std::string issuer_id;
        serial_number_t serial;
        std::tie(issuer_id, serial) = getParameters(parameters);
        log_debug_printf(pvacms, "DENY: Certificate %s:%llu\n", issuer_id.c_str(), serial);

        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id << ", is not our issuer ID: " << our_issuer_id);
        }

        // set status value
        certs::updateCertificateStatus(ca_db, serial, REVOKED, 0, {PENDING_APPROVAL});

        const auto revocation_date = std::time(nullptr);
        const auto cert_status = cert_status_creator.createPVACertificateStatus(serial, REVOKED, revocation_date, revocation_date);
        postCertificateStatus(status_pv, pv_name, serial, cert_status);
        log_info_printf(pvacms, "%s ==> REVOKED (Approval Request Denied)\n", getCertId(issuer_id, serial).c_str());
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error denying certificate request: %s\n", e.what());
        op->error(SB() << "Error denying certificate request: " << e.what());
    }
}

/**
 * @brief Get the issuer ID and serial number from the parameters
 *
 * @param parameters The list of parameters from the SharedWildcardPV
 * @return A tuple containing the issuer ID and serial number
 */
std::tuple<std::string, uint64_t> getParameters(const std::list<std::string> &parameters) {
    // get serial and issuer from URI parameters
    auto it = parameters.begin();
    const std::string &issuer_id = *it;

    const std::string &serial_string = *++it;
    uint64_t serial;
    try {
        serial = std::stoull(serial_string);
    } catch (std::invalid_argument &) {
        throw std::runtime_error(SB() << "Conversion error: Invalid argument. Serial in PV name is not a number: " << serial_string);
    } catch (std::out_of_range &) {
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
 * @param is_initialising true if we are in the initializing state when called
 */
void getOrCreateCaCertificate(ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &ca_chain, bool &is_initialising) {
    CertData cert_data;
    try {
        cert_data = IdFileFactory::create(config.ca_keychain_file, config.ca_keychain_pwd)->getCertDataFromFile();
    } catch (...) {
    }
    auto key_pair = cert_data.key_pair;

    if (!key_pair) {
        is_initialising = true; // Let caller know that we've created a new Cert and Key
        key_pair = IdFileFactory::createKeyPair();
        cert_data = createCaCertificate(config, ca_db, key_pair);
        createDefaultAdminACF(config, cert_data.cert);
        createAdminClientCert(config, ca_db, key_pair->pkey, cert_data.cert, cert_data.ca);
    }

    ca_pkey = std::move(key_pair->pkey);
    ca_cert = std::move(cert_data.cert);
    ca_chain = cert_data.ca;
}

/**
 * @brief Create the default admin ACF file
 *
 * @param config the config to use to get the ACF filename
 * @param ca_cert the CA certificate to use to get the issuer ID and common name
 */
void createDefaultAdminACF(const ConfigCms &config, const ossl_ptr<X509> &ca_cert) {
    auto cn = CertStatus::getCommonName(ca_cert);

    std::string extension = config.ca_acf_filename.substr(config.ca_acf_filename.find_last_of(".") + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    std::ofstream out_file(config.ca_acf_filename, std::ios::out | std::ios::trunc);
    if (!out_file) {
        throw std::runtime_error("Failed to open ACF file for writing: " + config.ca_acf_filename);
    }

    (extension == "yaml" || extension == "yml") ? out_file << "# EPICS YAML\n"
                                                              "version: 1.0\n"
                                                              "\n"
                                                              "# user access groups\n"
                                                              "uags:\n"
                                                              "  - name: CMS_ADMIN\n"
                                                              "    users:\n"
                                                              "      - admin\n"
                                                              "\n"
                                                              "# Access security group definitions\n"
                                                              "asgs:\n"
                                                              "  - name: DEFAULT\n"
                                                              "    rules:\n"
                                                              "      - level: 0\n"
                                                              "        access: READ\n"
                                                              "      - level: 1\n"
                                                              "        access: WRITE\n"
                                                              "        uags:\n"
                                                              "          - CMS_ADMIN\n"
                                                              "        methods:\n"
                                                              "          - x509\n"
                                                              "        authorities:\n"
                                                              "          - "
                                                           << cn << std::endl
                                                : out_file << "UAG(CMS_ADMIN) {admin}\n"
                                                              "\n"
                                                              "ASG(DEFAULT) {\n"
                                                              "    RULE(0,READ)\n"
                                                              "    RULE(1,WRITE) {\n"
                                                              "        UAG(CMS_ADMIN)\n"
                                                              "        METHOD(\"x509\")\n"
                                                              "        AUTHORITY(\""
                                                           << cn
                                                           << "\")\n"
                                                              "    }\n"
                                                              "}"
                                                           << std::endl;

    out_file.close();

    std::cout << "Created Default ACF file: " << config.ca_acf_filename << std::endl;
}

/**
 * @brief Add a new admin user to the ACF file
 *
 * @param filename The path to the ACF file
 * @param admin_name The name of the new admin to add
 */
void addNewAdminToAcfFile(const std::string &filename, const std::string &admin_name) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Read the file into a string
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string content = buffer.str();
    infile.close();

    // Regex to find and update the UAG(CMS_ADMIN) block
    std::regex uag_regex(R"(UAG\(CMS_ADMIN\)\s*\{([^}]*)\})");
    std::smatch match;

    // Check if the UAG(CMS_ADMIN) block exists
    if (std::regex_search(content, match, uag_regex)) {
        std::string admins = match[1].str();

        // Split the admins string into a list of admin names
        std::vector<std::string> admin_list;
        size_t start = 0, end;
        while ((end = admins.find(", ", start)) != std::string::npos) {
            admin_list.push_back(admins.substr(start, end - start));
            start = end + 2;
        }
        if (start < admins.size()) {
            admin_list.push_back(admins.substr(start));
        }

        // Check if admin_name is already in the list
        if (std::find(admin_list.begin(), admin_list.end(), admin_name) == admin_list.end()) {
            admin_list.push_back(admin_name);
        }

        // Rebuild the admins string with ", " separation
        admins = "";
        for (size_t i = 0; i < admin_list.size(); ++i) {
            if (i > 0) {
                admins += ", ";
            }
            admins += admin_list[i];
        }

        // Replace the matched UAG block with the updated list
        content = std::regex_replace(content, uag_regex, "UAG(CMS_ADMIN) {" + admins + "}");
    } else {
        throw std::runtime_error("UAG(CMS_ADMIN) block not found in file: " + filename);
    }

    // Write back to the file
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    outfile << content;
    outfile.close();
}

/**
 * @brief Adds a new admin entry to a YAML file.
 *
 * This method modifies the specified YAML file by adding a new admin user to the
 * users list in the CMS_ADMIN user access group
 *
 * @param filename The path to the YAML file where the admin information will be added.
 * @param admin_name The name of the new admin to be added.
 */
void addNewAdminToYamlFile(const std::string &filename, const std::string &admin_name) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string content = buffer.str();
    infile.close();

    // Regex to find the `CMS_ADMIN` section and `users` list
    std::regex yaml_regex(R"(- name:\s*CMS_ADMIN\s*[\r\n]+[^\S\r\n]*users:\s*[\r\n]+((?:[^\S]*-\s+[^\r\n]+[\r\n]*)*))");
    std::smatch match;

    if (std::regex_search(content, match, yaml_regex)) {
        std::string users_block = match[1].str();  // The captured `users` list (indented list of users)

        // Check if `admin_name` is already in the list
        std::regex user_regex("-\\s+" + std::regex_replace(admin_name, std::regex(R"([\\.^$|()\[\]{}*+?])"), R"(\\$&)"));
        if (!std::regex_search(users_block, user_regex)) {
            // Append the new admin with correct indentation
            users_block = users_block.substr(0, users_block.length() - 1);
            users_block += "      - " + admin_name + "\n\n";
        }

        // Replace the matched users block with the updated block
        content.replace(match.position(1), match.length(1), users_block);

        // Write back the updated YAML
        std::ofstream outfile(filename);
        if (!outfile.is_open()) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }
        outfile << content;
        outfile.close();

        std::cout << "Admin user '" << admin_name << "' successfully added to 'CMS_ADMIN'." << std::endl;
    } else {
        throw std::runtime_error("CMS_ADMIN users list not found in YAML file: " + filename);
    }
}

/**
 * @brief Add new admin user to the existing ACF file
 *
 * Handles both legacy and new yaml format
 *
 * @param config the config to read to find out the name of the acf file
 * @param admin_name the admin name to add
 */
void addUserToAdminACF(const ConfigCms &config, const std::string &admin_name) {
    std::string extension = config.ca_acf_filename.substr(config.ca_acf_filename.find_last_of(".") + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    if (extension == "acf") {
        addNewAdminToAcfFile(config.ca_acf_filename, admin_name);
    } else if (extension == "yaml" || extension == "yml") {
        addNewAdminToYamlFile(config.ca_acf_filename, admin_name);
    } else {
        throw std::invalid_argument("Unsupported file extension: " + extension);
    }
}

/**
 * @brief Create a default admin client certificate
 *
 * @param config The configuration to use to get the parameters to create cert
 * @param ca_db The database to store the certificate in
 * @param ca_pkey The CA's private key to sign the certificate
 * @param ca_cert The CA's certificate
 * @param ca_chain The CA's certificate chain
 * @param ca_pkey The CA's key pair to use to create the certificate
 * @param admin_name The optional name of the administrator (defaults to admin if not specified)
 */
void createAdminClientCert(const ConfigCms &config, sql_ptr &ca_db, ossl_ptr<EVP_PKEY> &ca_pkey, ossl_ptr<X509> &ca_cert,
                                  ossl_shared_ptr<STACK_OF(X509)> &ca_chain, const std::string &admin_name) {
    auto key_pair = IdFileFactory::createKeyPair();
    auto serial = generateSerial();

    // Get other certificate parameters from request
    auto country = getCountryCode();
    auto name = admin_name;
    auto organization = "";
    auto organization_unit = "";
    time_t not_before(time(nullptr));
    time_t not_after(not_before + (365 + 1) * 24 * 60 * 60);  // 1yrs

    // Create a certificate factory
    auto certificate_factory = CertFactory(serial, key_pair, name, country, organization, organization_unit, not_before, not_after, ssl::kForClient, true,
                                           ca_cert.get(), ca_pkey.get(), ca_chain.get(), VALID);

    // Create the certificate using the certificate factory, store it in the database and return the PEM string
    auto pem_string = createCertificatePemString(ca_db, certificate_factory);

    auto cert_file_factory = IdFileFactory::create(config.admin_keychain_file, config.admin_keychain_pwd, key_pair, nullptr, nullptr, pem_string);
    cert_file_factory->writeIdentityFile();

    std::string from = std::ctime(&certificate_factory.not_before_);
    std::string to = std::ctime(&certificate_factory.not_after_);
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
 * @param ca_chain
 */
void ensureServerCertificateExists(const ConfigCms &config, sql_ptr &ca_db, const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &ca_chain) {
    CertData cert_data;
    try {
        cert_data = IdFileFactory::create(config.tls_keychain_file, config.tls_keychain_pwd)->getCertDataFromFile();
    } catch (...) {
    }

    if (!cert_data.key_pair) {
        createServerCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain, IdFileFactory::createKeyPair());
    }
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
CertData createCaCertificate(const ConfigCms &config, sql_ptr &ca_db, const std::shared_ptr<KeyPair> &key_pair) {
    // Set validity to 4 yrs
    time_t not_before(time(nullptr));
    time_t not_after(not_before + (4 * 365 + 1) * 24 * 60 * 60);  // 4yrs

    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial, key_pair, config.ca_name, config.ca_country, config.ca_organization, config.ca_organizational_unit,
                                           not_before, not_after, ssl::kForCa, config.cert_status_subscription);

    auto pem_string = createCertificatePemString(ca_db, certificate_factory);

    // Create keychain file containing certs, private key and chain
    auto cert_file_factory = IdFileFactory::create(config.ca_keychain_file, config.ca_keychain_pwd, key_pair, nullptr, nullptr, pem_string);

    cert_file_factory->writeIdentityFile();

    return cert_file_factory->getCertData(key_pair);
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
void createServerCertificate(const ConfigCms &config, sql_ptr &ca_db, const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &ca_chain, const std::shared_ptr<KeyPair> &key_pair) {
    // Generate a new serial number
    auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial, key_pair, config.pvacms_name, config.pvacms_country, config.pvacms_organization,
                                           config.pvacms_organizational_unit, getNotBeforeTimeFromCert(ca_cert.get()), getNotAfterTimeFromCert(ca_cert.get()),
                                           ssl::kForCMS, config.cert_status_subscription, ca_cert.get(), ca_pkey.get(), ca_chain.get());

    auto cert = createCertificate(ca_db, certificate_factory);

    // Create keychain file containing certs, private key and null chain
    auto pem_string = CertFactory::certAndCasToPemString(cert, certificate_factory.certificate_chain_.get());
    auto cert_file_factory = IdFileFactory::create(config.tls_keychain_file, config.tls_keychain_pwd, key_pair, nullptr, nullptr, pem_string);

    cert_file_factory->writeIdentityFile();
}

/**
 * @brief Ensure that start and end dates are within the validity of issuer cert
 *
 * @param cert_factory the cert factory to check
 */
void ensureValidityCompatible(const CertFactory &cert_factory) {
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
std::string extractCountryCode(const std::string &locale_str) {
    // Look for underscore
    auto pos = locale_str.find('_');
    if (pos == std::string::npos || pos + 3 > locale_str.size()) {
        return "";
    }

    std::string country_code = locale_str.substr(pos + 1, 2);
    std::transform(country_code.begin(), country_code.end(), country_code.begin(), ::toupper);
    return country_code;
}

/**
 * @brief Get the country code from the environment
 *
 * @return The country code
 */
std::string getCountryCode() {
    // 1. Try from std::locale("")
    {
        std::locale loc("");
        std::string name = loc.name();
        if (name != "C" && name != "POSIX") {
            std::string cc = extractCountryCode(name);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 2. If we failed, try the LANG environment variable
    {
        const char *lang = std::getenv("LANG");
        if (lang && *lang) {
            std::string locale_str(lang);
            std::string cc = extractCountryCode(locale_str);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 3. Default to "US" if both attempts failed
    return "US";
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
 * @brief Set a value in a Value object marking any changes to the field if the values changed and if not then
 * the field is unmarked.  Doesn't work for arrays or enums so you need to do that manually.
 *
 * @param target The Value object to set the value in
 * @param field The field to set the value in
 * @param new_value The new value to set
 */
template <typename T>
void setValue(Value &target, const std::string &field, const T &new_value) {
    auto current_field = target[field];
    auto current_value = current_field.as<T>();
    if (current_value == new_value) {
        target[field].unmark();  // Assuming unmark is a valid method for indicating no change needed
    } else {
        target[field] = new_value;
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

Value postCertificateStatus(server::SharedWildcardPV &status_pv, const std::string &pv_name, uint64_t serial, const PVACertificateStatus &cert_status) {
    Guard G(status_pv_lock);
    Value status_value;
    const auto was_open = status_pv.isOpen(pv_name);
    if (was_open) {
        status_value = status_pv.fetch(pv_name);
        status_value["status.value.choices"].unmark();
        status_value["ocsp_status.value.choices"].unmark();
    } else {
        status_value = CertStatus::getStatusPrototype();
    }
    setValue<uint64_t>(status_value, "serial", serial);
    setValue<uint32_t>(status_value, "status.value.index", cert_status.status.i);
    setValue<time_t>(status_value, "status.timeStamp.secondsPastEpoch", time(nullptr));
    setValue<std::string>(status_value, "state", cert_status.status.s);
    setValue<time_t>(status_value, "ocsp_status.timeStamp.secondsPastEpoch", time(nullptr));
    setValue<uint32_t>(status_value, "ocsp_status.value.index", cert_status.ocsp_status.i);
    // Get ocsp info if specified
    if (cert_status.ocsp_bytes.empty()) {
        setValue<std::string>(status_value, "ocsp_state", SB() << "**UNCERTIFIED**: " << cert_status.ocsp_status.s);
    } else {
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
 * @param op
 * @param our_issuer_id The issuer ID of the certificate.
 * @param serial The serial number of the certificate.
 * @param error_status error status.
 * @param error_severity error severity
 * @param error_message The error message
 */
void postCertificateErrorStatus(server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op, const std::string &our_issuer_id,
                                const uint64_t &serial, const int32_t error_status, const int32_t error_severity, const std::string &error_message) {
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
    {
        Guard G(status_pv_lock);
        if (status_pv.isOpen(pv_name))
            status_pv.post(pv_name, status_value);
        else {
            status_pv.open(pv_name, status_value);
        }
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

/**
 * @brief Post an update to the next certificate that is becoming valid
 *
 * This function will post an update to the next certificate that is becoming VALID.
 * Certificates that are becoming valid are those that are in the PENDING state
 * and the not before time is now in the past.
 *
 * We can change the status of the certificate to VALID and post the status to the shared wildcard PV.
 *
 * We only do one at a time so we can reschedule the rest for the next loop
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
void postUpdateToNextCertBecomingValid(const CertStatusFactory &cert_status_creator, const StatusMonitor &status_monitor_params) {
    Guard G(status_update_lock);
    sqlite3_stmt *stmt;
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
                log_info_printf(pvacmsmonitor, "%s ==> VALID\n", getCertId(status_monitor_params.issuer_id_, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(status_monitor_params.ca_db_.get()));
    }
}

/**
 * @brief Post an update to the next certificate that is becoming expired
 *
 * This function will post an update to the next certificate that is becoming expired.
 * Certificates that are becoming expired are those that are in the VALID, PENDING_APPROVAL or PENDING state
 * and the not after time is now in the past.
 *
 * We can change the status of the certificate to EXPIRED and post the status to the shared wildcard PV.
 *
 * We only do one at a time so we can reschedule the rest for the next loop
 *
 * @param cert_status_creator The certificate status creator
 * @param status_pv the status pv
 * @param ca_db the database
 * @param issuer_id the issuer ID
 * @param full_skid optional full SKID - if provided will search only for a certificate that matches
 */
bool postUpdateToNextCertToExpire(const CertStatusFactory &cert_status_creator, server::SharedWildcardPV &status_pv, const sql_ptr &ca_db,
                                  const std::string &issuer_id, const std::string &full_skid) {
    Guard G(status_update_lock);
    bool updated{false};
    sqlite3_stmt *stmt;
    std::string expired_sql(full_skid.empty() ? SQL_CERT_TO_EXPIRED : SQL_CERT_TO_EXPIRED_WITH_FULL_SKID);
    const std::vector<certstatus_t> expired_status{VALID, PENDING_APPROVAL, PENDING};
    expired_sql += getValidStatusesClause(expired_status);
    if (sqlite3_prepare_v2(ca_db.get(), expired_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, expired_status);
        if (!full_skid.empty()) sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":skid"), full_skid.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            updated = true;
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertUri(GET_MONITOR_CERT_STATUS_ROOT, issuer_id, serial));
                updateCertificateStatus(ca_db, serial, EXPIRED, -1, {VALID, PENDING_APPROVAL, PENDING});
                auto status_date = std::time(nullptr);
                auto cert_status = cert_status_creator.createPVACertificateStatus(serial, EXPIRED, status_date);
                postCertificateStatus(status_pv, pv_name, serial, cert_status);
                log_info_printf(pvacmsmonitor, "%s ==> EXPIRED\n", getCertId(issuer_id, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(ca_db.get()));
    }
    return updated;
}

/**
 * @brief Post an update to the next certificate that is becoming expired
 *
 * This function will post an update to the next certificate that is becoming expired.
 * Certificates that are becoming expired are those that are in the VALID, PENDING_APPROVAL or PENDING state
 * and the not after time is now in the past.
 *
 * We can change the status of the certificate to EXPIRED and post the status to the shared wildcard PV.
 *
 * We only do one at a time so we can reschedule the rest for the next loop
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
void postUpdateToNextCertToExpire(const CertStatusFactory &cert_status_creator, const StatusMonitor &status_monitor_params) {
    postUpdateToNextCertToExpire(cert_status_creator, status_monitor_params.status_pv_, status_monitor_params.ca_db_, status_monitor_params.issuer_id_);
}

/**
 * @brief Post an update to the all certificates whose statuses are becoming invalid
 *
 * This function will post an update to the all certificates whose statuses are becoming invalid.
 * Certificates that are becoming invalid are those that are in the VALID, PENDING or PENDING_APPROVAL state
 * and the status validity time is now nearly up.  We use the timeout value (default 5 seconds) to determine
 * "nearly up".
 *
 * It uses the set of active serials that are updated everytime a connection is opened or closed.
 * So only certificates that are currently active will be updated.
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
void postUpdatesToExpiredStatuses(const CertStatusFactory &cert_status_creator, const StatusMonitor &status_monitor_params) {
    auto const serials = status_monitor_params.getActiveSerials();
    if (serials.empty()) return;

    sqlite3_stmt *stmt;
    std::string validity_sql(SQL_CERT_BECOMING_INVALID);
    validity_sql += getSelectedSerials(serials);
    const std::vector<certstatus_t> validity_status{VALID, PENDING, PENDING_APPROVAL};
    validity_sql += getValidStatusesClause(validity_status);
    if (sqlite3_prepare_v2(status_monitor_params.ca_db_.get(), validity_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, validity_status);

        // For each status in this state
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            int status = sqlite3_column_int(stmt, 1);
            uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertUri(GET_MONITOR_CERT_STATUS_ROOT, status_monitor_params.issuer_id_, serial));
                auto status_date = std::time(nullptr);
                auto cert_status = cert_status_creator.createPVACertificateStatus(serial, (certstatus_t)status, status_date);
                postCertificateStatus(status_monitor_params.status_pv_, pv_name, serial, cert_status);
                status_monitor_params.setValidity(serial, cert_status.status_valid_until_date.t);
                log_debug_printf(pvacmsmonitor, "%s ==> \u21BA \n", getCertId(status_monitor_params.issuer_id_, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(status_monitor_params.ca_db_.get()));
    }
}

/**
 * @brief The main loop for the certificate monitor.
 *
 * This function will post an update to the next certificate that is becoming valid,
 * the next certificate that is becoming expired
 * and any certificates whose statuses are becoming invalid.
 *
 * @param status_monitor_params The status monitor parameters
 * @return true if we should continue to run the loop, false if we should exit
 */
timeval statusMonitor(const StatusMonitor &status_monitor_params) {
    log_debug_printf(pvacmsmonitor, "Certificate Monitor Thread Wake Up%s", "\n");
    auto cert_status_creator(CertStatusFactory(status_monitor_params.ca_cert_, status_monitor_params.ca_pkey_, status_monitor_params.ca_chain_,
                                               status_monitor_params.config_.cert_status_validity_mins));
    // Search for next cert to become valid and update it
    postUpdateToNextCertBecomingValid(cert_status_creator, status_monitor_params);

    // Search for any certs that have expired
    postUpdateToNextCertToExpire(cert_status_creator, status_monitor_params);

    // Search for certs that are becoming invalid
    if (!status_monitor_params.active_status_validity_.empty()) {
        postUpdatesToExpiredStatuses(cert_status_creator, status_monitor_params);
    }

    log_debug_printf(pvacmsmonitor, "Certificate Monitor Thread Sleep%s", "\n");
    return {};
}

std::map<const std::string, std::unique_ptr<client::Config>> getAuthNConfigMap() {
    std::map<const std::string, std::unique_ptr<client::Config>> authn_config_map;

    for (auto &authn_entry : AuthRegistry::getRegistry()) {
        auto &auth = authn_entry.second;
        std::unique_ptr<client::Config> auth_config;
        auth->fromEnv(auth_config);
        auth->configure(*auth_config);
        authn_config_map[authn_entry.first] = std::move(auth_config);
    }
    return authn_config_map;
}

int readParameters(int argc, char *argv[], const char *program_name, ConfigCms &config,
                   std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map, bool &verbose, std::string &admin_name) {
    std::string ca_password_file, pvacms_password_file, admin_password_file;
    bool show_version{false}, help{false};

    CLI::App app{"PVACMS - Certificate Management Service"};

    // Define options
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-V,--version", show_version, "Print version and exit.");

    app.add_option("-c,--ca-keychain", config.ca_keychain_file, "Specify CA keychain file location");
    app.add_option("--ca-keychain-pwd", ca_password_file, "Specify CA keychain password file location");
    app.add_option("--ca-name", config.ca_name, "Specify the CA's name. Used if we need to create a root certificate");
    app.add_option("--ca-org", config.ca_organization, "Specify the CA's Organization. Used if we need to create a root certificate");
    app.add_option("--ca-org-unit", config.ca_organizational_unit, "Specify the CA's Organization Unit. Used if we need to create a root certificate");
    app.add_option("--ca-country", config.ca_country, "Specify the CA's Country. Used if we need to create a root certificate");
    app.add_option("-d,--cert-db", config.ca_db_filename, "Specify cert db file location");

    app.add_option("-p,--pvacms-keychain", config.tls_keychain_file, "Specify PVACMS keychain file location");
    app.add_option("--pvacms-keychain-pwd", pvacms_password_file, "Specify PVACMS keychain password file location");
    app.add_option("--pvacms-name", config.pvacms_name, "Specify the PVACMS name. Used if we need to create a PVACMS certificate");
    app.add_option("--pvacms-org", config.pvacms_organization, "Specify the PVACMS Organization. Used if we need to create a PVACMS certificate");
    app.add_option("--pvacms-org-unit", config.pvacms_organizational_unit,
                   "Specify the PVACMS Organization Unit. Used if we need to create a PVACMS certificate");
    app.add_option("--pvacms-country", config.pvacms_country, "Specify the PVACMS Country. Used if we need to create a PVACMS certificate");

    app.add_option("-a,--admin-keychain", config.admin_keychain_file, "Specify PVACMS admin user's keychain file location");
    app.add_option("--admin-keychain-new", admin_name, "Generate a new admin keychain and exit.");
    app.add_option("--admin-keychain-pwd", admin_password_file, "Specify PVACMS admin user's keychain password file location");
    app.add_option("--acf", config.ca_acf_filename, "Admin Security Configuration File");

    app.add_flag("--client-require-approval", config.cert_client_require_approval, "Generate Client Certificates in PENDING_APPROVAL state");
    app.add_flag("--server-require-approval", config.cert_server_require_approval, "Generate Server Certificates in PENDING_APPROVAL state");
    app.add_flag("--hybrid-require-approval", config.cert_hybrid_require_approval, "Generate Hybrid Certificates in PENDING_APPROVAL state");

    app.add_option("--status-validity-mins", config.cert_status_validity_mins, "Set Status Validity Time in Minutes");
    app.add_flag("--status-monitoring-enabled", config.cert_status_subscription,
                 "Require Peers to monitor Status of Certificates Generated by this server by default.  Can be overridden in each CCR");

    // Add any parameters for any registered authn methods
    for (auto &authn_entry : AuthRegistry::getRegistry()) authn_entry.second->addOptions(app, authn_config_map);

    CLI11_PARSE(app, argc, argv);

    if (help) {
        std::string authn_help, authn_options;
        for (auto &authn_entry : AuthRegistry::getRegistry()) authn_options += authn_entry.second->getOptionsPlaceholderText();
        for (auto &authn_entry : AuthRegistry::getRegistry()) authn_help += authn_entry.second->getOptionsHelpText();

        std::cout << "PVACMS: PVAccess Certificate Management Service\n"
                  << std::endl
                  << "Manages Certificates for a Secure PVAccess network.  The Certificate Authority.  Handles Create \n"
                  << "and Revoke requests.  Manages Certificate lifecycles and provides live OCSP certificate status.\n"
                  << std::endl
                  << "Also can be used to re-generate the admin certificate that is required to administer the certificates.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [admin options]" << authn_options << " [options]\n"
                  << "                                             Run PVACMS.  Interrupt to quit\n"
                  << "  " << program_name << " (-h | --help)                       Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                    Print version and exit\n"
                  << "  " << program_name << " [admin options] --admin-keychain-new <new_name>\n"
                  << "                                             Generate a new Admin User's keychain file, update the ACF file, and exit\n"
                  << std::endl
                  << "options:\n"
                  << "  (-c | --ca-keychain) <ca_keychain>         Specify CA keychain file location. Default ${XDG_CONFIG_HOME}/pva/1.3/ca.p12\n"
                  << "        --ca-keychain-pwd <file>             Specify location of file containing CA keychain file's password\n"
                  << "        --ca-name <name>                     Specify name (CN) to be used for CA certificate. Default `EPICS Root CA`\n"
                  << "        --ca-org <name>                      Specify organisation (O) to be used for CA certificate. Default `ca.epics.org`\n"
                  << "        --ca-org-unit <name>                 Specify organisational unit (OU) to be used for CA certificate. Default `EPICS Certificate "
                     "Authority`\n"
                  << "        --ca-country <name>                  Specify country (C) to be used for CA certificate. Default `US`\n"
                  << "  (-d | --cert-db) <db_name>                 Specify cert db file location. Default ${XDG_DATA_HOME}/pva/1.3/certs.db\n"
                  << "  (-p | --pvacms-keychain) <pvacms_keychain> Specify PVACMS keychain file location. Default ${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12\n"
                  << "        --pvacms-keychain-pwd <file>         Specify location of file containing PVACMS keychain file's password\n"
                  << "        --pvacms-name <name>                 Specify name (CN) to be used for PVACMS certificate. Default `PVACMS Service`\n"
                  << "        --pvacms-org <name>                  Specify organisation (O) to be used for PVACMS certificate. Default `ca.epics.org`\n"
                  << "        --pvacms-org-unit <name>             Specify organisational unit (OU) to be used for PVACMS certificate. Default `EPICS PVA "
                     "Certificate Management Service`\n"
                  << "        --pvacms-country <name>              Specify country (C) to be used for PVACMS certificate. Default US\n"
                  << "        --client-require-approval            Generate Client Certificates in PENDING_APPROVAL state\n"
                  << "        --hybrid-require-approval            Generate Hybrid Certificates in PENDING_APPROVAL state\n"
                  << "        --server-require-approval            Generate Server Certificates in PENDING_APPROVAL state\n"
                  << "        --status-monitoring-enabled          Require Peers to monitor Status of Certificates Generated by this\n"
                  << "                                             server by default. Can be overridden in each CCR\n"
                  << "        --status-validity-mins               Set Status Validity Time in Minutes\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << std::endl
                  << "admin options:\n"
                  << "        --acf <acf_file>                     Specify Admin Security Configuration File. Default ${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf\n"
                  << "  (-a | --admin-keychain) <admin_keychain>   Specify Admin User's keychain file location. Default ${XDG_CONFIG_HOME}/pva/1.3/admin.p12\n"
                  << "        --admin-keychain-pwd <file>          Specify location of file containing Admin User's keychain file password\n"
                  << authn_help << std::endl;
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            exit(10);
        }
        std::cout << pvxs::version_information;
        exit(0);
    }

    // New admin can only be specified with --acf and/or --admin-keychain-pwd, and/or --admin-keychain-pwd
    if (!admin_name.empty()) {
        for (auto arg = 1; arg < argc; ++arg) {
            const std::string option = argv[arg];
            if (option == "-a" || option == "--admin-keychain" || option == "--admin-keychain-pwd" || option == "--acf" || option == "--admin-keychain-new") {
                arg++;
            } else {
                std::cerr
                    << "Error: --admin-keychain-new option cannot be used with any options other than -a, --admin-keychain, --admin-keychain-pwd, or --acf.\n";
                exit(11);
            }
        }
    }

    // Make sure some directories exist and read some passwords
    if (!config.ca_keychain_file.empty()) config.ensureDirectoryExists(config.ca_keychain_file);
    if (!config.tls_keychain_file.empty()) config.ensureDirectoryExists(config.tls_keychain_file);
    if (!config.ca_acf_filename.empty()) config.ensureDirectoryExists(config.ca_acf_filename);
    if (!config.admin_keychain_file.empty()) config.ensureDirectoryExists(config.admin_keychain_file);
    if (!config.ca_db_filename.empty()) config.ensureDirectoryExists(config.ca_db_filename);
    if (!ca_password_file.empty()) {
        config.ensureDirectoryExists(ca_password_file);
        config.ca_keychain_pwd = config.getFileContents(ca_password_file);
    };
    if (!pvacms_password_file.empty()) {
        config.ensureDirectoryExists(pvacms_password_file);
        config.tls_keychain_pwd = config.getFileContents(pvacms_password_file);
    };
    if (!admin_password_file.empty()) {
        config.ensureDirectoryExists(admin_password_file);
        config.admin_keychain_pwd = config.getFileContents(admin_password_file);
    };

    // Override some settings for PVACMS
    config.tls_stop_if_no_cert = true;
    config.tls_client_cert_required = pvxs::impl::ConfigCommon::Optional;

    return 0;
}

}  // namespace certs
}  // namespace pvxs

int main(int argc, char *argv[]) {
    using namespace pvxs::certs;
    using namespace pvxs::server;

    try {
        std::map<serial_number_t, time_t> active_status_validity;
        // Get config
        auto config = ConfigCms::fromEnv();
        // And, get all configured authn configs
        auto authn_config_map = getAuthNConfigMap();

        pvxs::sql_ptr ca_db;
        auto program_name = argv[0];
        bool verbose = false;
        std::string ca_password_file, pvacms_password_file, admin_password_file, admin_name;

        auto parse_result = readParameters(argc, argv, program_name, config, authn_config_map, verbose, admin_name);
        if (parse_result) exit(parse_result);

        // Initialize SSL
        pvxs::ossl::sslInit();

        // Logger config from environment (so environment overrides verbose setting)
        if (verbose) logger_level_set("pvxs.certs.*", pvxs::Level::Info);
        pvxs::logger_config_env();

        // Initialize the certificates database
        initCertsDatabase(ca_db, config.ca_db_filename);

        // Get the CA Certificate
        pvxs::ossl_ptr<EVP_PKEY> ca_pkey;
        pvxs::ossl_ptr<X509> ca_cert;
        pvxs::ossl_shared_ptr<STACK_OF(X509)> ca_chain;

        // Get or create CA certificate
        auto is_initialising{false};
        getOrCreateCaCertificate(config, ca_db, ca_cert, ca_pkey, ca_chain, is_initialising);
        auto our_issuer_id = CertStatus::getSkId(ca_cert);

        if (!admin_name.empty()) {
            try {
                createAdminClientCert(config, ca_db, ca_pkey, ca_cert, ca_chain, admin_name);
                addUserToAdminACF(config, admin_name);
                std::cout << "Admin user \"" << admin_name << "\" has been added to list of administrators of this PVACMS" << std::endl;
                std::cout << "Restart the PVACMS for it to take effect" << std::endl;
            } catch (const std::runtime_error &e) {
                if (!is_initialising) throw std::runtime_error(std::string("Error creating admin user certificate: ") + e.what());
            }
            exit(0);
        }

        // Create this PVACMS server's certificate if it does not already exist
        ensureServerCertificateExists(config, ca_db, ca_cert, ca_pkey, ca_chain);

        // Set security if configured
        if (!config.ca_acf_filename.empty()) {
            asInitFile(config.ca_acf_filename.c_str(), "");
        } else {
            log_err_printf(pvacms, "****EXITING****: PVACMS Access Security Policy File Required%s", "\n");
            return 1;
        }

        // Create the PVs
        SharedPV create_pv(SharedPV::buildReadonly());
        SharedPV root_pv(SharedPV::buildReadonly());
        SharedWildcardPV status_pv(SharedWildcardPV::buildMailbox());

        // Create Root PV value which won't change
        // TODO what happens when it changes
        pvxs::Value root_pv_value = getRootValue(our_issuer_id, ca_cert, ca_chain);

        // RPC handlers
        pvxs::ossl_ptr<EVP_PKEY> ca_pub_key(X509_get_pubkey(ca_cert.get()));
        create_pv.onRPC([&config, &ca_db, &ca_pkey, &ca_cert, ca_chain, &our_issuer_id, &status_pv](
                            const SharedPV &pv, std::unique_ptr<ExecOp> &&op, pvxs::Value &&args) {
            onCreateCertificate(config, ca_db, status_pv, std::move(op), std::move(args), ca_pkey, ca_cert, ca_chain, our_issuer_id);
        });

        // Client Connect handlers GET/MONITOR
        status_pv.onFirstConnect([&config, &ca_db, &ca_pkey, &ca_cert, &ca_chain, &our_issuer_id, &active_status_validity](
                                     SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
            serial_number_t serial = 0;
            std::string issuer_id;
            std::tie(issuer_id, serial) = getParameters(parameters);
            onGetStatus(config, ca_db, our_issuer_id, pv, pv_name, serial, issuer_id, ca_pkey, ca_cert, ca_chain);

            // Add reference to this serial number
            active_status_validity.emplace(serial, 0);
        });
        status_pv.onLastDisconnect([&active_status_validity](SharedWildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
            pv.close(pv_name);

            // Remove reference to this serial number
            serial_number_t serial = 0;
            std::string issuer_id;
            std::tie(issuer_id, serial) = getParameters(parameters);
            active_status_validity.erase(serial);
        });

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

            // Get credentials for this operation
            auto creds = op->credentials();

            pvxs::ioc::Credentials credentials(*creds);

            // Get security client from channel
            pvxs::ioc::SecurityClient securityClient;

            static ASMember as_member;
            securityClient.update(as_member.mem, ASL1, credentials);

            if (!securityClient.canWrite()) {
                log_err_printf(pvacms, "PVACMS Client Not Authorised%s", "\n");
                op->error(pvxs::SB() << state << " operation not authorized on " << issuer_id << ":" << serial);
                return;
            }

            if (state == "REVOKED") {
                onRevoke(config, ca_db, our_issuer_id, pv, std::move(op), pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            } else if (state == "APPROVED") {
                onApprove(config, ca_db, our_issuer_id, pv, std::move(op), pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            } else if (state == "DENIED") {
                onDeny(config, ca_db, our_issuer_id, pv, std::move(op), pv_name, parameters, ca_pkey, ca_cert, ca_chain);
            } else {
                op->error(pvxs::SB() << "Invalid certificate state requested: " << state);
            }
        });

        StatusMonitor status_monitor_params(config, ca_db, our_issuer_id, status_pv, ca_cert, ca_pkey, ca_chain, active_status_validity);

        // Create a server with a certificate monitoring function attached to the cert file monitor timer
        // Return true to indicate that we want the file monitor time to run after this
        Server pva_server = Server(config, [&status_monitor_params](short evt) { return statusMonitor(status_monitor_params); });

        pva_server.addPV(RPC_CERT_CREATE, create_pv).addPV(GET_MONITOR_CERT_STATUS_PV, status_pv).addPV(kCertRoot, root_pv);
        root_pv.open(root_pv_value);

        if (verbose) {
            std::cout << "Effective config\n" << config;
        }

        try {
            std::cout << "PVACMS [" << our_issuer_id << "] Service Running" << std::endl;
            pva_server.run();
            std::cout << "PVACMS [" << our_issuer_id << "] Service Exiting" << std::endl;
        } catch (const std::exception &e) {
            log_err_printf(pvacms, "PVACMS error: %s\n", e.what());
        }

        return 0;
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error: %s\n", e.what());
        return 1;
    }
}
