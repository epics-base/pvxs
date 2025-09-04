/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The PVAccess Certificate Management Service.
 *
 *   pvacms.h
 *
 */
#ifndef PVXS_PVACMS_H
#define PVXS_PVACMS_H

#include <ctime>
#include <iostream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/sharedpv.h>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "configcms.h"
#include "openssl.h"
#include "ownedptr.h"
#include "wildcardpv.h"

#define SQL_CREATE_DB_FILE              \
    "BEGIN TRANSACTION; "               \
    "CREATE TABLE IF NOT EXISTS certs(" \
    "     serial INTEGER PRIMARY KEY,"  \
    "     skid TEXT,"                   \
    "     CN TEXT,"                     \
    "     O TEXT,"                      \
    "     OU TEXT,"                     \
    "     C TEXT,"                      \
    "     approved INTEGER,"            \
    "     not_before INTEGER,"          \
    "     not_after INTEGER,"           \
    "     renew_by INTEGER,"       \
    "     status INTEGER,"              \
    "     status_date INTEGER"          \
    "); "                               \
    "CREATE INDEX IF NOT EXISTS idx_certs_skid " \
    "     ON certs(skid); "            \
    "CREATE INDEX IF NOT EXISTS idx_certs_status " \
    "     ON certs(status); "          \
    "CREATE INDEX IF NOT EXISTS idx_certs_identity " \
    "     ON certs(CN, O, OU, C, status, not_before); "     \
    "CREATE INDEX IF NOT EXISTS idx_certs_not_after_skid " \
    "     ON certs(not_after, skid); " \
    "CREATE INDEX IF NOT EXISTS idx_certs_validity " \
    "     ON certs(not_before, not_after) ; " \
    "COMMIT;"

#define SQL_CHECK_EXISTS_DB_FILE       \
    "SELECT name "                     \
    "FROM sqlite_master "              \
    "WHERE type='table' "              \
    "  AND name='certs';"

#define SQL_CREATE_CERT               \
    "INSERT INTO certs ( "            \
    "     serial,"                    \
    "     skid,"                      \
    "     CN,"                        \
    "     O,"                         \
    "     OU,"                        \
    "     C,"                         \
    "     approved,"                  \
    "     not_before,"                \
    "     not_after,"                 \
    "     renew_by,"             \
    "     status,"                    \
    "     status_date"                \
    ") "                              \
    "VALUES ("                        \
    "     :serial,"                   \
    "     :skid,"                     \
    "     :CN,"                       \
    "     :O,"                        \
    "     :OU,"                       \
    "     :C,"                        \
    "     :approved,"                 \
    "     :not_before,"               \
    "     :not_after,"                \
    "     :renew_by,"            \
    "     :status,"                   \
    "     :status_date"               \
    ")"

#define SQL_DUPS_SUBJECT              \
    "SELECT COUNT(*) "                \
    "FROM certs "                     \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND OU = :OU "                 \
    "  AND C = :C "

#define SQL_DUPS_SUBJECT_KEY_IDENTIFIER \
    "SELECT COUNT(*) "                  \
    "FROM certs "                       \
    "WHERE skid = :skid "

// Delete certs that have become obsolete due to renewal
#define SQL_DELETE_RENEWER_CERTS      \
    "DELETE FROM certs "              \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND OU = :OU "                 \
    "  AND C = :C "                   \
    "  AND status IN (:status0, :status1, :status2, :status3) " \
    "  AND NOT (serial = :serial OR not_before = (  "      \
    "      SELECT not_before "       \
    "        FROM certs "            \
    "       WHERE CN = :CN "         \
    "         AND O = :O "           \
    "         AND OU = :OU "         \
    "         AND C = :C "           \
    "         AND status IN (:status0, :status1, :status2, :status3) " \
    "         AND renew_by != 0 " \
    "       ORDER BY not_before ASC " \
    "       LIMIT 1 "                \
    "      ) "                       \
    "    )"

// Get the original certificate being renewed
#define SQL_GET_RENEWED_CERT          \
    "SELECT serial"                   \
    "     , not_after "               \
    "     , renew_by "           \
    "     , status "                  \
    "FROM certs "                     \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND OU = :OU "                 \
    "  AND C = :C "                   \
    "  AND status IN (:status0, :status1, :status2, :status3) " \
    "  AND serial != :serial "        \
    "  AND renew_by != 0 "       \
    "LIMIT 1 "                        \

#define SQL_RENEW_CERTS               \
    "UPDATE certs "                   \
    "SET status = :status "           \
    "  , renew_by = :renew_by " \
    "  , status_date = :status_date " \
    "WHERE serial = :serial "

#define SQL_CERT_STATUS               \
    "SELECT status "                  \
    "     , status_date "             \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_VALIDITY             \
    "SELECT not_before "              \
    "     , not_after "               \
    "     , renew_by "           \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_SET_STATUS           \
    "UPDATE certs "                   \
    "SET status = :status "           \
    "  , status_date = :status_date " \
    "WHERE serial = :serial "

#define SQL_CERT_SET_STATUS_W_APPROVAL \
    "UPDATE certs "                    \
    "SET status = :status "            \
    "  , approved = :approved "        \
    "  , status_date = :status_date "  \
    "WHERE serial = :serial "

#define SQL_CERT_TO_VALID              \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_before <= strftime('%s', 'now') " \
    "  AND not_after > strftime('%s', 'now') "   \
    "  AND (renew_by = 0 OR renew_by > strftime('%s', 'now')) "

#define SQL_CERT_BECOMING_INVALID      \
    "SELECT serial, status "           \
    "FROM certs "                      \
    "WHERE "

#define SQL_CERT_TO_EXPIRED            \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_after <= strftime('%s', 'now') "

#define SQL_CERT_TO_EXPIRED_WITH_FULL_SKID      \
    "SELECT serial "                            \
    "FROM certs "                               \
    "WHERE not_after <= strftime('%s', 'now') " \
    "  AND skid = :skid "

#define SQL_CERT_TO_PENDING_RENEWAL    \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_before <= strftime('%s', 'now') " \
    "  AND not_after > strftime('%s', 'now') "   \
    "  AND renew_by != 0 "        \
    "  AND renew_by <= strftime('%s', 'now') "

#define SQL_PRIOR_APPROVAL_STATUS \
    "SELECT approved "            \
    "FROM certs "                 \
    "WHERE CN = :CN "             \
    "  AND O = :O "               \
    "  AND OU = :OU "             \
    "  AND C = :C "               \
    "ORDER BY status_date DESC "  \
    "LIMIT 1 "

namespace pvxs {
namespace certs {

/**
 * @brief Monitors the certificate status and updates the shared wildcard status pv when any become valid or expire.
 *
 * This function monitors the certificate status by connecting to the Certificate database, and searching
 * for all certificates that have just expired and all certificates that have just become valid.  If any
 * are found then the associated shared wildcard PV is updated and the new status stored in the database.
 *
 * @param certs_db The certificates database object.
 * @param issuer_id The issuer ID.
 * @param status_pv The shared wildcard PV to notify.
 *
 * @note This function assumes that the certificate database and the status PV have been properly configured and initialized.
 * @note The status_pv parameter must be a valid WildcardPV object.
 */
class StatusMonitor {
   public:
    ConfigCms &config_;
    sql_ptr &certs_db_;
    std::string &issuer_id_;
    server::WildcardPV &status_pv_;
    ossl_ptr<X509> &cert_auth_cert_;
    ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    pvxs::ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain_;
    std::map<serial_number_t, time_t> &active_status_validity_;

    StatusMonitor(ConfigCms &config, sql_ptr &certs_db, std::string &issuer_id, server::WildcardPV &status_pv, ossl_ptr<X509> &cert_auth_cert,
                  ossl_ptr<EVP_PKEY> &cert_auth_pkey, ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
                  std::map<serial_number_t, time_t> &active_status_validity)
        : config_(config),
          certs_db_(certs_db),
          issuer_id_(issuer_id),
          status_pv_(status_pv),
          cert_auth_cert_(cert_auth_cert),
          cert_auth_pkey_(cert_auth_pkey),
          cert_auth_cert_chain_(cert_auth_chain),
          active_status_validity_(active_status_validity) {}

    std::vector<serial_number_t> getActiveSerials() const {
        const auto cutoff{time(nullptr) - static_cast<uint64_t>(config_.request_timeout_specified)};
        std::vector<serial_number_t> result;
        for (const auto &pair : active_status_validity_) {
            if (pair.second > cutoff) {
                result.push_back(pair.first);
            }
        }
        return result;
    }

    /**
     * @brief Set the new validity timeout after we've updated the database
     * Note that its possible that the serial has been removed by another thread during the operation
     * TODO make threadsafe
     * @param serial the serial number of the validity we need to update
     * @param validity_date the new validity date
     */
    void setValidity(const serial_number_t serial, const time_t validity_date) const {
        const auto it = active_status_validity_.find(serial);
        if (it != active_status_validity_.end()) {
            it->second = validity_date;
        }
    }
};

void checkForDuplicates(const sql_ptr &certs_db, const CertFactory &cert_factory);

CertData createCertAuthCertificate(const ConfigCms &config, sql_ptr &certs_db, const std::shared_ptr<KeyPair> &key_pair);

ossl_ptr<X509> createCertificate(sql_ptr &certs_db, CertFactory &cert_factory);

std::string createCertificatePemString(sql_ptr &certs_db, CertFactory &cert_factory);

void createServerCertificate(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, const std::shared_ptr<KeyPair> &key_pair);

void ensureServerCertificateExists(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain);

void ensureValidityCompatible(const CertFactory &cert_factory);

uint64_t generateSerial();

std::tuple<certstatus_t, time_t> getCertificateStatus(const sql_ptr &certs_db, uint64_t serial);
void getWorstCertificateStatus(const sql_ptr &certs_db, uint64_t serial, certstatus_t &worst_status_so_far, time_t &worst_status_time_so_far);
DbCert getCertificateValidity(const sql_ptr &certs_db, uint64_t serial);

std::string extractCountryCode(const std::string &locale_str);

std::string getCountryCode();

Value getCreatePrototype();

time_t getNotAfterTimeFromCert(const X509 *cert);

time_t getNotBeforeTimeFromCert(const X509 *cert);

void getOrCreateCertAuthCertificate(const ConfigCms &config, sql_ptr &certs_db, ossl_ptr<X509> &cert_auth_cert, ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, ossl_ptr<X509> &cert_auth_root_cert, bool &is_initialising);

std::vector<std::string> getCertPaths(const CertData &cert_data);
std::string toACFAuth(const std::string &id, const CertData &cert_data);
std::string toACFYamlAuth(const std::string &id, const CertData &cert_data);

void createDefaultAdminACF(const ConfigCms &config, const CertData &cert_data);

void createAdminClientCert(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert,
                           const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain, const std::string &admin_name = "admin");

void initCertsDatabase(sql_ptr &certs_db, const std::string &db_file);

void onCreateCertificate(ConfigCms &config, sql_ptr &certs_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args,
                         const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                         const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, std::string issuer_id);

bool getPriorApprovalStatus(const sql_ptr &certs_db, const std::string &name, const std::string &country, const std::string &organization,
                            const std::string &organization_unit);

void onGetStatus(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
                 const std::string &pv_name, serial_number_t serial, const std::string &issuer_id, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                 const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

void onRevoke(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
              std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
              const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

void onApprove(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
               std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
               const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

void onDeny(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
            std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
            const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

int readOptions(ConfigCms &config, int argc, char *argv[], bool &verbose);

void updateCertificateStatus(const sql_ptr &certs_db, uint64_t serial, certstatus_t cert_status, int approval_status,
                             const std::vector<certstatus_t> &valid_status = {PENDING_APPROVAL, PENDING, VALID});

void updateCertificateRenewalStatus(const sql_ptr &certs_db, serial_number_t serial, certstatus_t cert_status, time_t renew_by);

certstatus_t storeCertificate(const sql_ptr &certs_db, CertFactory &cert_factory);

timeval statusMonitor(const StatusMonitor &status_monitor_params);

Value postCertificateStatus(server::WildcardPV &status_pv, const std::string &pv_name, uint64_t serial, const PVACertificateStatus &cert_status = {});

std::string getValidStatusesClause(const std::vector<certstatus_t> &valid_status);
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<certstatus_t> &valid_status);
uint64_t getParameters(const std::list<std::string> &parameters);

template <typename T>
void setValue(Value &target, const std::string &field, const T &new_value);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_PVACMS_H
