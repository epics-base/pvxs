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

#include <pvxs/sharedpv.h>

#include "certfactory.h"
#include "certmgmtservice.h"
#include "configcms.h"

#define DEFAULT_KEYCHAIN_FILE "server.p12"
#define DEFAULT_CA_KEYCHAIN_FILE "ca.p12"
#define DEFAULT_ACF_FILE "pvacms.acf"

#define GET_MONITOR_CERT_STATUS_ROOT "CERT:STATUS"
#define RPC_CERT_REVOKE_ROOT "CERT:REVOKE"

// Partition Management
#define GET_MONITOR_PARTITION_PV "CERT:PARTITION:*"
#define RPC_PARTITION_SCALEUP_PV "CERT:PARTITION:SCALE_UP"
#define RPC_PARTITION_SCALEDUP_PV "CERT:PARTITION:SCALED_UP:*"
#define RPC_PARTITION_SCALEDOWN_PV "CERT:PARTITION:SCALE_DOWN:*"
#define RPC_PARTITION_SCALEDDOWN_PV "CERT:PARTITION:SCALED_DOWN:*"

#define PVXS_HOSTNAME_MAX 1024
#define PVXS_ORG_UNIT_MAME "Certificate Authority"
#define PVXS_SERVICE_NAME "PVACMS Service"
#define PVXS_SERVICE_ORG_UNIT_NAME "EPICS PVA Certificate Management Service"

enum CertificateStatus { PENDING_VALIDATION, VALID, EXPIRED, REVOKED };

#define SQL_CREATE_DB_FILE              \
    "BEGIN TRANSACTION;"                \
    "CREATE TABLE IF NOT EXISTS certs(" \
    "     serial INTEGER,"              \
    "     skid TEXT,"                   \
    "     CN TEXT,"                     \
    "     O TEXT,"                      \
    "     OU TEXT,"                     \
    "     C TEXT,"                      \
    "     not_before INTEGER,"          \
    "     not_after INTEGER,"           \
    "     status INTEGER,"              \
    "     status_date INTEGER"          \
    ");"                                \
    "COMMIT;"

#define SQL_CREATE_CERT    \
    "INSERT INTO certs ( " \
    "     serial,"         \
    "     skid,"           \
    "     CN,"             \
    "     O,"              \
    "     OU,"             \
    "     C,"              \
    "     not_before,"     \
    "     not_after,"      \
    "     status,"         \
    "     status_date"     \
    ") "                   \
    "VALUES ("             \
    "     :serial,"        \
    "     :skid,"          \
    "     :CN,"            \
    "     :O,"             \
    "     :OU,"            \
    "     :C,"             \
    "     :not_before,"    \
    "     :not_after,"     \
    "     :status,"        \
    "     :status_date"    \
    ")"

#define SQL_DUPS_SUBJECT \
    "SELECT COUNT(*) "   \
    "FROM certs "        \
    "WHERE CN = :CN "    \
    "  AND O = :O "      \
    "  AND OU = :OU "    \
    "  AND C = :C "      \
    "  AND status = :status"

#define SQL_DUPS_SUBJECT_KEY_IDENTIFIER \
    "SELECT COUNT(*) "                  \
    "FROM certs "                       \
    "WHERE skid = :skid "               \
    "  AND status = :status"

#define SQL_CERT_STATUS \
    "SELECT status "    \
    "FROM certs "       \
    "WHERE serial = :serial"

#define SQL_CERT_SET_STATUS          \
    "UPDATE certs "                  \
    "SET status = :status "          \
    "WHERE serial = :serial "        \
    "  AND status = :valid_status "

namespace pvxs {
namespace certs {
time_t tmToTimeTUTC(std::tm &tm);

time_t ASN1_TIMEToTimeT(ASN1_TIME *time);

void createServerCertificate(const ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

void createCaCertificate(ConfigCms &config, sql_ptr &ca_db);

std::string createCertificatePemString(sql_ptr &ca_db, CertFactory &cert_factory);

ossl_ptr<X509> createCertificate(sql_ptr &ca_db, CertFactory &cert_factory);

void ensureServerCertificateExists(ConfigCms config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

void ensureValidityCompatible(CertFactory &cert_factory);

uint64_t generateSerial();

CertificateStatus getCertificateStatus(sql_ptr &ca_db, uint64_t serial);
void setCertificateStatus(sql_ptr &ca_db, uint64_t serial, CertificateStatus cert_status);

std::string getCountryCode();

void getOrCreateCaCertificate(ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

Value getCreatePrototype();

std::string getIPAddress();

time_t getNotAfterTimeFromCert(const X509 *cert);

time_t getNotBeforeTimeFromCert(const X509 *cert);

Value getPartitionPrototype();

Value getRevokePrototype();

Value getScaleDownPrototype();

Value getScaleUpPrototype();

Value getStatusPrototype();

void initCertsDatabase(sql_ptr &ca_db, std::string &db_file);

int readOptions(ConfigCms &config, int argc, char *argv[], bool &verbose);

void onCreateCertificate(sql_ptr &ca_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args, const ossl_ptr<EVP_PKEY> &ca_pkey,
                         const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain,
                         std::string issuer_id);

void onGetStatus(sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedPV &status_pv, std::shared_ptr<std::list<std::string>> &&parameters);

void onRevoke(sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedPV &status_pv, std::shared_ptr<std::list<std::string>>&&parameters, std::unique_ptr<server::ExecOp> &&op, Value &&args);

std::string getIssuerId(const ossl_ptr<X509> &ca_cert);

std::string getIssuerId(X509 *ca_cert);

void storeCertificate(sql_ptr &ca_db, CertFactory &cert_factory);

void checkForDuplicates(sql_ptr &ca_db, CertFactory &cert_factory);

void usage(const char *argv0);
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_PVACMS_H
