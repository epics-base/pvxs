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
#include <pvxs/sharedwildcardpv.h>
#include <vector>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "certfactory.h"
#include "certmgmtservice.h"
#include "configcms.h"
#include "ownedptr.h"

#define DEFAULT_KEYCHAIN_FILE "server.p12"
#define DEFAULT_CA_KEYCHAIN_FILE "ca.p12"
#define DEFAULT_ACF_FILE "pvacms.acf"

#define GET_MONITOR_CERT_STATUS_ROOT "CERT:STATUS"
#define RPC_CERT_REVOKE_ROOT "CERT:REVOKE"

#define PVXS_HOSTNAME_MAX 1024
#define PVXS_ORG_UNIT_MAME "Certificate Authority"
#define PVXS_SERVICE_NAME "PVACMS Service"
#define PVXS_SERVICE_ORG_UNIT_NAME "EPICS PVA Certificate Management Service"

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

#define SQL_CERT_STATUS    \
    "SELECT status "       \
    "     , status_date "  \
    "FROM certs "          \
    "WHERE serial = :serial"

#define SQL_CERT_SET_STATUS          \
    "UPDATE certs "                  \
    "SET status = :status "          \
    "WHERE serial = :serial "        \
    "  AND ( "                       \
    "      status = :valid_status1 " \
    "   OR status = :valid_status2 " \
    "  )"

namespace pvxs {
namespace certs {

time_t ASN1_TIMEToTimeT(ASN1_TIME *time);

const char* certificateStatusToString(CertificateStatus status);

void checkForDuplicates(sql_ptr &ca_db, CertFactory &cert_factory);

void createCaCertificate(ConfigCms &config, sql_ptr &ca_db);

ossl_ptr<X509> createCertificate(sql_ptr &ca_db, CertFactory &cert_factory);

std::string createCertificatePemString(sql_ptr &ca_db, CertFactory &cert_factory);

void createServerCertificate(const ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

void ensureServerCertificateExists(ConfigCms config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

void ensureValidityCompatible(CertFactory &cert_factory);

uint64_t generateSerial();

std::tuple<CertificateStatus, time_t> getCertificateStatus(sql_ptr &ca_db, uint64_t serial);

std::string getCountryCode();

Value getCreatePrototype();

std::string getIPAddress();

std::string getIssuerId(const ossl_ptr<X509> &ca_cert);

std::string getIssuerId(X509 *ca_cert);

time_t getNotAfterTimeFromCert(const X509 *cert);

time_t getNotBeforeTimeFromCert(const X509 *cert);

void getOrCreateCaCertificate(ConfigCms &config, sql_ptr &ca_db, ossl_ptr<X509> &ca_cert, ossl_ptr<EVP_PKEY> &ca_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

Value getStatusPrototype();

void initCertsDatabase(sql_ptr &ca_db, std::string &db_file);

void onCreateCertificate(sql_ptr &ca_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args, const ossl_ptr<EVP_PKEY> &ca_pkey,
                         const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain,
                         std::string issuer_id);

void onGetStatus(sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, const std::string &pv_name, const std::list<std::string>& parameters, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

void onRevoke(sql_ptr &ca_db, const std::string &our_issuer_id, server::SharedWildcardPV &status_pv, std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string>& parameters, pvxs::Value &&args, const ossl_ptr<EVP_PKEY> &ca_pkey, const ossl_ptr<X509> &ca_cert, const ossl_ptr<EVP_PKEY> &ca_pub_key, const ossl_shared_ptr<STACK_OF(X509)> &ca_chain);

int readOptions(ConfigCms &config, int argc, char *argv[], bool &verbose);

void setCertificateStatus(sql_ptr &ca_db, uint64_t serial, CertificateStatus cert_status);

void storeCertificate(sql_ptr &ca_db, CertFactory &cert_factory);

time_t tmToTimeTUTC(std::tm &tm);

void usage(const char *argv0);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_PVACMS_H
