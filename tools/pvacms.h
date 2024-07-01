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

#define DEFAULT_KEYCHAIN_FILE "server.p12"
#define DEFAULT_CA_KEYCHAIN_FILE "ca.p12"
#define DEFAULT_ACF_FILE "pvacms.acf"

// Certificate management
#define RPC_SERVER_CREATE "CERT:CREATE"
#define RPC_SERVER_REVOKE "CERT:REVOKE:*"
#define GET_SERVER_STATUS "CERT:STATUS:*"

// Partition Management
#define GET_SERVER_PARTITION "CERT:PARTITION:*"
#define RPC_SERVER_PARTITION_SCALEUP "CERT:PARTITION:SCALE_UP"
#define RPC_SERVER_PARTITION_SCALEDUP "CERT:PARTITION:SCALED_UP:*"
#define RPC_SERVER_PARTITION_SCALEDOWN "CERT:PARTITION:SCALE_DOWN:*"
#define RPC_SERVER_PARTITION_SCALEDDOWN "CERT:PARTITION:SCALED_DOWN:*"

#define PVXS_HOSTNAME_MAX 1024
#define PVXS_ORG_UNIT_MAME "Certificate Authority"
#define PVXS_SERVICE_NAME "PVACMS Service"
#define PVXS_SERVICE_ORG_UNIT_NAME "EPICS PVA Certificate Management Service"

enum CertificateStatus { PENDING_VALIDATION, VALID, EXPIRED, REVOKED };

#define SQL_CREATE_DB_FILE              \
    "BEGIN TRANSACTION;"                \
    "CREATE TABLE IF NOT EXISTS certs(" \
    "     serial INTEGER,"              \
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

#define SQL_CREATE_CERT  \
    "INSERT INTO certs " \
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"

#define SQL_CERT_STATUS \
    "SELECT status "    \
    "FROM certs "       \
    "WHERE serial = ?"

#endif  // PVXS_PVACMS_H
