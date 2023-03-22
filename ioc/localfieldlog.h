/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_LOCALFIELDLOG_H
#define PVXS_LOCALFIELDLOG_H

#include <db_field_log.h>
#include <dbChannel.h>
namespace pvxs {
namespace ioc {

class LocalFieldLog {
public:
    db_field_log* pFieldLog;
    bool owned = false;
    explicit LocalFieldLog(dbChannel* pDbChannel, db_field_log* existingFieldLog = nullptr);
    ~LocalFieldLog() {
        if (owned) {
            db_delete_field_log(pFieldLog);
        }
    }

};

} // pvxs
} // ioc

#endif //PVXS_LOCALFIELDLOG_H
