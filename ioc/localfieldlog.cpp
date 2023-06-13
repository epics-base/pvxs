/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include "localfieldlog.h"

namespace pvxs {
namespace ioc {

LocalFieldLog::LocalFieldLog(dbChannel* pDbChannel, db_field_log* existingFieldLog)
        :pFieldLog(existingFieldLog) {
    if (pDbChannel && !pFieldLog && (ellCount(&pDbChannel->pre_chain) != 0 || ellCount(&pDbChannel->post_chain) != 0)) {
        pFieldLog = db_create_read_log(pDbChannel);
        if (pFieldLog) {
            pFieldLog = dbChannelRunPreChain(pDbChannel, pFieldLog);
            if (pFieldLog) {
                pFieldLog = dbChannelRunPostChain(pDbChannel, pFieldLog);
                owned = true;
            }
        }
    }
}

} // pvxs
} // ioc
