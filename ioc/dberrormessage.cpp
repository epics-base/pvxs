/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <errlog.h>
#include <errMdef.h>
#include <errSymTbl.h>

#include "dberrormessage.h"

namespace pvxs {
namespace ioc {

/**
 * Set value of this DBErrorMessage object from the specified database status code
 *
 * @param dbStatus database command status code
 * @return updated  DBErrorMessage object
 */
DBErrorMessage& DBErrorMessage::operator=(const long& dbStatus) {
    status = dbStatus;
    if (!dbStatus) {
        message[0] = '\0';
    } else {
        errSymLookup(dbStatus, message, sizeof(message));
        message[sizeof(message) - 1] = '\0';
    }
    return *this;
}

} // ioc
} // pvxs
