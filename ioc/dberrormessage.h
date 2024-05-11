/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_DBERRORMESSAGE_H
#define PVXS_DBERRORMESSAGE_H

#include <epicsTypes.h>
#include <errSymTbl.h>

#include "dberrormessage.h"

namespace pvxs {
namespace ioc {

/**
 * Wrapper class for status returned from base IOC database commands.
 */
class DBErrorMessage {
    long status = 0;
    char message[MAX_STRING_SIZE]{};
public:
/**
 * Construct a new DBErrorMessage from a native database command status code
 *
 * @param dbStatus database command status code
 */
    explicit DBErrorMessage(const long& dbStatus = 0) {
        (*this) = dbStatus;
    }

    DBErrorMessage& operator=(const long& dbStatus);
/**
 * bool cast operation returns true if the status indicates a failure
 *
 * @return returns true if the status indicates a failure
 */
    explicit operator bool() const {
        return status;
    }

/**
 * Return the text of the database status as a string pointer
 *
 * @return the text of the database status as a string pointer
 */
    const char* c_str() const {
        return message;
    }

};

} // ioc
} // pvxs
#endif //PVXS_DBERRORMESSAGE_H
