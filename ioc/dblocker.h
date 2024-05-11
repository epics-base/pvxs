/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_DBLOCKER_H
#define PVXS_DBLOCKER_H

#include <dbLock.h>

namespace pvxs {
namespace ioc {

/**
 * To lock access to a single DB record.
 * Use by creating a new object.  It will lock the record referenced by the constructor parameter while the object is
 * in scope.
 *
 * e.g.
 * 		{
 *			DBLocker F(pDbChannel->addr.precord); // Lock
 *			IOCSource::put(pDbChannel, ...);
 *			...
 * 		}  // Unlocked
 */
class DBLocker {
public:
    dbCommon* const lock;
    explicit DBLocker(dbCommon* L)
            :lock(L) {
        dbScanLock(lock);
    }
    DBLocker(const DBLocker&) = delete;
    DBLocker(DBLocker&&) = delete;

    ~DBLocker() {
        dbScanUnlock(lock);
    }
};

} // pvxs
} // ioc

#endif //PVXS_DBLOCKER_H
