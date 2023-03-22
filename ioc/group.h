/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUP_H
#define PVXS_GROUP_H

#include <map>

#include <pvxs/data.h>

#include "dbmanylocker.h"
#include "field.h"

namespace pvxs {
namespace ioc {

class ChannelLocks {
public:
    std::vector<dbCommon*> channels;
    DBManyLock lock;
    ChannelLocks() = default;
};

class Group {
private:
public:
    std::string name;
    Fields fields;
    bool atomicPutGet, atomicMonitor;
    Value valueTemplate;
    ChannelLocks value;
    ChannelLocks properties;

/**
 * Constructor for IOC group.
 * Set the atomic and monitor atomic flags
 */
    Group()
            :atomicPutGet(false), atomicMonitor(false) {
    }

/**
 * Destructor for IOC group
 */
    virtual ~Group() = default;

    virtual void show(int level) const;
    Field& operator[](const std::string& fieldName);

    Group(const Group&) = delete;
};

// A map of group name to Group
typedef std::map<std::string, Group> GroupMap;

} // pvxs
} // ioc

#endif //PVXS_GROUP_H
