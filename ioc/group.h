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

#include <fstream>
#include <map>
#include <memory>
#include <list>
#include <stdexcept>

#include <pvxs/data.h>

#include <macLib.h>

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
    const std::string name;
    const bool atomicPutGet;
    std::vector<Field> fields;
    Value valueTemplate;
    ChannelLocks value;
    ChannelLocks properties;

    void show(int level) const;
    Field& operator[](const std::string& fieldName);

    Group(const std::string& name, bool atomicPutGet)
        :name(name)
        ,atomicPutGet(atomicPutGet)
    {}
    Group(const Group&) = delete;
};

struct IOCGroupConfig {
    static
    IOCGroupConfig& instance();

    std::map<std::string, Group> groupMap;
    struct JFile {
        struct DeleteMac {
            void operator()(MAC_HANDLE *handle) { (void)macDeleteHandle(handle); }
        };

        std::unique_ptr<std::ifstream> jf;
        std::string fname;
        std::string macros;
        std::unique_ptr<MAC_HANDLE, DeleteMac> handle;
        JFile(decltype(jf)&& jf, const std::string& fname, const std::string& macros,
              decltype(handle)&& handle)
            :jf(std::move(jf)), fname(fname), macros(macros), handle(std::move(handle))
        {}
    };
    std::list<JFile> groupConfigFiles;

    // For locking access to groupMap
    epicsMutex groupMapMutex{};
};

} // pvxs
} // ioc

#endif //PVXS_GROUP_H
