/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_IOCSERVER_H
#define PVXS_IOCSERVER_H

#include <string>

#include <pvxs/server.h>

#include "group.h"

namespace pvxs {
namespace ioc {

class IOCServer : public server::Server {

public:
    explicit IOCServer(const server::Config& config)
            :pvxs::server::Server(config) {
    }

    GroupMap groupMap;
    std::list<std::string> groupConfigFiles;

    // For locking access to groupMap
    epicsMutex groupMapMutex{};
};

IOCServer& iocServer();

} // pvxs
} // ioc

#endif //PVXS_IOCSERVER_H
