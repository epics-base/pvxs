/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "serverconn.h"

namespace pvxsimpl {

ServerChan::ServerChan(ServerConn* conn,
                       uint32_t sid,
                       uint32_t cid,
                       const std::string &name,
                       std::unique_ptr<server::Handler> &&handler)
    :conn(conn)
    ,sid(sid)
    ,cid(cid)
    ,name(name)
    ,handler(std::move(handler))
{}

ServerChan::~ServerChan() {}

} // namespace pvxsimpl
