/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cassert>

#include <pvxs/log.h>
#include "dataimpl.h"
#include "dataencode.h"
#include "serverconn.h"

namespace pvxs { namespace impl {
DEFINE_LOGGER(connsetup, "tcp.setup");

namespace {
struct ServerIntrospect : public ServerOp
{
    ServerIntrospect(const std::shared_ptr<ServerChan>& chan, uint32_t ioid)
        :ServerOp(chan, ioid)
    {}
    virtual ~ServerIntrospect() {}
};

struct ServerIntrospectControl : public server::Introspect
{
    ServerIntrospectControl(ServerConn* conn,
                            const std::weak_ptr<server::Server::Pvt>& server,
                            const std::string& name,
                            const std::weak_ptr<ServerIntrospect>& op)
        :server::Introspect(conn->peerName, conn->iface->name, name)
        ,server(server)
        ,op(op)
    {}
    virtual ~ServerIntrospectControl() {
        error("Implict Cancel");
    }

    virtual void reply(const Value& prototype) override final
    {
        auto desc = prototype._desc();
        if(!desc)
            throw std::logic_error("Can't reply to GET_FIELD with Null prototype");
        Status sts{Status::Ok};
        doReply(desc, sts);
    }

    virtual void error(const std::string &msg) override final
    {
        Status sts{Status::Error, msg};
        doReply(nullptr, sts);
    }

    void doReply(const FieldDesc* type, const Status& sts)
    {
        auto serv = server.lock();
        if(!serv)
            return; // soft fail if already completed, cancelled, disconnected, ....

        serv->acceptor_loop.call([this, type, &sts](){
            auto oper = op.lock();
            if(!oper || oper->state != ServerOp::Executing)
                return;
            auto chan = oper->chan.lock();
            if(!chan)
                return;
            auto conn = chan->conn.lock();
            if(!conn || !conn->bev)
                return;

            const bool be = EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG;
            {
                (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

                EvOutBuf R(be, conn->txBody.get());
                to_wire(R, uint32_t(oper->ioid));
                to_wire(R, sts);
                if(type)
                    to_wire(R, type);
                // would be FieldDesc payload if Ok or Warn
            }

            auto tx = bufferevent_get_output(conn->bev.get());
            to_evbuf(tx, Header{CMD_GET_FIELD,
                                pva_flags::Server,
                                uint32_t(evbuffer_get_length(conn->txBody.get()))},
                     be);
            auto err = evbuffer_add_buffer(tx, conn->txBody.get());
            assert(!err);

            oper->state = ServerOp::Dead;
            conn->opByIOID.erase(oper->ioid);
            chan->opByIOID.erase(oper->ioid);
        });
    }

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerIntrospect> op;
};
} // namespace

void ServerConn::handle_GET_FIELD()
{
    // aka. GetField

    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid = -1, ioid = -1;
    std::string subfield;

    from_wire(M, sid);
    from_wire(M, ioid);
    from_wire(M, subfield);
    if(!M.good())
        throw std::runtime_error("Error decoding Introspect");

    auto& chan = lookupSID(sid);

    if(opByIOID.find(ioid)!=opByIOID.end()) {
        log_printf(connsetup, PLVL_ERR, "Client %s reuses existing ioid %d\n", peerName.c_str(), unsigned(ioid));
        return;
    }

    std::shared_ptr<ServerIntrospect> op(new ServerIntrospect(chan, ioid));
    std::unique_ptr<ServerIntrospectControl> ctrl(new ServerIntrospectControl(this, iface->server->internal_self, chan->name, op));

    op->state = ServerOp::Executing; // this is a one-shot operation

    opByIOID[ioid] = op;
    chan->opByIOID[ioid] = op;

    if(chan->handler)
        chan->handler->onIntrospect(std::move(ctrl));
}

}} // namespace pvxs::impl
