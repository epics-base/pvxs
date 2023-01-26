/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cassert>

#include <pvxs/log.h>
#include "dataimpl.h"
#include "serverconn.h"

namespace pvxs { namespace impl {
DEFINE_LOGGER(connsetup, "pvxs.tcp.setup");

namespace {
struct ServerIntrospect : public ServerOp
{
    ServerIntrospect(const std::shared_ptr<ServerChan>& chan, uint32_t ioid)
        :ServerOp(chan, ioid)
    {}
    virtual ~ServerIntrospect() {}

    void doReply(const FieldDesc* type, const Status& sts)
    {
        if(state != ServerOp::Executing)
            return;
        auto ch = chan.lock();
        if(!ch)
            return;
        auto conn = ch->conn.lock();
        if(!conn || conn->state==ConnBase::Disconnected)
            return;

        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(conn->sendBE, conn->txBody.get());
            to_wire(R, uint32_t(ioid));
            to_wire(R, sts);
            if(type)
                to_wire(R, type);
        }

        ch->statTx += conn->enqueueTxBody(CMD_GET_FIELD);

        state = ServerOp::Dead;
        conn->opByIOID.erase(ioid);
        ch->opByIOID.erase(ioid);
    }

    void show(std::ostream& strm) const override final
    {
        strm<<"INFO\n";
    }

    INST_COUNTER(ServerIntrospect);
};

struct ServerIntrospectControl : public server::ConnectOp
{
    ServerIntrospectControl(ServerConn *conn, ServerChan *chan,
                            const std::weak_ptr<server::Server::Pvt>& server,
                            const std::weak_ptr<ServerIntrospect>& op)
        :server::ConnectOp(chan->name, conn->cred, Info, Value()) // TODO: pvRequest?
        ,server(server)
        ,op(op)
    {}
    virtual ~ServerIntrospectControl() {
        error("Implicit Cancel");
    }

    virtual void connect(const Value& prototype) override final
    {
        auto desc = Value::Helper::desc(prototype);
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
            return; // soft fail if already completed, canceled, disconnected, ....

        serv->acceptor_loop.call([this, type, &sts](){
            if(auto oper = op.lock())
                oper->doReply(type, sts);
        });
    }

    virtual void onClose(std::function<void(const std::string&)>&& fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onClose = std::move(fn);
        });
    }

    // we'll never use these, so no reason to store
    virtual void onGet(std::function<void(std::unique_ptr<server::ExecOp>&& fn)>&& fn) override final {}
    virtual void onPut(std::function<void(std::unique_ptr<server::ExecOp>&& fn, Value&&)>&& fn) override final {}

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerIntrospect> op;

    INST_COUNTER(ServerIntrospectControl);
};
} // namespace

void ServerConn::handle_GET_FIELD()
{
    // aka. GetField

    auto rxlen = 8u + evbuffer_get_length(segBuf.get());
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid = -1, ioid = -1;
    std::string subfield;

    from_wire(M, sid);
    from_wire(M, ioid);
    from_wire(M, subfield);
    if(!M.good())
        throw std::runtime_error(SB()<<M.file()<<':'<<M.line()<<" Error decoding Introspect");

    auto& chan = lookupSID(sid);

    if(!chan || opByIOID.find(ioid)!=opByIOID.end()) {
        log_err_printf(connsetup, "Client %s reuses existing sid %u ioid %d\n",
                       peerName.c_str(), unsigned(sid), unsigned(ioid));
        return;
    }
    chan->statRx += rxlen;

    auto op(std::make_shared<ServerIntrospect>(chan, ioid));
    std::unique_ptr<ServerIntrospectControl> ctrl(new ServerIntrospectControl(this, chan.get(), iface->server->internal_self, op));

    op->state = ServerOp::Executing; // this is a one-shot operation

    opByIOID[ioid] = op;
    chan->opByIOID[ioid] = op;

    if(chan->onOp) {
        try {
            chan->onOp(std::move(ctrl));
        }catch(std::exception& e){
            // a remote error will be signaled from ~ServerIntrospectControl
            log_err_printf(connsetup, "Client %s Info \"%s\" onOp() error: %s\n",
                           peerName.c_str(), chan->name.c_str(), e.what());
        }
    }
}

}} // namespace pvxs::impl
