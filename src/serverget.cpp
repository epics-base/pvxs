/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cassert>

#include <pvxs/log.h>
#include "dataimpl.h"
#include "serverconn.h"
#include "pvrequest.h"

namespace pvxs { namespace impl {
DEFINE_LOGGER(connsetup, "pvxs.tcp.setup");
DEFINE_LOGGER(connio, "pvxs.tcp.io");

namespace {
server::OpBase::op_t
cmd2op(pva_app_msg_t cmd){
    switch(cmd) {
    case CMD_GET: return server::OpBase::Get; break;
    case CMD_PUT: return server::OpBase::Put; break;
    case CMD_RPC: return server::OpBase::RPC; break;
    default: return server::OpBase::None; break; // should never be reached
    }
}

// generalized Get/Put/RPC
struct ServerGPR : public ServerOp
{
    ServerGPR(const std::shared_ptr<ServerChan>& chan, uint32_t ioid)
        :ServerOp(chan, ioid)
    {}
    virtual ~ServerGPR() {}

    void doReply(const Value& value,
                 const std::string& msg)
    {
        auto ch = chan.lock();
        if(!ch)
            return;
        auto conn = ch->conn.lock();
        if(!conn || conn->state==ConnBase::Disconnected)
            return;

        if(state==Dead || state==Idle) {
            // no warn if Idle as this may result from a remote Cancel
            return;

        } else if(state==Executing) {
            /* valid combinations
             * GET and !!value
             * RPC
             * PUT w/  subcmd&0x40 and !!value
             * PUT w/o subcmd&0x40 and !value
             */

            if(!msg.empty()) {
                // noop

            } else if(cmd==CMD_GET || (cmd==CMD_PUT && (subcmd&0x40))) {
                if(!value)
                    throw std::logic_error("GET must reply Value");
                else if(Value::Helper::desc(value)!=this->type.get())
                    throw std::logic_error("GET must reply with exact type previously passed to connect()");

            } else if(cmd==CMD_PUT) {
                if(value)
                    throw std::logic_error("PUT reply can't include Value");
            }
        }

        Status sts{};
        if(!msg.empty())
            sts = Status::error(msg);

        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(conn->sendBE, conn->txBody.get());
            to_wire(R, uint32_t(ioid));
            to_wire(R, subcmd);
            to_wire(R, sts);

            if(!sts.isSuccess()) {
                // error()

                if(state==Executing)
                    state = Idle;
                else // Creating
                    state = Dead;

            } else if(state==Creating) {
                // connect()
                if(cmd!=CMD_RPC) {
                    to_wire(R, type.get());
                }
                state = Idle;

            } else if(state==Executing) {
                if(cmd==CMD_GET || (cmd==CMD_PUT && (subcmd&0x40))) {
                    to_wire_valid(R, value, &pvMask); // GET and PUT/Get reply with bitmask and partial value

                } else if(cmd==CMD_RPC) {
                    auto type = Value::Helper::desc(value);
                    to_wire(R, type);
                    if(value)
                        to_wire_full(R, value);
                }
                state = lastRequest ? Dead : Idle;

            } else {
                assert(false);
            }
            assert(R.good());
        }

        ch->statTx += conn->enqueueTxBody(cmd);

        if(state == ServerOp::Dead) {
            ch->opByIOID.erase(ioid);
            auto it = conn->opByIOID.find(ioid);
            if(it!=conn->opByIOID.end()) {
                auto self(it->second);
                conn->opByIOID.erase(it);

                if(self->onClose)
                    conn->iface->server->acceptor_loop.dispatch([self](){
                        self->onClose("");
                    });

            } else {
                assert(false); // really shouldn't happen
            }
            conn->opByIOID.erase(ioid);
        }
    }

    void show(std::ostream& strm) const override final
    {
        switch(cmd) {
#define CASE(CMD) case CMD_ ## CMD : strm<< #CMD "\n"; break
        CASE(GET);
        CASE(PUT);
        CASE(RPC);
#undef CASE
        default: {
            Restore R(strm);
            strm<<"CMD"<<std::hex<<cmd<<"\n";
        }
        }
    }

    pva_app_msg_t cmd;
    uint8_t subcmd; // valid when state==Executing or Creating
    bool lastRequest=false;

    std::shared_ptr<const FieldDesc> type;
    Value pvRequest;
    BitMask pvMask; // mask computed from pvRequest .fields

    std::function<void(std::unique_ptr<server::ExecOp>&&, Value&&)> onPut;

    std::function<void(std::unique_ptr<server::ExecOp>&&)> onGet;

    INST_COUNTER(ServerGPR);
};


struct ServerGPRConnect : public server::ConnectOp
{
    ServerGPRConnect(ServerConn* conn,
                     pva_app_msg_t cmd,
                     const std::weak_ptr<server::Server::Pvt>& server,
                     const std::string& name,
                     const Value& request,
                     const std::weak_ptr<ServerGPR>& op)
        :server::ConnectOp(name, conn->cred, cmd2op(cmd), request)
        ,server(server)
        ,op(op)
    {}
    virtual ~ServerGPRConnect() {
        error("Op Create implied error");
    }

    virtual void connect(const Value& prototype) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &prototype](){
            if(auto oper = op.lock()) {
                if(oper->state!=ServerOp::Creating)
                    return;

                if(!prototype && oper->cmd!=CMD_RPC)
                    throw std::invalid_argument("Must provide prototype");

                if(oper->type)
                    throw std::logic_error("Operation already connected (has a type)");

                if(prototype) {
                    oper->type = Value::Helper::type(prototype);
                    oper->pvMask = request2mask(oper->type.get(), _pvRequest);
                }

                oper->doReply(Value(), std::string());
            }
        });
    }
    virtual void error(const std::string& msg) override final
    {
        if(msg.empty())
            throw std::invalid_argument("Must provide error message");
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &msg](){
            if(auto oper = op.lock()) {
                if(oper->state==ServerOp::Creating)
                    oper->doReply(Value(), msg);
            }
        });
    }

    virtual void onGet(std::function<void(std::unique_ptr<server::ExecOp>&&)>&& fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onGet = std::move(fn);
        });
    }
    virtual void onPut(std::function<void(std::unique_ptr<server::ExecOp>&&, Value&&)>&& fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onPut = std::move(fn);
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

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerGPR> op;

    INST_COUNTER(ServerGPRConnect);
};

struct ServerGPRExec : public server::ExecOp
{
    ServerGPRExec(ServerConn* conn,
                  pva_app_msg_t cmd,
                  const std::weak_ptr<server::Server::Pvt>& server,
                  const std::string& name,
                  //const Value& request,
                  const std::shared_ptr<ServerGPR>& op)
        :server::ExecOp(name, conn->cred, cmd2op(cmd), op->pvRequest)
        ,server(server)
        ,op(op)
    {}
    virtual ~ServerGPRExec() {}

    virtual void reply() override final
    {
        reply(Value());
    }

    virtual void reply(const Value& val) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &val](){
            if(auto oper = op.lock()) {
                oper->doReply(val, std::string());
            }
        });
    }

    virtual void error(const std::string& msg) override final
    {
        if(msg.empty())
            throw std::invalid_argument("Must provide error message");
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &msg](){
            if(auto oper = op.lock()) {
                oper->doReply(Value(), msg);
            }
        });
    }

    virtual void onCancel(std::function<void()>&& fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onCancel = std::move(fn);
        });
    }

    virtual Timer _timerOneShot(double delay, std::function<void()>&& fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            throw std::logic_error("Can't start timer on deal server");

        return Timer::Pvt::buildOneShot(delay, serv->acceptor_loop.internal(), std::move(fn));
    }

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerGPR> op;

    INST_COUNTER(ServerGPRExec);
};

} // namespace

void ServerConn::handle_GPR(pva_app_msg_t cmd)
{
    auto rxlen = 8u + evbuffer_get_length(segBuf.get());
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid = -1, ioid = -1;
    uint8_t subcmd = 0;

    from_wire(M, sid);
    from_wire(M, ioid);
    from_wire(M, subcmd);

    // subcmd bitmask
    // 0x08 - Init
    // 0x10 - Destroy
    // 0x40 - Get
    // 0x00 - context dependent.  for CMD_GET the same as 0x40, for CMD_PUT and CMD_RPC the opposite of Get
    bool isput = cmd!=CMD_GET && !(subcmd&0x40);

    if(subcmd&0x08) { // INIT
        // type and full value
        Value pvRequest;
        from_wire_type_value(M, rxRegistry, pvRequest);

        if(!M.good()) {
            log_debug_printf(connio, "%s:%d Client %s\n Invalid op=%x/%x INIT\n",
                       M.file(), M.line(), peerName.c_str(), cmd, subcmd);
            bev.reset();
            return;
        }

        auto& chan = lookupSID(sid);

        if(!chan || opByIOID.find(ioid)!=opByIOID.end()) {
            log_err_printf(connsetup, "Client %s reuses existing sid %u ioid %u\n",
                           peerName.c_str(), unsigned(sid), unsigned(ioid));
            bev.reset();
            return;
        }
        chan->statRx += rxlen;

        auto op(std::make_shared<ServerGPR>(chan, ioid));
        op->cmd = cmd;
        op->pvRequest = pvRequest;
        std::unique_ptr<ServerGPRConnect> ctrl(new ServerGPRConnect(this, cmd, iface->server->internal_self, chan->name, pvRequest, op));

        op->subcmd = subcmd;
        op->state = ServerOp::Creating;

        opByIOID[ioid] = op;
        chan->opByIOID[ioid] = op;

        log_debug_printf(connsetup, "Client %s Get INIT ioid=%u pvRequest=%s\n",
                   peerName.c_str(), unsigned(ioid),
                   std::string(SB()<<pvRequest).c_str());

        if(cmd==CMD_RPC) {
            ctrl->connect(Value());

        } else if(chan->onOp) { // GET, PUT
            try {
                chan->onOp(std::move(ctrl));
            }catch(std::exception& e){
                // a remote error will be signaled from ~ServerGPRConnect
                log_err_printf(connsetup, "Client %s op%2x \"%s\" onOp() error: %s\n",
                               peerName.c_str(), cmd, chan->name.c_str(), e.what());
            }

        } else {
            ctrl->error("Get/Put/RPC not implemented for this PV");
        }

    } else { // EXEC, maybe Get or Put

        std::shared_ptr<ServerGPR> op;
        auto it = opByIOID.find(ioid);
        if(it==opByIOID.end() || it->second->state==ServerOp::Dead) {
            rxRegistryDirty = true;
            log_debug_printf(connio, "Client %s Gets non-existent IOID %u\n",
                       peerName.c_str(), unsigned(ioid));
            return;

        } else if(!(op=std::dynamic_pointer_cast<ServerGPR>(it->second)) || op->state==ServerOp::Creating) {
            log_err_printf(connio, "Client %s Gets invalid IOID %u state=%d\n", peerName.c_str(),
                       unsigned(ioid),
                       op ? op->state : ServerOp::Dead);
            bev.reset();
            return;
        }

        if(cmd!=CMD_RPC && !op->type) {
            log_err_printf(connsetup, "Client %s tries to Exec to early\n", peerName.c_str());
            bev.reset();
            return;
        }

        Value val;
        if(cmd==CMD_RPC) {
            // type and full value
            from_wire_type_value(M, rxRegistry, val);

        } else if(isput) {
            // bitmask and partial value
            val = Value::Helper::build(op->type);
            from_wire_valid(M, rxRegistry, val);
        }

        if(!M.good()) {
            log_debug_printf(connio, "%s:%d Client %s\n Invalid op=%x/%x Get\n",
                       M.file(), M.line(), peerName.c_str(), cmd, subcmd);
            bev.reset();
            return;
        }

        auto chan = op->chan.lock();
        if(!chan)
            throw std::logic_error("live op on dead channel");

        chan->statRx += rxlen;

        if(op->state==ServerOp::Idle) {
            // all set

            if(!op->lastRequest)
                op->lastRequest = subcmd&0x10;

            std::unique_ptr<ServerGPRExec> ctrl{new ServerGPRExec(this, cmd, iface->server->internal_self, chan->name, op)};

            op->subcmd = subcmd;
            op->state = ServerOp::Executing;

            log_debug_printf(connsetup, "Client %s op%x executing\n", peerName.c_str(), cmd);

            try {
                if(cmd==CMD_RPC && isput) {
                    if(chan->onRPC)
                        chan->onRPC(std::move(ctrl), std::move(val));
                    else
                        ctrl->error("RPC Not Implemented");

                } else if(cmd==CMD_PUT && isput) {
                    if(op->onPut)
                        op->onPut(std::move(ctrl), std::move(val));
                    else
                        ctrl->error("PUT Not Implemented");

                } else if(cmd!=CMD_RPC && !isput) {
                    if(op->onGet)
                        op->onGet(std::move(ctrl));
                    else
                        ctrl->error("GET Not Implemented");

                } else {
                    log_err_printf(connsetup, "Client %s Get exec in incorrect command %d\n",
                               peerName.c_str(), subcmd);
                }
            } catch(std::exception& e) {
                log_err_printf(connsetup, "Client %s Unhandled exception in onGet/Put/RPC %s : %s\n",
                           peerName.c_str(), typeid(e).name(), e.what());
                if(ctrl)
                    ctrl->error(e.what());
            }

        } else {
            log_err_printf(connsetup, "CLient %s Get exec in incorrect state %d\n",
                       peerName.c_str(), op->state);
        }
    }

}

void ServerConn::handle_GET()
{
    handle_GPR(CMD_GET);
}

void ServerConn::handle_PUT()
{
    handle_GPR(CMD_PUT);
}

void ServerConn::handle_RPC()
{
    handle_GPR(CMD_RPC);
}

}} // namespace pvxs::impl
