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
DEFINE_LOGGER(connsetup, "tcp.setup");
DEFINE_LOGGER(connio, "tcp.io");

namespace {
struct ServerGet : public ServerOp
{
    ServerGet(const std::shared_ptr<ServerChan>& chan, uint32_t ioid)
        :ServerOp(chan, ioid)
    {}
    virtual ~ServerGet() {}

    bool lastRequest=false;
    std::function<void()> onExec;
};

struct ServerGetControl : public server::Get
{
    ServerGetControl(ServerConn* conn,
                     const std::weak_ptr<server::Server::Pvt>& server,
                     const std::string& name,
                     const Value& request,
                     const std::weak_ptr<ServerGet>& op)
        :server::Get(conn->peerName, conn->iface->name, name, request)
        ,server(server)
        ,op(op)
    {}
    virtual ~ServerGetControl() {
        error("Implict Cancel");
    }

    virtual void connect(const Value& prototype,
                         std::function<void()>&& onExec) override final
    {
        if(!onExec || !prototype)
            throw std::logic_error("connect() requires prototype and onExec()");
        action(ServerOp::Creating, prototype, std::string(), std::move(onExec));
    }

    virtual void reply(const Value& value) override final
    {
        if(!value)
            throw std::logic_error("reply() requires Value");
        action(ServerOp::Executing, value, std::string(), nullptr);
    }

    virtual void error(const std::string& msg) override final
    {
        action(ServerOp::Dead, Value(), msg, nullptr);
    }

    void action(ServerOp::state_t action,
                const Value& value,
                const std::string& msg,
                std::function<void()>&& onExec)
    {

        auto serv = server.lock();
        if(!serv)
            return;

        serv->acceptor_loop.call([this, action, &value, &msg, &onExec](){
            auto oper = op.lock();
            if(!oper || oper->state == ServerOp::Dead)
                return;
            auto chan = oper->chan.lock();
            if(!chan)
                return;
            auto conn = chan->conn.lock();
            if(!conn || !conn->bev)
                return;

            const bool be = EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG;

            Status sts{};
            uint8_t cmd = oper->state==ServerOp::Creating ? 0x08 : oper->lastRequest ? 0x50 : 0x40;

            if(action==ServerOp::Dead) {
                // error()
                sts.code = Status::Error;
                sts.msg = msg;
                sts.trace = ""; // TODO

                if(oper->state == ServerOp::Executing)
                    oper->state = ServerOp::Idle;
                else
                    oper->state = ServerOp::Dead;
                log_printf(connsetup, PLVL_DEBUG, "CLient %s Get error\n", peerName.c_str());

            } else if(oper->state == ServerOp::Creating && action==ServerOp::Creating) {
                // connect()
                type = Value::Helper::type(value);
                oper->onExec = std::move(onExec);
                oper->state = ServerOp::Idle;
                log_printf(connsetup, PLVL_DEBUG, "CLient %s Get connected\n", peerName.c_str());

            } else if(oper->state == ServerOp::Executing && action==ServerOp::Executing) {
                // reply()
                if(type.get()!=Value::Helper::desc(value))
                    throw std::logic_error("Can't reply() w/ type change");
                log_printf(connsetup, PLVL_DEBUG, "CLient %s Get complete\n", peerName.c_str());

                oper->state = oper->lastRequest ? ServerOp::Dead : ServerOp::Idle;

            } else {
                log_printf(connsetup, PLVL_DEBUG, "Client %s Get operation not possible %d %d\n",
                           peerName.c_str(), action, oper->state);
                return;
            }

            {
                (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

                EvOutBuf R(be, conn->txBody.get());
                to_wire(R, uint32_t(oper->ioid));
                to_wire(R, cmd);
                to_wire(R, sts);
                if(sts.code!=Status::Ok) {
                    // error()

                } else if(action==ServerOp::Creating) {
                    // connect()
                    to_wire(R, type.get()); // type

                } else {
                    // reply()
                    to_wire_valid(R, value);

                }
            }

            auto tx = bufferevent_get_output(conn->bev.get());
            to_evbuf(tx, Header{CMD_GET,
                                pva_flags::Server,
                                uint32_t(evbuffer_get_length(conn->txBody.get()))},
                     be);
            auto err = evbuffer_add_buffer(tx, conn->txBody.get());
            assert(!err);

            if(oper->state == ServerOp::Dead) {
                conn->opByIOID.erase(oper->ioid);
                chan->opByIOID.erase(oper->ioid);
            }
        });

    }

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerGet> op;
    std::shared_ptr<const FieldDesc> type;
};
} // namespace

void ServerConn::handle_GET()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid = -1, ioid = -1;
    uint8_t subcmd = 0;

    from_wire(M, sid);
    from_wire(M, ioid);
    from_wire(M, subcmd);

    Status reply{};

    if(subcmd&0x08) { // INIT
        Value pvRequest;

        from_wire_type_value(M, rxRegistry, pvRequest);

        if(!M.good()) {
            log_printf(connio, PLVL_DEBUG, "Client %s\n Invalid Get INIT\n", peerName.c_str());
            bev.reset();
            return;
        }

        auto& chan = lookupSID(sid);

        if(opByIOID.find(ioid)!=opByIOID.end()) {
            log_printf(connsetup, PLVL_ERR, "Client %s reuses existing ioid %u\n", peerName.c_str(), unsigned(ioid));
            bev.reset();
            return;
        }

        std::shared_ptr<ServerGet> op(new ServerGet(chan, ioid));
        std::unique_ptr<ServerGetControl> ctrl(new ServerGetControl(this, iface->server->internal_self, chan->name, pvRequest, op));

        op->state = ServerOp::Creating;

        opByIOID[ioid] = op;
        chan->opByIOID[ioid] = op;

        log_printf(connsetup, PLVL_DEBUG, "Client %s Get INIT ioid=%u pvRequest=%s\n",
                   peerName.c_str(), unsigned(ioid),
                   std::string(SB()<<pvRequest).c_str());

        if(chan->handler)
            chan->handler->onGet(std::move(ctrl));

    } else { // EXEC  should be 0x40 however, some clients are lax
        // no additional message fields
        if(!M.good()) {
            log_printf(connio, PLVL_DEBUG, "Client %s\n Invalid Get EXEC\n", peerName.c_str());
            bev.reset();
            return;
        }

        std::shared_ptr<ServerGet> op;
        auto it = opByIOID.find(ioid);
        if(it==opByIOID.end() || !(op=std::dynamic_pointer_cast<ServerGet>(it->second))) {
            log_printf(connio, PLVL_ERR, "Client %s Gets %s IOID %u\n", peerName.c_str(),
                       it==opByIOID.end() ? "non-existant" : "invalid", unsigned(ioid));
            bev.reset();
            return;
        }

        op->lastRequest = subcmd&0x10;

        if(op->state==ServerOp::Idle) {
            // all set

            op->state = ServerOp::Executing;

            log_printf(connsetup, PLVL_DEBUG, "CLient %s Get executing\n", peerName.c_str());
            op->onExec(); // notify

        } else {
            log_printf(connsetup, PLVL_ERR, "CLient %s Get exec in incorrect state %d\n",
                       peerName.c_str(), op->state);
        }
    }

}

}} // namespace pvxs::impl
