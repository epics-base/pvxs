/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cassert>

#include <deque>

#include <epicsMutex.h>
#include <epicsGuard.h>

#include <pvxs/log.h>
#include "dataimpl.h"
#include "serverconn.h"

namespace pvxs { namespace impl {
DEFINE_LOGGER(connsetup, "pvxs.tcp.setup");
DEFINE_LOGGER(connio, "pvxs.tcp.io");

namespace {

typedef epicsGuard<epicsMutex> Guard;

struct MonitorOp : public ServerOp,
                   public std::enable_shared_from_this<MonitorOp>
{
    MonitorOp(const std::shared_ptr<ServerChan>& chan, uint32_t ioid)
        :ServerOp(chan, ioid)
    {}
    virtual ~MonitorOp() {}

    // only access from acceptor worker thread
    std::function<void(bool)> onStart;
    std::function<void()> onLowMark;
    std::function<void()> onHighMark;
    std::function<void(const std::string&)> onClose;

    // const after setup phase
    std::shared_ptr<const FieldDesc> type;
    std::string msg;

    // Further members can only be changed from the accepter worker thread with this lock held.
    // They may be read from the worker, or if this lock is held.
    mutable epicsMutex lock;

    // is doReply() scheduled to run
    bool scheduled=false;
    bool pipeline=false;
    bool finished=false;
    size_t window=0u, limit=1u;
    size_t low=0u, high=0u;

    std::deque<Value> queue;

    // caller must hold lock.
    // only used after State==Idle
    static
    void maybeReply(server::Server::Pvt* server, const std::shared_ptr<MonitorOp>& op)
    {
        if(!op->scheduled && op->state==Executing && !op->queue.empty() && (!op->pipeline || op->window))
        {
            server->acceptor_loop.dispatch([op](){
                op->doReply();
            });
            op->scheduled = true;
        }
    }

    void doReply()
    {
        auto ch = chan.lock();
        if(!ch)
            return;
        auto conn = ch->conn.lock();
        if(!conn || !conn->bev)
            return;

        Guard G(lock);
        scheduled = false;

        if(state==Dead)
            return;

        uint8_t subcmd = 0u;
        if(state==Creating) {
            subcmd = 0x08;
            state = type ? Idle : Dead;

        } else if(state==Executing) {
            if(queue.empty()) {
                return; // nothing to do

            } else if(!queue.front()) {
                finished = true;
                subcmd = 0x10;
                state = Dead;
            }
        }

        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(hostBE, conn->txBody.get());
            to_wire(R, uint32_t(ioid));
            to_wire(R, subcmd);
            if(subcmd&0x08) {
                if(!msg.empty() || !type) {
                    to_wire(R, Status::error(msg));

                } else {
                    to_wire(R, Status{});
                    to_wire(R, type.get());
                }

            } else if(!queue.empty()) {
                auto& ent = queue.front();
                if(ent) {
                    to_wire_valid(R, ent);
                    // TODO: placeholder for overrun mask
                    to_wire(R, uint8_t(0u));

                } else { // finish (could be used to send an error)
                    to_wire(R, Status{});
                }

                queue.pop_front();
            }
        }

        conn->enqueueTxBody(pva_app_msg_t::CMD_MONITOR);

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
            return;
        }

        if(state==Executing) {
            // TODO: look at queue size change and maybe dispatch low water mark
        }

        if(state==Executing && !queue.empty()) {
            // reshedule myself
            assert(!scheduled); // we've been holding the lock, so this should not have changed

            auto self(shared_from_this());
            conn->iface->server->acceptor_loop.dispatch([self]() {
                self->doReply();
            });
            scheduled = true;
        }
    }
};

struct ServerMonitorSetup;

struct ServerMonitorControl : public server::MonitorControlOp
{
    ServerMonitorControl(ServerMonitorSetup* setup,
                     const std::weak_ptr<server::Server::Pvt>& server,
                     const std::string& name,
                     const Value& request,
                     const std::weak_ptr<MonitorOp>& op);
    virtual ~ServerMonitorControl() {
        finish();
    }

    virtual bool doPost(Value&& val, bool maybe, bool force) override final
    {
        auto mon(op.lock());
        if(!mon)
            return false;

        Guard G(mon->lock);

        if((mon->queue.size() < mon->limit) || force || !val) {
            mon->queue.push_back(std::move(val));

        } else if(!maybe) {
            // squash
            assert(mon->limit>0 && !mon->queue.empty());

            mon->queue.back().assign(val);
            // TODO track overrun

        } else {
            // nope
        }

        if(auto serv = server.lock())
            MonitorOp::maybeReply(serv.get(), mon);

        return mon->queue.size() < mon->limit;
    }

    virtual int32_t nFree() const override final
    {
        return 0; // TODO
    }
    virtual unsigned long long maxFree() const override final
    {
        return 0; // TODO
    }
    virtual void setWatermarks(size_t low, size_t high) override final
    {
    }
    virtual void onStart(std::function<void (bool)> &&fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onStart = std::move(fn);
        });
    }
    virtual void onHighMark(std::function<void ()> &&fn) override final
    {
    }
    virtual void onLowMark(std::function<void ()> &&fn) override final
    {
    }

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<MonitorOp> op;
};

struct ServerMonitorSetup : public server::MonitorSetupOp
{
    ServerMonitorSetup(ServerConn* conn,
                     const std::weak_ptr<server::Server::Pvt>& server,
                     const std::string& name,
                     const Value& request,
                     const std::weak_ptr<MonitorOp>& op)
        :server(server)
        ,op(op)
    {
        _op = Info;
        _name = name;
        _peerName = conn->peerName;
        _ifaceName = conn->iface->name;
    }
    virtual ~ServerMonitorSetup() {
        error("Monitor Create implied error");
    }

    virtual std::unique_ptr<server::MonitorControlOp> connect(const Value &prototype) override final
    {
        if(!prototype)
            throw std::invalid_argument("Must provide prototype");
        auto type = Value::Helper::type(prototype);

        std::unique_ptr<server::MonitorControlOp> ret;

        auto serv = server.lock();
        if(!serv)
            return ret;
        serv->acceptor_loop.call([this, &type, &ret](){
            if(auto oper = op.lock()) {
                if(oper->state!=ServerOp::Creating)
                    return;
                oper->type = type;
                ret.reset(new ServerMonitorControl(this, server, _name, pvRequest, oper));
                oper->doReply();
            }
        });
        if(!ret)
            throw std::runtime_error("Dead Operation");

        return ret;
    }
    virtual void error(const std::string &msg) override final
    {
        if(msg.empty())
            throw std::invalid_argument("Must provide error message");
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &msg](){
            if(auto oper = op.lock()) {
                if(oper->state==ServerOp::Creating) {
                    oper->msg = msg;
                    oper->doReply();
                }
            }
        });
    }
    virtual void onClose(std::function<void (const std::string &)> &&fn) override final
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
    const std::weak_ptr<MonitorOp> op;
};


ServerMonitorControl::ServerMonitorControl(ServerMonitorSetup* setup,
                                           const std::weak_ptr<server::Server::Pvt>& server,
                                           const std::string& name,
                                           const Value& request,
                                           const std::weak_ptr<MonitorOp>& op)
    :server(server)
    ,op(op)
{
    _op = Info;
    _name = name;
    _peerName = setup->peerName();
    _ifaceName = setup->name();
}

} // namespace

void ServerConn::handle_MONITOR()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid = -1, ioid = -1;
    uint8_t subcmd = 0;
    uint32_t nack = 0;

    from_wire(M, sid);
    from_wire(M, ioid);
    from_wire(M, subcmd);

    if(subcmd&0x08) { // INIT
        // type and full value
        Value pvRequest;
        from_wire_type_value(M, rxRegistry, pvRequest);

        if(subcmd&0x80) {
            from_wire(M, nack);
        }

        if(!M.good()) {
            log_printf(connio, Debug, "Client %s\n Invalid MONITOR/%x INIT\n",
                       peerName.c_str(), subcmd);
            bev.reset();
            return;
        }

        auto& chan = lookupSID(sid);

        if(opByIOID.find(ioid)!=opByIOID.end()) {
            log_printf(connsetup, Err, "Client %s reuses existing ioid %u\n", peerName.c_str(), unsigned(ioid));
            bev.reset();
            return;
        }

        auto op(std::make_shared<MonitorOp>(chan, ioid));
        op->window = nack;
        (void)pvRequest["record._options.pipeline"].as(op->pipeline);

        pvRequest["record._options.queueSize"].as<size_t>([&op](size_t qSize){
            if(qSize>1)
                op->limit = qSize;
        });

        std::unique_ptr<ServerMonitorSetup> ctrl(new ServerMonitorSetup(this, iface->server->internal_self, chan->name, pvRequest, op));

        op->state = ServerOp::Creating;

        opByIOID[ioid] = op;
        chan->opByIOID[ioid] = op;

        log_printf(connsetup, Debug, "Client %s Monitor INIT ioid=%u pvRequest=%s\n",
                   peerName.c_str(), unsigned(ioid),
                   std::string(SB()<<pvRequest).c_str());

        if(chan->onSubscribe) {
            chan->onSubscribe(std::move(ctrl));
        } else {
            ctrl->error("Monitor operation not implemented by this PV");
        }

    } else { // start, stop, ack, destroy

        if(subcmd&0x80) {
            from_wire(M, nack);
        }

        if(!M.good()) {
            log_printf(connio, Debug, "Client %s\n Invalid MONITOR/%x CMD\n",
                       peerName.c_str(), subcmd);
            bev.reset();
            return;
        }

        std::shared_ptr<MonitorOp> op;
        auto it = opByIOID.find(ioid);
        if(it==opByIOID.end() || !(op=std::dynamic_pointer_cast<MonitorOp>(it->second))
                || op->state==ServerOp::Dead || op->state==ServerOp::Creating) {
            log_printf(connio, Err, "Client %s MONITORs %s IOID %u state=%d\n", peerName.c_str(),
                       it==opByIOID.end() ? "non-existant" : "invalid", unsigned(ioid),
                       op ? op->state : ServerOp::Dead);
            bev.reset();
            return;
        }

        auto& chan = lookupSID(sid);

        // pvAccessCPP won't accept ack and start/stop in the same message,
        // although it will accept destroy in any !INIT message.
        // We do accept ack+start/stop as there is no reason not to.
        if(subcmd&0x80 && op->pipeline) { // ack
            log_printf(connio, Debug, "Client %s IOID %u acks %u\n",
                       peerName.c_str(), unsigned(ioid), unsigned(nack));

            Guard G(op->lock);

            op->window += nack;

            // TODO: notify high level
        }

        if(subcmd&0x04) {
            bool start = subcmd&0x40;

            {
                Guard G(op->lock);
                op->state = start ? ServerOp::Executing : ServerOp::Idle;
            }

            if(op->onStart)
                op->onStart(start);

            {
                Guard G(op->lock);
                MonitorOp::maybeReply(iface->server, op);
            }
        }

        if(subcmd&0x10) {
            // destroy

            chan->opByIOID.erase(ioid);
            auto it = opByIOID.find(ioid);
            if(it!=opByIOID.end()) {
                auto self(it->second);
                opByIOID.erase(it);

                if(self->onClose)
                    iface->server->acceptor_loop.dispatch([self](){
                        self->onClose("");
                    });

            } else {
                assert(false); // really shouldn't happen
            }
            opByIOID.erase(ioid);
        }
    }
}

}} // namespace pvxs::impl
