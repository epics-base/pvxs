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
#include "pvrequest.h"

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

    // only access from accepter worker thread
    std::function<void(bool)> onStart;
    std::function<void()> onLowMark;
    std::function<void()> onHighMark;
    bool lowMarkPending = false;
    bool highMarkPending = false;

    // const after setup phase
    std::shared_ptr<const FieldDesc> type;
    BitMask pvMask;
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
    size_t maxQueue=0u;

    std::deque<Value> queue;

    INST_COUNTER(MonitorOp);

    // caller must hold lock.
    // only used after State==Idle
    static
    void maybeReply(server::Server::Pvt* server, const std::shared_ptr<MonitorOp>& op)
    {
        // can we send a reply?
        if(!op->scheduled && op->state==Executing && !op->queue.empty() && (!op->pipeline || op->window))
        {
            // based on operation state, yes
            server->acceptor_loop.dispatch([op](){
                auto ch(op->chan.lock());
                if(!ch)
                    return;
                auto conn(ch->conn.lock());
                if(!conn || conn->state==ConnBase::Disconnected)
                    return;

                if(conn->connection() && (bufferevent_get_enabled(conn->connection())&EV_READ)) {
                    op->doReply();
                } else {
                    // connection TX queue is too full
                    conn->backlog.push_back(std::bind(&MonitorOp::doReply, op));
                }
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
        if(!conn || !conn->connection())
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
            if(queue.empty() || (pipeline && !window)) {
                return; // nothing to do

            } else if(!queue.front()) {
                finished = true;
                subcmd = 0x10;
                state = Dead;
            }
        }

        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(conn->sendBE, conn->txBody.get());
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
                    to_wire_valid(R, ent, &pvMask);
                    // TODO: placeholder for overrun mask
                    to_wire(R, uint8_t(0u));

                } else { // finish (could be used to send an error)
                    to_wire(R, Status{});
                }

                queue.pop_front();
            }
        }

        ch->statTx += conn->enqueueTxBody(pva_app_msg_t::CMD_MONITOR);

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

        auto self(shared_from_this());

        if(state==Executing && pipeline) {
            assert(window); // previously tested

            window--;

            if(!lowMarkPending && window <= low && onLowMark) {
                lowMarkPending = true;
                conn->iface->server->acceptor_loop.dispatch([self]() {
                    self->lowMarkPending = false;
                    if(self->onLowMark)
                        self->onLowMark();
                });
            }
        }

        if(state==Executing && !queue.empty() && (!pipeline || window)) {
            // reschedule myself
            assert(!scheduled); // we've been holding the lock, so this should not have changed

            conn->iface->server->acceptor_loop.dispatch([self]() {
                self->doReply();
            });
            scheduled = true;
        }
    }

    void show(std::ostream& strm) const override final
    {
        strm<<"MONITOR\n";
    }
};

struct ServerMonitorSetup;

struct ServerMonitorControl : public server::MonitorControlOp
{
    ServerMonitorControl(ServerMonitorSetup* setup,
                     const std::weak_ptr<server::Server::Pvt>& server,
                     const std::string& name,
                     const std::weak_ptr<MonitorOp>& op);
    virtual ~ServerMonitorControl() {
        finish();
    }

    virtual bool doPost(const Value& val, bool maybe, bool force) override final
    {
        auto mon(op.lock());
        if(!mon)
            return false;

        if(val && mon->type && mon->type.get()!=Value::Helper::desc(val))
            throw std::logic_error("Type change not allowed in post().  Recommend pvxs::Value::cloneEmpty()");

        // pvMask is const at this point, so no need to lock
        bool real = testmask(val, mon->pvMask);

        Guard G(mon->lock);
        if(real) {

            if((mon->queue.size() < mon->limit) || force || !val) {
                mon->queue.push_back(val);

                if(mon->maxQueue < mon->queue.size())
                    mon->maxQueue = mon->queue.size();

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
        }

        return mon->queue.size() < mon->limit;
    }

    virtual void stats(server::MonitorStat& stat, bool reset) const override final
    {
        auto mon(op.lock());
        if(!mon)
            return;

        Guard G(mon->lock);

        stat.running = mon->state==MonitorOp::Executing;
        stat.finished = mon->finished;
        stat.pipeline = mon->pipeline;

        stat.nQueue = mon->queue.size();
        stat.maxQueue = mon->maxQueue;
        stat.limitQueue = mon->limit;
        stat.window = mon->window;

        if(reset)
            stat.maxQueue = 0u;
    }

    virtual void setWatermarks(size_t low, size_t high) override final
    {
        if(low > high)
            throw std::logic_error("low must be <= high");

        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, low, high](){
            if(auto oper = op.lock()) {
                Guard G(oper->lock);
                oper->low = low;
                oper->high = high;
                // TODO handle change of levels after start
            }
        });
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
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onHighMark = std::move(fn);
        });
    }
    virtual void onLowMark(std::function<void ()> &&fn) override final
    {
        auto serv = server.lock();
        if(!serv)
            return;
        serv->acceptor_loop.call([this, &fn](){
            if(auto oper = op.lock())
                oper->onLowMark = std::move(fn);
        });
    }

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<MonitorOp> op;

    INST_COUNTER(ServerMonitorControl);
};

struct ServerMonitorSetup : public server::MonitorSetupOp
{
    ServerMonitorSetup(ServerConn* conn,
                     const std::weak_ptr<server::Server::Pvt>& server,
                     const std::string& name,
                     const Value& request,
                     const std::weak_ptr<MonitorOp>& op)
        :MonitorSetupOp(name, conn->cred, Info, request)
        ,server(server)
        ,op(op)
    {}
    virtual ~ServerMonitorSetup() {
        error("Monitor Create implied error");
    }

    virtual std::unique_ptr<server::MonitorControlOp> connect(const Value &prototype) override final
    {
        if(!prototype)
            throw std::invalid_argument("Must provide prototype");
        auto type = Value::Helper::type(prototype);
        auto mask = request2mask(type.get(), _pvRequest);

        std::unique_ptr<server::MonitorControlOp> ret;

        auto serv = server.lock();
        if(!serv)
            return ret;
        serv->acceptor_loop.call([this, &type, &ret, &mask](){
            if(auto oper = op.lock()) {
                if(oper->state!=ServerOp::Creating)
                    return;
                oper->type = type;
                oper->pvMask = std::move(mask);
                ret.reset(new ServerMonitorControl(this, server, _name, oper));
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

    INST_COUNTER(ServerMonitorSetup);
};


ServerMonitorControl::ServerMonitorControl(ServerMonitorSetup* setup,
                                           const std::weak_ptr<server::Server::Pvt>& server,
                                           const std::string& name,
                                           const std::weak_ptr<MonitorOp>& op)
    :server::MonitorControlOp(name, setup->credentials(), Info)
    ,server(server)
    ,op(op)
{}

} // namespace

void ServerConn::handle_MONITOR()
{
    auto rxlen = 8u + evbuffer_get_length(segBuf.get());
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
            log_debug_printf(connio, "%s:%d Client %s\n Invalid MONITOR/%x INIT\n",
                       M.file(), M.line(), peerName.c_str(), subcmd);
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

        auto op(std::make_shared<MonitorOp>(chan, ioid));
        op->window = nack;
        (void)pvRequest["record._options.pipeline"].as(op->pipeline);

        pvRequest["record._options.queueSize"].as<size_t>([&op](size_t qSize){
            if(qSize>1)
                op->limit = qSize;
        });

        if(op->limit < op->window)
            op->limit = op->window;

        std::unique_ptr<ServerMonitorSetup> ctrl(new ServerMonitorSetup(this, iface->server->internal_self, chan->name, pvRequest, op));

        op->state = ServerOp::Creating;

        opByIOID[ioid] = op;
        chan->opByIOID[ioid] = op;

        log_debug_printf(connsetup, "Client %s Monitor INIT%s ioid=%u pvRequest=%s\n",
                   peerName.c_str(), op->pipeline ? " pipeline" : "", unsigned(ioid),
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
            log_debug_printf(connio, "%s:%d Client %s\n Invalid MONITOR/%x CMD\n",
                       M.file(), M.line(), peerName.c_str(), subcmd);
            bev.reset();
            return;
        }

        std::shared_ptr<MonitorOp> op;
        auto it = opByIOID.find(ioid);
        if(it==opByIOID.end() || it->second->state==ServerOp::Dead) {
            // since server destroy commands aren't acknowledged, we can race
            // with traffic sent by the client before processing our destroy.
            // so we can't fault hard, so just ignore and hope for the best.
            rxRegistryDirty = true;
            log_debug_printf(connio, "Client %s MONITORs non-existent IOID %u\n",
                       peerName.c_str(), unsigned(ioid));
            return;

        } else if(!(op=std::dynamic_pointer_cast<MonitorOp>(it->second))
                  || op->state==ServerOp::Creating) {
            // mixing up operation types, or trying to exec before we complete creation,
            // is a protocol error.
            log_err_printf(connio, "Client %s MONITORs invalid IOID %u state=%d\n",
                       peerName.c_str(), unsigned(ioid), op ? op->state : ServerOp::Dead);
            bev.reset();
            return;
        }

        auto chan(op->chan.lock());
        if(!chan || chan->sid!=sid) {
            log_err_printf(connio, "Client %s MONITOR inconsistent sid %u:%u ioid %u\n",
                           peerName.c_str(), unsigned(sid), unsigned(chan ? chan->sid : -1), ioid);
            bev.reset();
            return;
        }
        chan->statRx += rxlen;

        // pvAccessCPP won't accept ack and start/stop in the same message,
        // although it will accept destroy in any !INIT message.
        // We do accept ack+start/stop as there is no reason not to.
        if(subcmd&0x80 && op->pipeline) { // ack

            Guard G(op->lock);

            log_debug_printf(connio, "Client %s IOID %u acks %u, %u/%u\n",
                       peerName.c_str(), unsigned(ioid), unsigned(nack),
                             unsigned(op->window), unsigned(op->high));

            op->window += nack;

            if(!op->highMarkPending && op->window > op->high && op->onHighMark) {
                op->highMarkPending = true;
                iface->server->acceptor_loop.dispatch([op](){
                    op->highMarkPending = false;
                    if(op->onHighMark)
                        op->onHighMark();
                });
            }
        }

        if(subcmd&0x04) {
            bool start = subcmd&0x40;

            log_debug_printf(connio, "Client %s IOID %u MON %s\n",
                       peerName.c_str(), unsigned(ioid), start ? "START" : "STOP");

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

                if(self->onClose) {
                    iface->server->acceptor_loop.dispatch([self](){
                        if(self->onClose)
                            self->onClose("");
                    });
                }

            } else {
                assert(false); // really shouldn't happen
            }
            opByIOID.erase(ioid);
        }
    }
}

}} // namespace pvxs::impl
