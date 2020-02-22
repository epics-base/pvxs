/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsAssert.h>

#include <pvxs/log.h>
#include "clientimpl.h"

namespace pvxs {
namespace client {

DEFINE_LOGGER(setup, "pvxs.client.setup");
DEFINE_LOGGER(io, "pvxs.client.io");

namespace {

struct GPROp : public OperationBase
{
    std::function<Value(Value&&)> builder;
    std::function<void(Result&&)> done;
    Value pvRequest;
    Value rpcarg;
    Result result;
    bool getOput = false;

    enum state_t : uint8_t {
        Connecting, // waiting for an active Channel
        Creating,   // waiting for reply to INIT
        GetOPut,    // waiting for reply to GET (CMD_PUT only)
        BuildPut,   // waiting for PUT builder callback
        Exec,       // waiting for reply to EXEC
        Done,
    } state = Connecting;

    GPROp(operation_t op, const std::shared_ptr<Channel>& chan)
        :OperationBase (op, chan)
    {}
    ~GPROp() {
        cancel();
    }

    void notify() {
        try {
            if(done)
                done(std::move(result));
        } catch(std::exception& e) {
            if(chan && chan->conn)
                log_err_printf(io, "Server %s channel %s error in result cb : %s\n",
                               chan->conn->peerName.c_str(), chan->name.c_str(), e.what());

            // keep first error (eg. from put builder)
            if(!result.error())
                result = Result(std::current_exception());
        }
    }

    virtual void cancel() override final
    {
        auto context = chan->context;
        decltype (done) junk;
        context->tcp_loop.call([this, &junk](){
            if(state==GetOPut || state==Exec) {
                chan->conn->sendDestroyRequest(chan->sid, ioid);

                // This opens up a race with an in-flight reply.
                chan->conn->opByIOID.erase(ioid);
            }
            state = Done;
            chan.reset();
            junk = std::move(done);
            // leave opByIOID for GC
        });
    }

    virtual void createOp() override final
    {
        if(state!=Connecting) {
            return;
        }

        auto& conn = chan->conn;

        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(hostBE, conn->txBody.get());

            to_wire(R, chan->sid);
            to_wire(R, ioid);
            to_wire(R, uint8_t(0x08)); // INIT
            to_wire(R, Value::Helper::desc(pvRequest));
            to_wire_full(R, pvRequest);
        }
        conn->enqueueTxBody(pva_app_msg_t(uint8_t(op)));

        log_debug_printf(io, "Server %s channel '%s' op%02x INIT\n",
                         conn->peerName.c_str(), chan->name.c_str(), op);

        state = Creating;
    }

    virtual void disconnected(const std::shared_ptr<OperationBase> &self) override final
    {
        if(state==Connecting || state==Done) {
            // noop

        } else if(state==Creating || state==GetOPut || (state==Exec && op==Get)) {
            // return to pending

            chan->pending.push_back(self);
            state = Connecting;

        } else if(state==Exec) {
            // can't restart as server side-effects may occur
            state = Done;
            result = Result(std::make_exception_ptr(Disconnect()));

            notify();

        } else {
            throw std::logic_error("GPR Disconnect unexpected state");
        }
    }
};

} // namespace

void Connection::handle_GPR(pva_app_msg_t cmd)
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t ioid;
    uint8_t subcmd;
    Status sts;
    Value data; // hold prototype (INIT) or reply data (GET)

    from_wire(M, ioid);
    from_wire(M, subcmd);
    from_wire(M, sts);
    bool init = subcmd&0x08;
    bool get  = subcmd&0x40;

    // immediately deserialize in unambigous cases

    if(M.good() && cmd!=CMD_RPC && init && sts.isSuccess()) {
        // INIT of PUT or GET, decode type description

        from_wire_type(M, rxRegistry, data);

    } else if(M.good() && cmd==CMD_RPC && !init &&  sts.isSuccess()) {
        // RPC reply

        from_wire_type(M, rxRegistry, data);
        if(data)
            from_wire_full(M, rxRegistry, data);
    }

    // need type info from INIT reply to decode PUT/GET

    RequestInfo* info=nullptr;
    if(M.good()) {
        auto it = opByIOID.find(ioid);
        if(it!=opByIOID.end()) {
            info = &it->second;

        } else {
            auto lvl = Level::Debug;
            if(cmd!=CMD_RPC && !init) {
                // We don't have enough information to decode the rest of the payload.
                // This *may* leave rxRegistry out of sync (if it contains Variant Unions).
                // We can't know whether this is the case.
                // Failing soft here may lead to failures decoding future replies.
                // We could force close the Connection here to be "safe".
                // However, we assume the such usage of Variant is relatively rare

                lvl = Level::Err;
            }

            log_printf(io, lvl,  "Server %s uses non-existant IOID %u.  Ignoring...\n",
                       peerName.c_str(), unsigned(ioid));
            return;
        }

        if(cmd!=CMD_RPC && init && sts.isSuccess()) {
            // INIT of PUT or GET, store type description
            info->prototype = data;

        } else if(M.good() && cmd!=CMD_RPC && !init &&  sts.isSuccess()) {
            // GET/PUT reply

            data = info->prototype.cloneEmpty();
            if(data)
                from_wire_full(M, rxRegistry, data);
        }
    }

    // validate received message against operation state

    std::shared_ptr<OperationBase> op;
    GPROp* gpr = nullptr;
    if(M.good() && info) {
        op = info->handle.lock();
        if(!op) {
            // assume op has already sent CMD_DESTROY_REQUEST
            log_debug_printf(io, "Server %s ignoring stake cmd%02x ioid %u\n",
                             peerName.c_str(), cmd, unsigned(ioid));
            return;
        }

        if(uint8_t(op->op)!=cmd) {
            // peer mixes up IOID and operation type
            M.fault();

        } else {
            gpr = static_cast<GPROp*>(op.get());

            // check that subcmd is as expected based on operation state
            if((gpr->state==GPROp::Creating) ^ init) {
                M.fault();

            } else if(gpr->state==GPROp::GetOPut && !get) {
                M.fault();

            } else if(gpr->state!=GPROp::Exec) {
                M.fault();
            }
        }
    }

    if(!M.good() || !gpr) {
        log_crit_printf(io, "Server %s sends invalid op%02x.  Disconnecting...\n", peerName.c_str(), cmd);
        bev.reset();
        return;
    }

    // advance operation state

    decltype (gpr->state) prev = gpr->state;

    if(!sts.isSuccess()) {
        gpr->result = Result(std::make_exception_ptr(RemoteError(sts.msg)));
        gpr->state = GPROp::Done;

    } else if(gpr->state==GPROp::Creating) {

        if(cmd==CMD_PUT && gpr->getOput) {
            gpr->state = GPROp::GetOPut;

        } else if(cmd==CMD_PUT && !gpr->getOput) {
            gpr->state = GPROp::BuildPut;

        } else {
            gpr->state = GPROp::Exec;
        }

    } else if(gpr->state==GPROp::GetOPut) {
        gpr->state = GPROp::BuildPut;

        info->prototype.assign(data);

    } else if(gpr->state==GPROp::Exec) {
        gpr->state = GPROp::Done;

        if(cmd!=CMD_PUT)
            gpr->result = Result(std::move(data));

    } else {
        // should be avoided above
        throw std::logic_error("GPR advance state inconsistent");
    }

    // transient state (because builder callback is synchronous)
    if(gpr->state==GPROp::BuildPut) {
        Value arg(info->prototype.clone());

        try {
            info->prototype = gpr->builder(std::move(arg));
            gpr->state = GPROp::Exec;

        } catch(std::exception& e) {
            gpr->result = Result(std::current_exception());
            gpr->state = GPROp::Done;
        }
    }

    log_debug_printf(io, "Server %s channel %s op%02x state %d -> %d\n",
                     peerName.c_str(), op->chan->name.c_str(), cmd, prev, gpr->state);

    // act on new operation state

    {
        (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

        EvOutBuf R(hostBE, txBody.get());

        to_wire(R, op->chan->sid);
        to_wire(R, ioid);
        if(gpr->state==GPROp::GetOPut) {
            to_wire(R, 0x40);

        } else if(gpr->state==GPROp::Exec) {
            to_wire(R, 0x00);
            to_wire_valid(R, info->prototype);

        } else if(gpr->state==GPROp::Done) {
            // we're actually building CMD_DESTROY_REQUEST
            // nothing more needed
        }
    }
    enqueueTxBody(gpr->state==GPROp::Done ? CMD_DESTROY_REQUEST :  cmd);

    if(gpr->state==GPROp::Done) {
        // CMD_DESTROY_REQUEST is not acknowledged (sigh...)
        // but at this point a server should not send further GET/PUT/RPC w/ this IOID
        // so we can ~safely forget about it.
        // we might get CMD_MESSAGE, but these could be ignored with no ill effects.
        opByIOID.erase(ioid);

        gpr->notify();
    }
}

void Connection::handle_GET() { handle_GPR(CMD_GET); }
void Connection::handle_PUT() { handle_GPR(CMD_PUT); }
void Connection::handle_RPC() { handle_GPR(CMD_RPC); }

std::shared_ptr<Operation> Context::GetBuilder::_exec_get()
{
    std::shared_ptr<Operation> ret;
    assert(_get);

    pvt->tcp_loop.call([&ret, this]() {
        auto chan = Channel::build(pvt, _name);

        auto op = std::make_shared<GPROp>(Operation::Get, chan);
        op->done = std::move(_result);
        // TODO pvRequest

        chan->pending.push_back(op);
        chan->createOperations();

        ret = std::move(op);
    });

    return  ret;
}

std::shared_ptr<Operation> Context::PutBuilder::exec()
{
    std::shared_ptr<Operation> ret;

    if(!_builder)
        throw std::logic_error("put() requires a builder()");

    pvt->tcp_loop.call([&ret, this]() {
        auto chan = Channel::build(pvt, _name);

        auto op = std::make_shared<GPROp>(Operation::Put, chan);
        op->done = std::move(_result);
        op->builder = std::move(_builder);
        op->getOput = _doGet;
        // TODO pvRequest

        chan->pending.push_back(op);
        chan->createOperations();

        ret = std::move(op);
    });

    return  ret;
}

std::shared_ptr<Operation> Context::RPCBuilder::exec()
{
    std::shared_ptr<Operation> ret;

    pvt->tcp_loop.call([&ret, this]() {
        auto chan = Channel::build(pvt, _name);

        auto op = std::make_shared<GPROp>(Operation::Put, chan);
        op->done = std::move(_result);
        op->rpcarg = std::move(_argument);
        // TODO pvRequest

        chan->pending.push_back(op);
        chan->createOperations();

        ret = std::move(op);
    });

    return  ret;
}

} // namespace client
} // namespace pvxs
