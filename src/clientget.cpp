/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <epicsAssert.h>

#include <pvxs/log.h>
#include <pvxs/nt.h>
#include "utilpvt.h"
#include "clientimpl.h"

namespace pvxs {
namespace client {

DEFINE_LOGGER(setup, "pvxs.client.setup");
DEFINE_LOGGER(io, "pvxs.client.io");

namespace detail {

struct PRBase::Args
{
    std::map<std::string, std::pair<Value, bool>> values;
    std::vector<std::string> names;

    // put() builder
    Value build(Value&& prototype) const
    {
        Value ret(prototype.cloneEmpty());

        for(auto& pair : values) {
            if(auto fld = ret[pair.first]) {
                try {
                    auto store = Value::Helper::store(pair.second.first);
                    fld.copyIn(static_cast<const void*>(&store->store), store->code);
                }catch(NoConvert& e){
                    if(pair.second.second)
                        throw;
                }

            } else if(pair.second.second) {
                throw std::runtime_error(SB()<<"PutBuilder server type missing required field '"<<pair.first<<"'");
            }
        }
        return ret;
    }

    Value uriArgs() const
    {
        TypeDef type(nt::NTURI{}.build());

        std::list<Member> arguments;

        for(auto& name : names) {
            auto it = values.find(name);
            if(it==values.end())
                throw std::logic_error("uriArgs() names vs. values mis-match");

            auto& value = it->second.first;

            arguments.push_back(TypeDef(value).as(name));
        }

        type += {Member(TypeCode::Struct, "query", arguments)};

        auto inst(type.create());

        for(auto& pair : values) {
            inst["query"][pair.first].assign(pair.second.first);
        }

        return inst;
    }
};

PRBase::~PRBase() {}

Value PRBase::_builder(Value&& prototype) const
{
    assert(_args);
    return _args->build(std::move(prototype));
}

Value PRBase::_uriArgs() const
{
    assert(_args);
    return _args->uriArgs();
}

void PRBase::_set(const std::string& name, const void *ptr, StoreType type, bool required)
{
    if(!_args)
        _args = std::make_shared<Args>();

    if(_args->values.find(name)!=_args->values.end())
        throw std::logic_error(SB()<<"PutBuilder can't assign a second value to field '"<<name<<"'");

    Value aval(Value::Helper::build(ptr, type));

    _args->values.emplace(std::piecewise_construct,
                         std::make_tuple(name),
                         std::make_tuple(std::move(aval), required));
    _args->names.push_back(name);
}

} // namespace detail

namespace {

struct GPROp : public OperationBase
{
    std::function<Value(Value&&)> builder;
    std::function<void(Result&&)> done;
    std::function<void (const Value&)> onInit;
    Value pvRequest;
    Value arg;
    Result result;
    bool getOput = false;
    bool autoExec = true;

    enum state_t : uint8_t {
        Connecting, // waiting for an active Channel
        Creating,   // waiting for reply to INIT
        Idle,       // waiting for explicit exec request
        GetOPut,    // waiting for reply to GET (CMD_PUT only)
        BuildPut,   // waiting for PUT builder callback
        Exec,       // waiting for reply to EXEC
        Done,
    } state = Connecting;

    INST_COUNTER(GPROp);

    GPROp(operation_t op, const evbase& loop)
        :OperationBase (op, loop)
    {}
    ~GPROp() {
        loop.assertInLoop();
        _cancel(true);
    }

    void setDone(decltype (done)&& donecb, decltype (onInit)&& initcb)
    {
        onInit = std::move(initcb);
        if(donecb) {
            done = std::move(donecb);
        } else {
            auto waiter = this->waiter = std::make_shared<ResultWaiter>();
            done = [waiter](Result&& result) {
                waiter->complete(std::move(result), false);
            };
        }
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

    virtual bool cancel() override final
    {
        decltype (done) junk;
        decltype (onInit) junkI;
        bool ret;
        loop.call([this, &junk, &junkI, &ret](){
            ret = _cancel(false);
            junk = std::move(done);
            junkI = std::move(onInit);
            // leave opByIOID for GC
        });
        return ret;
    }


    bool _cancel(bool implicit) {
        if(implicit && state!=Done) {
            log_info_printf(setup, "implied cancel of op%x on channel '%s'\n",
                            op, chan ? chan->name.c_str() : "");
        }
        if(state==Idle || state==GetOPut || state==Exec) {
            chan->conn->sendDestroyRequest(chan->sid, ioid);
        }
        if(state==Creating || state==Idle || state==GetOPut || state==Exec) {
            // This opens up a race with an in-flight reply.
            chan->conn->opByIOID.erase(ioid);
            chan->opByIOID.erase(ioid);
        }
        bool ret = state!=Done;
        state = Done;
        return ret;
    }

    virtual void reExec(const Value& arg, std::function<void(client::Result&&)>&& resultcb) override final
    {
        if(op!=RPC && arg)
            throw std::invalid_argument("Only RPC may reExec() with Value");

        auto a(arg);
        auto cb(std::move(resultcb));

        loop.dispatch([this, a, cb]() mutable {
            if(autoExec) {
                client::Result ret(std::make_exception_ptr(std::invalid_argument("reExec() requires Operation creation with .autoExec(false)")));
                cb(std::move(ret));
                return;
            }
            if(state!=Idle)
                return;

            this->arg = std::move(a);
            this->done = std::move(cb);

            _reExec();
        });
    }

    void _reExec()
    {
        if(op==Put && getOput) {
            state = GPROp::GetOPut;

        } else if(op==Put && !getOput) {
            state = GPROp::BuildPut;

        } else {
            state = GPROp::Exec;
        }

        sendReply();
    }

    void sendReply()
    {
        Value temp;

        // transient state (because builder callback is synchronous)
        if(state==GPROp::BuildPut) {
            temp = arg.clone();

            try {
                temp = builder(std::move(temp));
                state = GPROp::Exec;

            } catch(std::exception& e) {
                result = Result(std::current_exception());
                state = GPROp::Done;
            }
        }

        // act on new operation state

        {
            (void)evbuffer_drain(chan->conn->txBody.get(), evbuffer_get_length(chan->conn->txBody.get()));

            EvOutBuf R(hostBE, chan->conn->txBody.get());

            to_wire(R, chan->sid);
            to_wire(R, ioid);
            if(state==GPROp::GetOPut) {
                to_wire(R, uint8_t(0x40));

            } else if(state==GPROp::Exec) {
                to_wire(R, uint8_t(0x00));
                if(op==Put) {
                    to_wire_valid(R, temp);

                } else if(op==RPC) {
                    to_wire(R, Value::Helper::desc(arg));
                    if(arg)
                        to_wire_full(R, arg);
                }

            } else if(state==GPROp::Done) {
                // we're actually building CMD_DESTROY_REQUEST
                // nothing more needed

            } else {
                throw std::logic_error("Invalid state in GPR sendReply()");
            }
        }
        chan->conn->enqueueTxBody(state==GPROp::Done ? CMD_DESTROY_REQUEST :  (pva_app_msg_t)op);

        if(state==GPROp::Done) {
            // CMD_DESTROY_REQUEST is not acknowledged (sigh...)
            // but at this point a server should not send further GET/PUT/RPC w/ this IOID
            // so we can ~safely forget about it.
            // we might get CMD_MESSAGE, but these could be ignored with no ill effects.
            chan->conn->opByIOID.erase(ioid);
            chan->opByIOID.erase(ioid);

            notify();
        }
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

        } else if(state==Exec && op!=Get && !autoExec) {
            // can't restart as server side-effects may occur
            state = Done;
            result = Result(std::make_exception_ptr(Disconnect()));

            notify();

        } else if(state==Creating || state==Idle || state==GetOPut || state==Exec) {
            // return to pending

            chan->pending.push_back(self);
            state = Connecting;

        } else {
            state = Done;
            result = Result(std::make_exception_ptr(std::logic_error("GPR Disconnect in unexpected state")));

            notify();
        }
    }
};

} // namespace

void Connection::handle_GPR(pva_app_msg_t cmd)
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t ioid;
    uint8_t subcmd=0;
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

        } else if(M.good() && !init && (cmd==CMD_GET || (cmd==CMD_PUT && get)) &&  sts.isSuccess()) {
            // GET reply

            data = info->prototype.cloneEmpty();
            if(data)
                from_wire_valid(M, rxRegistry, data);
        }
    }

    // validate received message against operation state

    std::shared_ptr<OperationBase> op;
    GPROp* gpr = nullptr;
    if(M.good() && info) {
        op = info->handle.lock();
        if(!op) {
            // assume op has already sent CMD_DESTROY_REQUEST
            log_debug_printf(io, "Server %s ignoring stale cmd%02x ioid %u\n",
                             peerName.c_str(), cmd, unsigned(ioid));
            return;
        }

        if(uint8_t(op->op)!=cmd) {
            // peer mixes up IOID and operation type
            M.fault(__FILE__, __LINE__);

        } else {
            gpr = static_cast<GPROp*>(op.get());

            // check that subcmd is as expected based on operation state
            if((gpr->state==GPROp::Creating) && init) {

            } else if((gpr->state==GPROp::GetOPut) && !init && get) {

            } else if((gpr->state==GPROp::Exec) && !init && !get) {

            } else {
                M.fault(__FILE__, __LINE__);
            }
        }
    }

    if(!M.good() || !gpr) {
        log_crit_printf(io, "%s:%d Server %s sends invalid op%02x.  Disconnecting...\n",
                        M.file(), M.line(), peerName.c_str(), cmd);
        bev.reset();
        return;
    }

    // advance operation state

    decltype (gpr->state) prev = gpr->state;

    if(!sts.isSuccess()) {
        gpr->result = Result(std::make_exception_ptr(RemoteError(sts.msg)));
        gpr->state = gpr->state==GPROp::Creating || gpr->autoExec ? GPROp::Done : GPROp::Idle;

    } else if(gpr->state==GPROp::Creating) {

        gpr->state = GPROp::Idle;
        if(cmd==CMD_PUT || cmd==CMD_GET)
            gpr->arg = data; // save for later use in sendReply()

        try {
            if(gpr->onInit)
                gpr->onInit(data);
        } catch(std::exception& e) {
            gpr->result = Result(std::current_exception());
            gpr->state = GPROp::Done;
        }

        if(gpr->state==GPROp::Idle && gpr->autoExec)
            gpr->_reExec();
        // reply may now be sent, or deferred
        return;

    } else if(gpr->state==GPROp::GetOPut) {
        gpr->state = GPROp::BuildPut;

        info->prototype.assign(data);

    } else if(gpr->state==GPROp::Exec) {
        // data always empty for CMD_PUT
        gpr->result = Result(std::move(data), peerName);

        if(!gpr->autoExec) {
            gpr->state = GPROp::Idle;
            gpr->notify();
            return;
        }
        gpr->state = GPROp::Done;

    } else {
        // should be avoided above
        throw std::logic_error("GPR advance state inconsistent");
    }

    log_debug_printf(io, "Server %s channel %s op%02x state %d -> %d\n",
                     peerName.c_str(), gpr->chan->name.c_str(), cmd, prev, gpr->state);

    gpr->sendReply();
}

void Connection::handle_GET() { handle_GPR(CMD_GET); }
void Connection::handle_PUT() { handle_GPR(CMD_PUT); }
void Connection::handle_RPC() { handle_GPR(CMD_RPC); }

static
std::shared_ptr<Operation> gpr_setup(const std::shared_ptr<Context::Pvt>& context,
                                     std::string name, // need to capture by value
                                     const std::shared_ptr<GPROp>& op)
{
    auto internal(op);
    std::shared_ptr<GPROp> external(internal.get(), [internal](GPROp*) mutable {
        // (maybe) user thread
        auto loop(internal->loop);
        // std::bind for lack of c++14 generalized capture
        // to move internal ref to worker for dtor
        loop.call(std::bind([](std::shared_ptr<GPROp>& op) {
                      // on worker

                      // ordering of dispatch()/call() ensures creation before destruction
                      assert(op->chan);
                      op->_cancel(true);                  }, std::move(internal)));
        assert(!internal);
        internal.reset();
    });

    context->tcp_loop.dispatch([internal, context, name]() {
        // on worker

        internal->chan = Channel::build(context, name);

        internal->chan->pending.push_back(internal);
        internal->chan->createOperations();
    });

    return external;
}

std::shared_ptr<Operation> GetBuilder::_exec_get()
{
    assert(_get);
    if(!ctx)
        throw std::logic_error("NULL Builder");

    auto op(std::make_shared<GPROp>(Operation::Get, ctx->tcp_loop));
    op->setDone(std::move(_result), std::move(_onInit));
    op->autoExec = _autoexec;
    op->pvRequest = _buildReq();

    return gpr_setup(ctx->shared_from_this(), _name, op);
}

std::shared_ptr<Operation> PutBuilder::exec()
{
    if(!ctx)
        throw std::logic_error("NULL Builder");

    auto op(std::make_shared<GPROp>(Operation::Put, ctx->tcp_loop));
    op->setDone(std::move(_result), std::move(_onInit));

    if(_builder) {
        op->builder = std::move(_builder);
    } else if(_args) {
        // PRBase builder doesn't use current value
        _doGet = false;

        auto build = std::move(_args);
        op->builder = [build](Value&& prototype) -> Value {
            return build->build(std::move(prototype));
        };
    } else {
        // handled above
    }
    op->getOput = _doGet;
    op->autoExec = _autoexec;
    op->pvRequest = _buildReq();

    return gpr_setup(ctx->shared_from_this(), _name, op);
}

std::shared_ptr<Operation> RPCBuilder::exec()
{
    if(!ctx)
        throw std::logic_error("NULL Builder");

    auto op(std::make_shared<GPROp>(Operation::RPC, ctx->tcp_loop));
    op->setDone(std::move(_result), std::move(_onInit));
    if(_argument) {
        if(!_autoexec)
            throw std::invalid_argument("Pass RPC argument during reExec()");
        op->arg = std::move(_argument);
    } else if(_args) {
        op->arg = _args->uriArgs();
        op->arg["path"] = _name;
    }
    op->autoExec = _autoexec;
    op->pvRequest = _buildReq();

    return gpr_setup(ctx->shared_from_this(), _name, op);
}

} // namespace client
} // namespace pvxs
