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

DEFINE_LOGGER(io, "pvxs.client.io");

namespace {

struct InfoOp : public OperationBase
{
    std::function<void(Value&&)> done;
    Value result;

    enum state_t {
        Connecting,
        Waiting,
        Done,
    } state = Connecting;

    explicit InfoOp(const std::shared_ptr<Channel>& chan)
        :OperationBase(Info, chan)
    {}

    virtual ~InfoOp()
    {
        cancel();
    }

    virtual void cancel() override final {}

    virtual void createOp() override final
    {
        assert(state==Connecting);

        auto& conn = chan->conn;

        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(hostBE, conn->txBody.get());

            to_wire(R, chan->sid);
            to_wire(R, ioid);
            // sub-field, which no one knows how to use...
            to_wire(R, "");
        }
        conn->enqueueTxBody(CMD_GET_FIELD);

        log_debug_printf(io, "Server %s channel '%s' GET_INFO\n", conn->peerName.c_str(), chan->name.c_str());

        state = Waiting;
    }
};

} // namespace

void Connection::handle_GET_FIELD()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t ioid=0u;
    Status sts;
    Value prototype;

    from_wire(M, ioid);
    from_wire(M, sts);
    from_wire_type(M, rxRegistry, prototype);

    if(!M.good()) {
        log_crit_printf(io, "Server %s sends invalid GET_FIELD.  Disconnecting...\n", peerName.c_str());
        bev.reset();
        return;
    }

    std::shared_ptr<Operation> op;
    {
        auto it = opByIOID.find(ioid);
        if(it==opByIOID.end()
                || !(op = it->second.handle.lock())
                || op->op!=Operation::Info) {
            log_warn_printf(io, "Server %s sends stale GET_FIELD\n", peerName.c_str());
            return;
        }
        opByIOID.erase(it);
    }

    auto info = static_cast<InfoOp*>(op.get());

    if(info->state!=InfoOp::Waiting) {
        log_warn_printf(io, "Server %s ignore second reply to GET_FIELD\n", peerName.c_str());
        return;
    }

    log_debug_printf(io, "Server %s completes GET_FIELD.\n", peerName.c_str());

    info->state = InfoOp::Done;

    if(info->done) {
        auto done = std::move(info->done);
        done(std::move(prototype));

    } else {
        info->result = prototype;
    }
}

std::shared_ptr<Operation> Context::GetBuilder::exec()
{
    std::shared_ptr<Operation> ret;

    if(_get)
        throw std::runtime_error("Get Not Implemented");

    pvt->tcp_loop.call([&ret, this]() {
        auto chan = Channel::build(pvt, _name);

        auto op = std::make_shared<InfoOp>(chan);
        op->done = std::move(_result);

        chan->pending.push_back(op);
        chan->createOperations();

        ret = op;
    });

    return ret;
}

} // namespace client
} // namespace pvxs
