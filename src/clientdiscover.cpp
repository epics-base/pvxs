/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <pvxs/log.h>
#include <pvxs/nt.h>
#include "utilpvt.h"
#include "clientimpl.h"

DEFINE_LOGGER(setup, "pvxs.client.setup");
DEFINE_LOGGER(io, "pvxs.client.io");

namespace pvxs {
namespace client {

Discovery::Discovery(const std::shared_ptr<ContextImpl> &context)
    :OperationBase (Operation::Discover, context->tcp_loop)
    ,context(context)
{}

Discovery::~Discovery() {
    if(loop.assertInRunningLoop())
        _cancel(true);
}

bool Discovery::cancel()
{
    decltype (notify) junk;
    bool ret;
    loop.call([this, &junk, &ret](){
        ret = _cancel(false);
        junk = std::move(notify);
        // leave opByIOID for GC
    });
    return ret;
}

bool Discovery::_cancel(bool implicit) {
    bool active = running;

    if(active) {
        context->discoverers.erase(this);
        running = false;
    }
    return active;
}

// unused for this special case
void Discovery::_reExecGet(std::function<void (Result &&)> &&resultcb) {}
void Discovery::_reExecPut(const Value &arg, std::function<void (Result &&)> &&resultcb) {}
void Discovery::createOp() {}
void Discovery::disconnected(const std::shared_ptr<OperationBase> &self) {}

std::shared_ptr<Operation> DiscoverBuilder::exec()
{
    if(!ctx)
        throw std::logic_error("NULL Builder");
    if(!_fn)
        throw std::logic_error("Callback required");

    auto context(ctx->impl->shared_from_this());
    auto ping(_ping);

    auto op(std::make_shared<Discovery>(context));
    op->notify = std::move(_fn);

    auto syncCancel(_syncCancel);
    std::shared_ptr<Discovery> external(op.get(), [op, syncCancel](Discovery*) mutable {
        // (maybe) user thread
        auto loop(op->context->tcp_loop);
        auto temp(std::move(op));
        loop.tryInvoke(syncCancel, std::bind([](std::shared_ptr<Discovery>& op){
                           // on worker
                           op->context->discoverers.erase(op.get());

                       }, std::move(temp)));
    });

    // setup timer to send discovery

    context->tcp_loop.dispatch([op, context, ping]() {

        if(context->state!=ContextImpl::Running)
            throw std::logic_error("Context close()d");

        bool first = context->discoverers.empty();

        context->discoverers[op.get()] = op;
        op->running = true;

        if(first && ping) {
            log_debug_printf(setup, "Starting Discover%s", "\n");

            context->tickSearch(true);
        }
    });

    return external;
}

void ContextImpl::serverEvent(const Discovered &evt)
{
    for(auto& pair : discoverers) {
        if(auto dis = pair.second.lock()) {
            try {
                dis->notify(evt);
            } catch(std::exception& e) {
                log_exc_printf(io, "Unhandled exception during Discovery callback : %s\n", e.what());
            }
        }
    }
}

std::ostream& operator<<(std::ostream& strm, const Discovered& serv)
{
    char prefix[64];

    serv.time.strftime(prefix, sizeof(prefix), "%Y-%m-%dT%H:%M:%S.%9f");
    strm<<prefix;

    switch(serv.event) {
    case client::Discovered::Online:
        strm<<" ONLINE ";
        break;
    case client::Discovered::Timeout:
        strm<<" OFFLINE";
        break;
    }

    strm<<" guid: "<<serv.guid
        <<" proto: "<<escape(serv.proto)
        <<" server: "<<serv.server
        <<" ver: "<<unsigned(serv.peerVersion)
        <<" via: "<<serv.peer;

    return strm;
}

} // namespace client
} // namespace pvxs
