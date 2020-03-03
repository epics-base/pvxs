/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiProcess.h>

#include <pvxs/log.h>
#include "clientimpl.h"

namespace pvxs {
namespace client {

DEFINE_LOGGER(io, "pvxs.client.io");

Connection::Connection(const std::shared_ptr<Context::Pvt>& context, const SockAddr& peerAddr)
    :ConnBase (true,
               bufferevent_socket_new(context->tcp_loop.base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS),
               peerAddr)
    ,context(context)
    ,echoTimer(event_new(context->tcp_loop.base, -1, EV_TIMEOUT|EV_PERSIST, &tickEchoS, this))
{
    bufferevent_setcb(bev.get(), &bevReadS, nullptr, &bevEventS, this);

    // shorter timeout until connect() ?
    timeval timo = {30, 0};
    bufferevent_set_timeouts(bev.get(), &timo, &timo);

    if(bufferevent_socket_connect(bev.get(), &peerAddr->sa, peerAddr.size()))
        throw std::runtime_error("Unable to begin connecting");

    log_debug_printf(io, "Connecting to %s\n", peerName.c_str());
}

Connection::~Connection()
{
    log_debug_printf(io, "Cleaning connection to %s\n", peerName.c_str());
    cleanup();
}


void Connection::createChannels()
{
    if(!ready)
        return; // defer until CONNECTION_VALIDATED

    (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

    auto todo = std::move(pending);

    for(auto& wchan : todo) {
        auto chan = wchan.lock();
        if(!chan)
            continue;

        {
            (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

            EvOutBuf R(hostBE, txBody.get());

            to_wire(R, uint16_t(1u));
            to_wire(R, chan->cid);
            to_wire(R, chan->name);
        }
        enqueueTxBody(CMD_CREATE_CHANNEL);

        creatingByCID[chan->cid] = chan;
        chan->state = Channel::Creating;

        log_debug_printf(io, "Server %s creating channel '%s' (%u)\n", peerName.c_str(),
                         chan->name.c_str(), unsigned(chan->cid));
    }
}

void Connection::sendDestroyRequest(uint32_t sid, uint32_t ioid)
{
    if(!bev)
        return;
    {
        (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

        EvOutBuf R(hostBE, txBody.get());

        to_wire(R, sid);
        to_wire(R, ioid);
    }
    enqueueTxBody(CMD_DESTROY_REQUEST);

}

void Connection::bevEvent(short events)
{
    ConnBase::bevEvent(events);

    if(bev && (events&BEV_EVENT_CONNECTED)) {
        log_debug_printf(io, "Connected to %s\n", peerName.c_str());

        if(bufferevent_enable(bev.get(), EV_READ|EV_WRITE))
            throw std::logic_error("Unable to enable BEV");

        // start echo timer
        timeval interval{15, 0};
        if(event_add(echoTimer.get(), &interval))
            log_err_printf(io, "Server %s error starting echoTimer\n", peerName.c_str());
    }
}

std::shared_ptr<ConnBase> Connection::self_from_this()
{
    return shared_from_this();
}

void Connection::cleanup()
{
    // (maybe) keep myself alive
    std::shared_ptr<Connection> self;

    context->connByAddr.erase(peerAddr);

    if(bev)
        bev.reset();

    if(event_del(echoTimer.get()))
        log_err_printf(io, "Server %s error stopping echoTimer\n", peerName.c_str());

    // return Channels to Searching state
    for(auto& wchan : pending) {
        auto chan = wchan.lock();
        if(!chan)
            continue;

        chan->disconnect(chan);
    }
    for(auto& pair : chanBySID) {
        auto chan = pair.second.lock();
        if(!chan)
            continue;

        chan->disconnect(chan);
    }
    for(auto& pair : creatingByCID) {
        auto chan = pair.second.lock();
        if(!chan)
            continue;

        chan->disconnect(chan);
    }

    auto ops = std::move(opByIOID);
    for (auto& pair : ops) {
        auto op = pair.second.handle.lock();
        if(!op)
            continue;
        op->chan->opByIOID.erase(op->ioid);
        op->disconnected(op);
    }

    // paranoia
    pending.clear();
    chanBySID.clear();
}

void Connection::handle_CONNECTION_VALIDATION()
{
    log_debug_printf(io, "Server %s begins validation handshake\n", peerName.c_str());

    EvInBuf M(peerBE, segBuf.get(), 16);

    // unused
    //   serverReceiveBufferSize
    //   serverIntrospectionRegistryMaxSize
    M.skip(4u + 2u);

    Size nauth{};
    from_wire(M, nauth);

    std::string selected;

    for(auto n : range(nauth.size)) {
        (void)n;

        std::string method;
        from_wire(M, method);

        if(method=="ca" || (method=="anonymous" && selected!="ca"))
            selected = method;
    }

    if(!M.good()) {
        log_err_printf(io, "Server %s sends invalid CONNECTION_VALIDATION.  Disconnect...\n", peerName.c_str());
        bev.reset();
        return;
    }

    if(!selected.empty()) {
        log_debug_printf(io, "Server %s selecting auth '%s'\n", peerName.c_str(), selected.c_str());

    } else {
        selected = "anonymous";
        log_warn_printf(io, "Server %s no supported auth.  try to force '%s'\n", peerName.c_str(), selected.c_str());
    }

    MValue cred;
    if(selected=="ca") {
        cred = context->caMethod.cloneEmpty();

        std::vector<char> buffer(256u);

        if(osiGetUserName(&buffer[0], buffer.size()) == osiGetUserNameSuccess) {
            buffer[buffer.size()-1] = '\0';
            cred["user"] = buffer.data();
        } else {
            cred["user"] = "nobody";
        }

        if (gethostname(&buffer[0], buffer.size()) == 0) {
            buffer[buffer.size()-1] = '\0';
            cred["host"] = buffer.data();
        } else {
            cred["host"] = "invalidhost.";
        }

        log_info_printf(io, "Server %s 'ca' auth as %s@%s\n", peerName.c_str(),
                        cred["user"].as<std::string>().c_str(),
                        cred["host"].as<std::string>().c_str());
    }

    {
        (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

        EvOutBuf R(hostBE, txBody.get());

        // serverReceiveBufferSize, not used
        to_wire(R, uint32_t(0x10000));
        // serverIntrospectionRegistryMaxSize, also not used
        to_wire(R, uint16_t(0x7fff));
        // QoS, not used (quality?)
        to_wire(R, uint16_t(0));

        to_wire(R, selected);

        to_wire(R, ValueBase::Helper::desc(cred));
        if(cred)
            to_wire_full(R, cred.freeze());
    }
    enqueueTxBody(CMD_CONNECTION_VALIDATION);
}

void Connection::handle_CONNECTION_VALIDATED()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    Status sts{};
    from_wire(M, sts);

    if(!M.good()) {
        log_crit_printf(io, "Server %s sends invalid CONNECTION_VALIDATED.  Disconnecting...\n", peerName.c_str());
        bev.reset();
        return;

    } else if(!sts.isSuccess()) {
        log_err_printf(io, "Server %s refuses auth.  Trying to proceed w/o cred\n", peerName.c_str());

    } else {
        log_debug_printf(io, "Server %s accepts auth%s%s\n", peerName.c_str(),
                         sts.msg.empty() ? "" : " ", sts.msg.c_str());
    }

    ready = true;

    createChannels();
}

void Connection::handle_CREATE_CHANNEL()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t cid, sid;
    Status sts{};

    from_wire(M, cid);
    from_wire(M, sid);
    from_wire(M, sts);
    // "spec" calls for uint16_t Access Rights here, but pvAccessCPP don't include this (it's useless anyway)

    if(!M.good()) {
        log_crit_printf(io, "Server %s sends invalid CREATE_CHANNEL.  Disconnecting...\n", peerName.c_str());
        bev.reset();
        return;
    }

    std::shared_ptr<Channel> chan;
    {
        auto it = creatingByCID.find(cid);
        if(it==creatingByCID.end() || !(chan = it->second.lock())) {

            if(it!=creatingByCID.end())
                creatingByCID.erase(it);

            if(sts.isSuccess()) {
                // we now have a channel which is no longer interesting.
                log_debug_printf(io, "Server %s disposing of newly stale channel\n", peerName.c_str());

                {
                    (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

                    EvOutBuf R(hostBE, txBody.get());
                    to_wire(R, sid);
                    to_wire(R, cid);
                }
                enqueueTxBody(CMD_DESTROY_CHANNEL);
            }
            return;
        }
        creatingByCID.erase(it);
    }

    if(!sts.isSuccess()) {
        // server refuses to create a channel, but presumably responded positivly to search

        chan->state = Channel::Searching;
        context->searchBuckets[context->currentBucket].push_back(chan);

        log_warn_printf(io, "Server %s refuses channel to '%s' : %s\n", peerName.c_str(),
                        chan->name.c_str(), sts.msg.c_str());

    } else {
        chan->state = Channel::Active;
        chan->sid = sid;

        chanBySID[sid] = chan;

        log_debug_printf(io, "Server %s active channel to '%s' %u:%u\n", peerName.c_str(),
                         chan->name.c_str(), unsigned(chan->cid), unsigned(chan->sid));

        chan->createOperations();
    }
}

void Connection::handle_DESTROY_CHANNEL()
{
    // (maybe) keep myself alive
    std::shared_ptr<Connection> self;

    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t cid, sid;
    from_wire(M, sid);
    from_wire(M, cid);

    if(!M.good()) {
        log_crit_printf(io, "Server %s sends invalid DESTROY_CHANNEL.  Disconnecting...\n", peerName.c_str());
        bev.reset();
        return;
    }

    std::shared_ptr<Channel> chan;
    {
        auto it = chanBySID.find(sid);
        if(it==chanBySID.end() || !(chan = it->second.lock())) {
            log_debug_printf(io, "Server %s destroys non-existant channel %u:%u\n",
                             peerName.c_str(), unsigned(cid), unsigned(sid));
            return;
        }
    }

    chanBySID.erase(sid);

    chan->state = Channel::Searching;
    chan->sid = 0xdeadbeef; // spoil
    self = std::move(chan->conn);
    context->searchBuckets[context->currentBucket].push_back(chan);

    for(auto& pair : chan->opByIOID) {
        auto op = pair.second->handle.lock();
        opByIOID.erase(pair.first); // invalidates pair.second
        op->disconnected(op);
    }

    log_debug_printf(io, "Server %s destroys channel '%s' %u:%u\n",
                     peerName.c_str(), chan->name.c_str(), unsigned(cid), unsigned(sid));
}

void Connection::tickEcho()
{
    log_debug_printf(io, "Server %s ping\n", peerName.c_str());

    if(!bev)
        return;

    auto tx = bufferevent_get_output(bev.get());

    to_evbuf(tx, Header{CMD_ECHO, 0u, 0u}, hostBE);

    // maybe help reduce latency
    bufferevent_flush(bev.get(), EV_WRITE, BEV_FLUSH);
}

void Connection::tickEchoS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Connection*>(raw)->tickEcho();
    }catch(std::exception& e){
        log_crit_printf(io, "Unhandled error in echo timer callback: %s\n", e.what());
    }
}

} // namespace client
} // namespace pvxs
