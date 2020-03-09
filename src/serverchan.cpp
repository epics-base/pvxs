/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <cassert>

#include "pvxs/log.h"
#include "serverconn.h"

namespace pvxs {namespace impl {

// message related to client state and errors
DEFINE_LOGGER(connsetup, "pvxs.tcp.setup");
// related to low level send/recv
DEFINE_LOGGER(connio, "pvxs.tcp.io");

DEFINE_LOGGER(serversetup, "pvxs.server.setup");

ServerChan::ServerChan(const std::shared_ptr<ServerConn> &conn,
                       uint32_t sid,
                       uint32_t cid,
                       const std::string &name)
    :conn(conn)
    ,sid(sid)
    ,cid(cid)
    ,name(name)
    ,state(Creating)
{}

ServerChan::~ServerChan() {}

ServerChannelControl::ServerChannelControl(const std::shared_ptr<ServerConn> &conn, const std::shared_ptr<ServerChan>& channel)
    :server(conn->iface->server->internal_self)
    ,chan(channel)
{
    _op = None;
    _name = channel->name;
    _peerName = conn->peerName;
    _ifaceName = conn->iface->name;
}

ServerChannelControl::~ServerChannelControl() {}

void ServerChannelControl::onOp(std::function<void(std::unique_ptr<server::ConnectOp>&&)>&& fn)
{
    auto serv = server.lock();
    if(!serv)
        return;

    serv->acceptor_loop.call([this, &fn](){
        auto ch = chan.lock();
        if(!ch)
            return;

        ch->onOp = std::move(fn);
    });
}

void ServerChannelControl::onRPC(std::function<void(std::unique_ptr<server::ExecOp>&&, Value&&)>&& fn)
{
    auto serv = server.lock();
    if(!serv)
        return;

    serv->acceptor_loop.call([this, &fn](){
        auto ch = chan.lock();
        if(!ch)
            return;

        ch->onRPC = std::move(fn);
    });
}

void ServerChannelControl::onSubscribe(std::function<void(std::unique_ptr<server::MonitorSetupOp>&&)>&& fn)
{
    auto serv = server.lock();
    if(!serv)
        return;

    serv->acceptor_loop.call([this, &fn](){
        auto ch = chan.lock();
        if(!ch)
            return;

        ch->onSubscribe = std::move(fn);
    });
}

void ServerChannelControl::onClose(std::function<void(const std::string&)>&& fn)
{
    auto serv = server.lock();
    if(!serv)
        return;

    serv->acceptor_loop.call([this, &fn](){
        auto ch = chan.lock();
        if(!ch)
            return;

        ch->onClose = std::move(fn);
    });
}

static
void ServerChannel_shutdown(const std::shared_ptr<ServerChan>& chan)
{
    if(chan->state==ServerChan::Destroy)
        return;

    auto conn = chan->conn.lock();
    if(!conn)
        return;

    chan->state = ServerChan::Destroy;

    conn->chanBySID.erase(chan->sid);

    for(auto& pair : chan->opByIOID) {
        auto op = pair.second;
        if(op->state==ServerOp::Dead)
            continue;

        if(op->state==ServerOp::Executing && op->onCancel)
            op->onCancel();

        op->state = ServerOp::Dead;

        if(op->onClose)
            op->onClose("");

        conn->opByIOID.erase(op->ioid);
    }

    chan->opByIOID.clear();
}

void ServerChannelControl::close()
{
    // fail soft if server stopped, or channel/connection already closed
    auto serv = server.lock();
    if(!serv)
        return;

    serv->acceptor_loop.call([this](){
        auto ch = chan.lock();
        if(!ch)
            return;
        auto conn = ch->conn.lock();
        if(conn) {
            if(ch->state==ServerChan::Active) {
                // Send unsolicited Channel Destroy

                auto tx = bufferevent_get_output(conn->bev.get());
                EvOutBuf R(hostBE, tx);
                to_wire(R, Header{CMD_DESTROY_CHANNEL, pva_flags::Server, 8});
                to_wire(R, ch->sid);
                to_wire(R, ch->cid);

                ServerChannel_shutdown(ch);
            }
            ch->state = ServerChan::Destroy;
        }
    });
}

std::pair<std::string, Value> ServerChannelControl::rawCredentials() const
{
    std::pair<std::string, Value> ret;
    auto serv = server.lock();
    if(serv)
        serv->acceptor_loop.call([this, &ret](){
            if(auto chan = this->chan.lock())
                if(auto conn = chan->conn.lock())
                    ret = std::make_pair(conn->autoMethod, conn->credentials.clone());
        });
    return ret;
}

void ServerConn::handle_SEARCH()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t searchID=0;
    uint8_t flags=0;

    from_wire(M, searchID);
    from_wire(M, flags);
    bool mustReply = flags&pva_search_flags::MustReply;
    M.skip(3 + 16 + 2); // unused and replyAddr (we always and only reply to TCP peer)

    bool foundtcp = false;
    Size nproto{0};
    from_wire(M, nproto);
    for(size_t i=0; i<nproto.size && !foundtcp && M.good(); i++) {
        std::string proto;
        from_wire(M, proto);
        foundtcp |= proto=="tcp";
    }

    uint16_t nchan=0;
    from_wire(M, nchan);

    server::Source::Search op;
    op._src = peerAddr;
    std::vector<std::pair<uint32_t, std::string>> nameStorage(nchan);
    op._names.resize(nchan);

    for(auto n : range(nchan)) {
        from_wire(M, nameStorage[n].first);
        from_wire(M, nameStorage[n].second);
        op._names[n]._name = nameStorage[n].second.c_str();
    }

    if(!M.good())
        throw std::runtime_error("TCP Search decode error");

    {
        auto G(iface->server->sourcesLock.lockReader());
        for(const auto& pair : iface->server->sources) {
            try {
                pair.second->onSearch(op);
            }catch(std::exception& e){
                log_err_printf(serversetup, "Unhandled error in Source::onSearch for '%s' : %s\n",
                           pair.first.second.c_str(), e.what());
            }
        }
    }

    uint16_t nreply = 0;
    for(const auto& name : op._names) {
        if(name._claim)
            nreply++;
    }

    if(nreply==0 && !mustReply)
        return;

    {
        (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

        EvOutBuf R(hostBE, txBody.get());

        to_wire(M, searchID);
        to_wire(M, iface->bind_addr);
        to_wire(M, iface->bind_addr.port());
        to_wire(M, "tcp");
        // "found" flag
        to_wire(M, uint8_t(nreply!=0 ? 1 : 0));

        to_wire(M, uint16_t(nreply));
        for(auto i : range(op._names.size())) {
            if(op._names[i]._claim)
                to_wire(M, uint32_t(nameStorage[i].first));
        }
    }

    enqueueTxBody(CMD_SEARCH_RESPONSE);
}

void ServerConn::handle_CREATE_CHANNEL()
{
    const auto self = shared_from_this();

    EvInBuf M(peerBE, segBuf.get(), 16);

    auto G(iface->server->sourcesLock.lockReader());

    // one channel create request contains main channel names.
    // each of which will received a seperate reply.

    uint16_t count = 0;
    from_wire(M, count);
    for(auto i : range(count)) {
        (void)i;
        uint32_t cid = -1, sid = -1;
        std::string name;
        from_wire(M, cid);
        from_wire(M, name);

        if(!M.good() || name.empty())
            break;

        Status sts{Status::Ok};

        bool claimed = false;

        if(chanBySID.size()==0xffffffff) {
            sts.code = Status::Error;
            sts.msg = "Too many Server channels";
            sts.trace = "pvx:serv:chanidoverflow:";

        } else {
            do {
                sid = nextSID++;
            } while(chanBySID.find(sid)!=chanBySID.end());

            auto chan(std::make_shared<ServerChan>(self, sid, cid, name));
            std::unique_ptr<server::ChannelControl> op(new ServerChannelControl(self, chan));

            for(auto& pair : iface->server->sources) {
                try {
                    pair.second->onCreate(std::move(op));
                    if(!op || chan->onOp || chan->onClose || chan->state!=ServerChan::Creating) {
                        claimed = chan->state==ServerChan::Creating;
                        log_debug_printf(connsetup, "Client %s %s channel to %s through %s\n", peerName.c_str(),
                                   claimed?"accepted":"rejected", name.c_str(), pair.first.second.c_str());
                        break;
                    }
                }catch(std::exception& e){
                    log_err_printf(connsetup, "Client %s Unhandled error in onCreate %s,%d %s : %s\n", peerName.c_str(),
                               pair.first.second.c_str(), pair.first.first,
                               typeid(&e).name(), e.what());
                }
            }

            if(claimed && chan->state==ServerChan::Creating) {
                chanBySID[sid] = chan;
                chan->state = ServerChan::Active;

            } else {
                sts.code = Status::Fatal;
                sts.msg = "Refused to create Channel";
                sts.trace = "pvx:serv:refusechan:";

                sid = -1;
            }

            // ServerChannelControl destroyed it not saved by claiming Source
        }


        {
            (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

            EvOutBuf R(hostBE, txBody.get());
            to_wire(R, cid);
            to_wire(R, sid);
            to_wire(R, sts);
            // "spec" calls for uint16_t Access Rights here, but pvAccessCPP don't include this (it's useless anyway)
            if(!R.good()) {
                M.fault();
                log_err_printf(connio, "Client %s Encode error in CreateChan\n", peerName.c_str());
                break;
            }
        }

        enqueueTxBody(CMD_CREATE_CHANNEL);
    }

    if(!M.good()) {
        log_err_printf(connio, "Client %s Decode error in CreateChan\n", peerName.c_str());
        bev.reset();
    }
}

void ServerConn::handle_DESTROY_CHANNEL()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid=-1, cid=-1;

    from_wire(M, sid);
    from_wire(M, cid);
    if(!M.good())
        throw std::runtime_error("Decode error in DestroyChan");

    auto it = chanBySID.find(sid);
    if(it==chanBySID.end()) {
        log_debug_printf(connsetup, "Client %s DestroyChan non-existant sid=%d cid=%d\n", peerName.c_str(),
                   unsigned(sid), unsigned(cid));
        return;
    }

    auto chan = it->second;
    if(chan->cid!=cid) {
        log_debug_printf(connsetup, "Client %s provides incorrect CID with DestroyChan sid=%d cid=%d!=%d '%s'\n", peerName.c_str(),
                   unsigned(sid), unsigned(chan->cid), unsigned(cid), chan->name.c_str());
    }

    ServerChannel_shutdown(chan);

    assert(chan.use_count()==1); // we only take transient refs on this thread
    // ServerChannel is delete'd

    {
        auto tx = bufferevent_get_output(bev.get());
        EvOutBuf R(hostBE, tx);
        to_wire(R, Header{CMD_DESTROY_CHANNEL, pva_flags::Server, 8});
        to_wire(R, sid);
        to_wire(R, cid);

        if(!R.good())
            bev.reset();
    }
}

}} // namespace pvxs::impl
