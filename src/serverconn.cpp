/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <limits>
#include <system_error>
#include <utility>

#include <osiSock.h>
#include <epicsGuard.h>
#include <epicsAssert.h>

#include <pvxs/log.h>
#include "serverconn.h"

// Amount of following messages which we allow to be read while
// processing the current message.  Avoids some extra recv() calls,
// at the price of maybe extra copying.
static const size_t tcp_readahead = 0x1000;

namespace pvxs {namespace impl {

// message related to client state and errors
DEFINE_LOGGER(connsetup, "tcp.setup");
// related to low level send/recv
DEFINE_LOGGER(connio, "tcp.io");

DEFINE_LOGGER(remote, "tcp.log");

ServerConn::ServerConn(ServIface* iface, evutil_socket_t sock, struct sockaddr *peer, int socklen)
    :iface(iface)
    ,peerAddr(peer, socklen)
    ,peerName(peerAddr.tostring())
    ,bev(bufferevent_socket_new(iface->server->acceptor_loop.base, sock, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS))
    ,peerBE(true) // arbitrary choice, default should be overwritten before use
    ,expectSeg(false)
    ,segCmd(0xff)
    ,segBuf(evbuffer_new())
    ,txBody(evbuffer_new())
    ,nextSID(0)
{
    log_printf(connio, PLVL_DEBUG, "Client %s connects\n", peerName.c_str());

    bufferevent_setcb(bev.get(), &bevReadS, &bevWriteS, &bevEventS, this);
    // initially wait for at least a header
    bufferevent_setwatermark(bev.get(), EV_READ, 8, tcp_readahead);

    timeval timo = {30, 0};
    bufferevent_set_timeouts(bev.get(), &timo, &timo);

    auto tx = bufferevent_get_output(bev.get());

    std::vector<uint8_t> buf(128);

    // queue connection validation message
    {
        uint8_t flags = hostBE ? pva_flags::MSB : 0;
        flags |= pva_flags::Server;

        VectorOutBuf M(hostBE, buf);
        to_wire(M, Header{pva_ctrl_msg::SetEndian, pva_flags::Control|pva_flags::Server, 0});

        auto save = M.save();
        M.skip(8); // placeholder for header
        auto bstart = M.save();

        // serverReceiveBufferSize, not used
        to_wire(M, uint32_t(0x10000));
        // serverIntrospectionRegistryMaxSize, also not used
        to_wire(M, uint16_t(0x7fff));
        to_wire(M, Size{2});
        to_wire(M, "anonymous");
        to_wire(M, "ca");
        auto bend = M.save();

        FixedBuf H(hostBE, save, 8);
        to_wire(H, Header{CMD_CONNECTION_VALIDATION, pva_flags::Server, uint32_t(bend-bstart)});

        assert(M.good() && H.good());

        if(evbuffer_add(tx, buf.data(), M.save()-buf.data()))
            throw std::bad_alloc();
    }

    if(bufferevent_enable(bev.get(), EV_READ|EV_WRITE))
        throw std::logic_error("Unable to enable BEV");
}

ServerConn::~ServerConn()
{}

const std::shared_ptr<ServerChan>& ServerConn::lookupSID(uint32_t sid)
{
    auto it = chanBySID.find(sid);
    if(it==chanBySID.end())
        throw std::runtime_error(SB()<<"Client "<<peerName<<" non-existant SID "<<sid);
    return it->second;
}

void ServerConn::enqueueTxBody(pva_app_msg_t cmd)
{
    auto tx = bufferevent_get_output(bev.get());
    to_evbuf(tx, Header{cmd,
                        pva_flags::Server,
                        uint32_t(evbuffer_get_length(txBody.get()))},
             hostBE);
    auto err = evbuffer_add_buffer(tx, txBody.get());
    assert(!err);
}

void ServerConn::handle_ECHO()
{
    // Client requests echo as a keep-alive check

    auto tx = bufferevent_get_output(bev.get());
    uint32_t len = evbuffer_get_length(segBuf.get());

    to_evbuf(tx, Header{CMD_ECHO, pva_flags::Server, len}, hostBE);

    auto err = evbuffer_add_buffer(tx, segBuf.get());
    assert(!err);

    // maybe help reduce latency
    bufferevent_flush(bev.get(), EV_WRITE, BEV_FLUSH);
}

static
void auth_complete(ServerConn *self, const Status& sts)
{
    (void)evbuffer_drain(self->txBody.get(), evbuffer_get_length(self->txBody.get()));

    {
        EvOutBuf M(hostBE, self->txBody.get());
        to_wire(M, sts);
    }

    self->enqueueTxBody(CMD_CONNECTION_VALIDATED);

    log_printf(connsetup, PLVL_DEBUG, "%s Auth complete with %d\n", self->peerName.c_str(), sts.code);
}

void ServerConn::handle_CONNECTION_VALIDATION()
{
    // Client begins (restarts?) Auth handshake

    EvInBuf M(peerBE, segBuf.get(), 16);

    std::string selected;
    {
        M.skip(6); // ignore unused buffer and introspection size
        uint16_t qos;
        from_wire(M, qos);
        from_wire(M, selected);

        Value auth;
        from_wire_type_value(M, rxRegistry, auth);
        // TODO store credentials

        if(!M.good()) {
            log_printf(connio, PLVL_ERR, "Client %s Truncated/Invalid ConnValid from client\n", peerName.c_str());
            bev.reset();
            return;

        } else {
            log_printf(connsetup, PLVL_DEBUG, "Client %s authenticates using %s and %s\n",
                       peerName.c_str(), selected.c_str(),
                       std::string(SB()<<auth).c_str());
        }
    }

    if(selected!="ca" && selected!="anonymous") {
        log_printf(connsetup, PLVL_DEBUG, "Client %s selects unadvertised auth \"%s\"", peerName.c_str(), selected.c_str());
        auth_complete(this, Status{Status::Error, "Client selects unadvertised auth"});
        return;

    } else {
        log_printf(connsetup, PLVL_DEBUG, "Client %s selects auth \"%s\"", peerName.c_str(), selected.c_str());
    }

    // remainder of segBuf is payload w/ credentials

    // TODO actually check credentials
    auth_complete(this, Status{Status::Ok});
}

void ServerConn::handle_AUTHNZ()
{
    // ignored (so far no auth plugin actually uses)
}

void ServerConn::handle_PUT_GET()
{}

void ServerConn::handle_CANCEL_REQUEST()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid=0, ioid=0;
    from_wire(M, sid);
    from_wire(M, ioid);
    if(!M.good())
        throw std::runtime_error("Error decoding DestroyOp");

    auto it = opByIOID.find(ioid);
    if(it==opByIOID.end()) {
        log_printf(connsetup, PLVL_WARN, "Client %s Cancel of non-existant Op %u\n", peerName.c_str(), unsigned(ioid));
        return;
    }

    const auto& op = it->second;
    auto chan = op->chan.lock();
    if(!chan || chan->sid!=sid) {
        log_printf(connsetup, PLVL_ERR, "Client %s Cancel inconsistent Op\n", peerName.c_str());
        return;
    }

    if(op->state==ServerOp::Executing) {
        op->state = ServerOp::Idle;

        if(op->onCancel)
            op->onCancel();

    } else {
        // an allowed race
        log_printf(connsetup, PLVL_DEBUG, "Client %s Cancel of non-executing Op\n", peerName.c_str());
    }
}

void ServerConn::handle_DESTROY_REQUEST()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid=0, ioid=0;
    from_wire(M, sid);
    from_wire(M, ioid);
    if(!M.good())
        throw std::runtime_error("Error decoding DestroyOp");

    auto& chan = lookupSID(sid);

    auto it = opByIOID.find(ioid);
    auto n = chan->opByIOID.erase(ioid);

    if(it==opByIOID.end() || n!=1) {
        log_printf(connsetup, PLVL_WARN, "Client %s can't destroy non-existant op %u:%u\n",
                   peerName.c_str(), unsigned(sid), unsigned(ioid));

    } else {
        auto op = it->second;
        opByIOID.erase(it);
        op->state = ServerOp::Dead;

        if(op->onClose)
            op->onClose("");
    }
}

void ServerConn::handle_MESSAGE()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t ioid = 0;
    uint8_t mtype = 0;
    std::string msg;

    from_wire(M, ioid);
    from_wire(M, mtype);
    from_wire(M, msg);

    if(!M.good())
        throw std::runtime_error("Decode error for Message");

    auto it = opByIOID.find(ioid);
    if(it==opByIOID.end()) {
        log_printf(connsetup, PLVL_DEBUG, "Client %s Message on non-existant ioid\n", peerName.c_str());
        return;
    }
    auto chan = it->second->chan.lock();

    switch(mtype) {
    case 0: mtype = PLVL_INFO;
    case 1: mtype = PLVL_WARN;
    case 2: mtype = PLVL_ERR;
    default:mtype = PLVL_CRIT;
    }

    log_printf(remote, mtype, "Client %s Channel %s Remote message: %s\n",
               peerName.c_str(), chan ? "<dead>" : chan->name.c_str(),
               msg.c_str());
}


void ServerConn::cleanup()
{
    log_printf(connsetup, PLVL_DEBUG, "Client %s Cleanup TCP Connection\n", peerName.c_str());

    auto it = iface->server->connections.find(this);
    if(it!=iface->server->connections.end()) {
        auto self = std::move(it->second);
        iface->server->connections.erase(it);

        // delete this
    }
}

void ServerConn::bevEvent(short events)
{
    if(events&(BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
        if(events&BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            const char *msg = evutil_socket_error_to_string(err);
            log_printf(connio, PLVL_ERR, "Client %s connection closed with socket error %d : %s\n", peerName.c_str(), err, msg);
        }
        if(events&BEV_EVENT_EOF) {
            log_printf(connio, PLVL_DEBUG, "Client %s connection closed by peer\n", peerName.c_str());
        }
        if(events&BEV_EVENT_TIMEOUT) {
            log_printf(connio, PLVL_WARN, "Client %s connection timeout\n", peerName.c_str());
        }
        bev.reset();
    }

    if(!bev)
        cleanup();
}

void ServerConn::bevRead()
{
    auto rx = bufferevent_get_input(bev.get());

    while(bev && evbuffer_get_length(rx)>=8) {
        uint8_t header[8];

        auto ret = evbuffer_copyout(rx, header, sizeof(header));
        assert(ret==sizeof(header)); // previously verified

        if(header[0]!=0xca || header[1]==0 || (header[2]&pva_flags::Server)) {
            log_hex_printf(connio, PLVL_ERR, header, sizeof(header), "Client %s Protocol decode fault.  Force disconnect.\n", peerName.c_str());
            bev.reset();
            break;
        }
        log_hex_printf(connio, PLVL_DEBUG, header, sizeof(header), "Client %s Receive header\n", peerName.c_str());

        if(header[2]&pva_flags::Control) {
            // Control messages are not actually useful
            evbuffer_drain(rx, 8);
            continue;
        }
        // application message

        peerBE = header[2]&pva_flags::MSB;

        // a bit verbose :P
        FixedBuf L(peerBE, header+4, 4);
        uint32_t len = 0;
        from_wire(L, len);
        assert(L.good());

        if(evbuffer_get_length(rx)-8 < len) {
            // wait for complete payload
            // and some additional if available
            size_t readahead = len;
            if(readahead < std::numeric_limits<size_t>::max()-tcp_readahead)
                readahead += tcp_readahead;
            bufferevent_setwatermark(bev.get(), EV_READ, len, readahead);
            break;
        }

        evbuffer_drain(rx, 8);
        {
            unsigned n = evbuffer_remove_buffer(rx, segBuf.get(), len);
            assert(n==len); // we know rx buf contains the entire body
        }

        // so far we do not use segmentation to support incremental processing
        // of long messages.  We instead accumulate all segments of a message
        // prior to parsing.

        auto seg = header[2]&pva_flags::SegMask;

        bool continuation = seg&pva_flags::SegLast; // true for mid or last.  false for none for first
        if((continuation ^ expectSeg) || (continuation && header[3]!=segCmd)) {
            log_printf(connio, PLVL_CRIT, "Client %s Peer segmentation violation %c%c 0x%02x==0x%02x\n", peerName.c_str(),
                       expectSeg?'Y':'N', continuation?'Y':'N',
                       segCmd, header[3]);
            bev.reset();
            break;
        }

        if(!seg || seg==pva_flags::SegFirst) {
            expectSeg = true;
            segCmd = header[3];
        }

        if(!seg || seg==pva_flags::SegLast) {
            expectSeg = false;

            // ready to process segBuf
            switch(segCmd) {
            default:
                log_printf(connio, PLVL_DEBUG, "Client %s Ignore unexpected command 0x%02x\n", peerName.c_str(), segCmd);
                evbuffer_drain(segBuf.get(), evbuffer_get_length(segBuf.get()));
                break;
#define CASE(OP) case CMD_##OP: handle_##OP(); break
                CASE(ECHO);
                CASE(CONNECTION_VALIDATION);
                CASE(SEARCH);
                CASE(AUTHNZ);

                CASE(CREATE_CHANNEL);
                CASE(DESTROY_CHANNEL);

                CASE(GET);
                CASE(PUT);
                CASE(PUT_GET);
                CASE(RPC);
                CASE(CANCEL_REQUEST);
                CASE(DESTROY_REQUEST);
                CASE(GET_FIELD);

                CASE(MESSAGE);
#undef CASE
            }
            // handlers may be cleared bev to force disconnect
            if(!bev)
                break;

            // silently drain any unprocessed body (forward compatibility)
            if(auto n = evbuffer_get_length(segBuf.get()))
                evbuffer_drain(segBuf.get(), n);

            // wait for next header
            bufferevent_setwatermark(bev.get(), EV_READ, 8, tcp_readahead);
        }
    }

    if(!bev) {
        cleanup();

    } else if(auto tx = bufferevent_get_output(bev.get())) {
        if(evbuffer_get_length(tx)>=0x100000) {
            // write buffer "full".  stop reading until it drains
            // TODO configure
            (void)bufferevent_disable(bev.get(), EV_READ);
            bufferevent_setwatermark(bev.get(), EV_WRITE, 0x100000/2, 0);
        }
    }
}

void ServerConn::bevWrite()
{
    (void)bufferevent_enable(bev.get(), EV_READ);
    bufferevent_setwatermark(bev.get(), EV_WRITE, 0, 0);
}

void ServerConn::bevEventS(struct bufferevent *bev, short events, void *ptr)
{
    auto conn = static_cast<ServerConn*>(ptr);
    try {
        conn->bevEvent(events);
    }catch(std::exception& e){
        log_printf(connsetup, PLVL_CRIT, "Client %s Unhandled error in bev event callback: %s\n", conn->peerName.c_str(), e.what());
        static_cast<ServerConn*>(ptr)->cleanup();
    }
}

void ServerConn::bevReadS(struct bufferevent *bev, void *ptr)
{
    auto conn = static_cast<ServerConn*>(ptr);
    try {
        conn->bevRead();
    }catch(std::exception& e){
        log_printf(connsetup, PLVL_CRIT, "Client %s Unhandled error in bev read callback: %s\n", conn->peerName.c_str(), e.what());
        static_cast<ServerConn*>(ptr)->cleanup();
    }
}

void ServerConn::bevWriteS(struct bufferevent *bev, void *ptr)
{
    auto conn = static_cast<ServerConn*>(ptr);
    try {
        conn->bevWrite();
    }catch(std::exception& e){
        log_printf(connsetup, PLVL_CRIT, "Client %s Unhandled error in bev write callback: %s\n", conn->peerName.c_str(), e.what());
        static_cast<ServerConn*>(ptr)->cleanup();
    }
}

ServIface::ServIface(const std::string& addr, unsigned short port, server::Server::Pvt *server)
    :server(server)
    ,bind_addr(AF_INET, addr.c_str(), port)
    ,sock(AF_INET, SOCK_STREAM, 0)
{
    server->acceptor_loop.assertInLoop();

    // try to bind to requested port, then fallback to a random port
    while(true) {
        try {
            sock.bind(bind_addr);
        } catch(std::system_error& e) {
            if(e.code().value()==SOCK_EADDRINUSE && bind_addr.port()!=0) {
                bind_addr.setPort(0);
                continue;
            }
            throw;
        }
        break;
    }

    name = bind_addr.tostring();

    const int backlog = 4;
    listener = evlisten(evconnlistener_new(server->acceptor_loop.base, onConnS, this, LEV_OPT_DISABLED, backlog, sock.sock));
}

void ServIface::onConnS(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *peer, int socklen, void *raw)
{
    auto self = static_cast<ServIface*>(raw);
    try {
        if(peer->sa_family!=AF_INET) {
            log_printf(connsetup, PLVL_CRIT, "Interface %s Rejecting !ipv4 client\n", self->name.c_str());
            evutil_closesocket(sock);
            return;
        }
        std::shared_ptr<ServerConn> conn(new ServerConn(self, sock, peer, socklen));
        self->server->connections[conn.get()] = std::move(conn);
    }catch(std::exception& e){
        log_printf(connsetup, PLVL_CRIT, "Interface %s Unhandled error in accept callback: %s\n", self->name.c_str(), e.what());
        evutil_closesocket(sock);
    }
}

ServerOp::~ServerOp() {}

}} // namespace pvxs::impl
