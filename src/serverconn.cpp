/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <limits>
#include <system_error>

#include <osiSock.h>
#include <epicsAssert.h>

#include <pvxs/log.h>
#include "serverconn.h"

// Amount of following messages which we allow to be read while
// processing the current message.  Avoids some extra recv() calls,
// at the price of maybe extra copying.
static const size_t tcp_readahead = 0x1000;

namespace pvxsimpl {

DEFINE_LOGGER(connsetup, "tcp.setup");
DEFINE_LOGGER(connio, "tcp.io");

ServerConn::ServerConn(ServIface* iface, evutil_socket_t sock, struct sockaddr *peer, int socklen)
    :iface(iface)
    ,peerAddr(peer, socklen)
    ,peerName(peerAddr.tostring())
    ,bev(bufferevent_socket_new(iface->server->acceptor_loop.base, sock, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS))
    ,peerBE(true) // arbitrary choice, default should be overwritten before use
    ,expectSeg(false)
    ,segCmd(0xff)
    ,segBuf(evbuffer_new())
{
    bufferevent_setcb(bev.get(), &bevReadS, &bevWriteS, &bevEventS, this);
    // initially wait for at least a header
    bufferevent_setwatermark(bev.get(), EV_READ, 8, tcp_readahead);

    timeval timo = {30, 0};
    bufferevent_set_timeouts(bev.get(), &timo, &timo);

    auto tx = bufferevent_get_output(bev.get());

    std::vector<uint8_t> buf(128);
    const bool be = EPICS_BYTE_ORDER == EPICS_ENDIAN_BIG;

    // queue connection validation message
    {
        uint8_t flags = be ? pva_flags::MSB : 0;
        flags |= pva_flags::Server;

        sbuf<uint8_t> M(buf.data(), buf.size());
        to_wire(M, {0xca, pva_version::server, uint8_t(flags|pva_flags::Control), pva_ctrl_msg::SetEndian}, be);
        to_wire(M, uint32_t(0), be);

        to_wire(M, {0xca, pva_version::server, flags, pva_app_msg::ConnValid}, be);
        auto blen = M.split(4);
        auto bstart = blen.pos;

        // serverReceiveBufferSize, not used
        to_wire(M, uint32_t(0x10000), be);
        // serverIntrospectionRegistryMaxSize, also not used
        to_wire(M, uint16_t(0x7fff), be);
        to_wire(M, Size{2}, be);
        to_wire(M, "anonymous", be);
        to_wire(M, "ca", be);

        to_wire(blen, uint32_t(M.pos-bstart), be);

        assert(!M.err && !blen.err);

        if(evbuffer_add(tx, buf.data(), M.pos-buf.data()))
            throw std::bad_alloc();
    }

    if(bufferevent_enable(bev.get(), EV_READ|EV_WRITE))
        throw std::logic_error("Unable to enable BEV");
}

ServerConn::~ServerConn()
{}


void ServerConn::handle_Echo()
{
    // Client requests echo as a keep-alive check

    auto tx = bufferevent_get_output(bev.get());
    uint32_t len = evbuffer_get_length(segBuf.get());

    const bool be = EPICS_BYTE_ORDER == EPICS_ENDIAN_BIG;
    uint8_t header[8];
    sbuf<uint8_t> M(header, sizeof(header));
    to_wire(M, Header{pva_app_msg::Echo, pva_flags::Server, len}, be);
    assert(!M.err);

    auto err = evbuffer_add(tx, header, sizeof(header));
    err |= evbuffer_add_buffer(tx, segBuf.get());
    assert(!err);

    // maybe help reduce latency
    bufferevent_flush(bev.get(), EV_WRITE, BEV_FLUSH);
}

void ServerConn::handle_ConnValid()
{
    // Client begins/restarts Auth handshake

    // size to extract and process up to auth payload.
    // client may only select from our advertised auth
    // mechanisms.  "anonymous" is the longest.
    uint8_t buf[4+2+2+sizeof("anonymous")];

    const auto n = evbuffer_copyout(segBuf.get(), buf, sizeof(buf));

    sbuf<uint8_t> M(buf, n);

    M += 6; // ignore unused buffer and introspection size
    uint16_t qos;
    from_wire(M, qos, peerBE);
    std::string selected;
    from_wire(M, selected, peerBE);

    (void)evbuffer_drain(segBuf.get(), M.pos-buf);

    if(M.err) {
        log_hex_printf(connio, PLVL_ERR, buf, n, "Truncated/Invalid ConnValid from client");
        bev.reset();
        return;
    } else if(selected!="ca" && selected!="anonymous") {
        log_printf(connio, PLVL_DEBUG, "Client selects unadvertised auth \"%s\"", selected.c_str());
    }

    // remainder of segBuf is payload w/ credentials
}

void ServerConn::handle_AuthZ()
{}

void ServerConn::handle_Search()
{}

void ServerConn::handle_CreateChan()
{}

void ServerConn::handle_DestroyChan()
{}

void ServerConn::handle_GetOp()
{}

void ServerConn::handle_PutOp()
{}

void ServerConn::handle_RPCOp()
{}

void ServerConn::handle_PutGetOp()
{}

void ServerConn::handle_CancelOp()
{}

void ServerConn::handle_DestroyOp()
{}

void ServerConn::handle_Introspect()
{}

void ServerConn::handle_Message()
{}


void ServerConn::cleanup()
{
    // remove myself from connections list
    decltype (iface->connections) trash;
    for (auto it = iface->connections.begin(), end = iface->connections.end(); it!=end; ++it) {
        if((&*it)==this) {
            trash.splice(it, iface->connections);
            break;
        }
    }
    assert(!trash.empty());
}

void ServerConn::bevEvent(short events)
{
    if(events&(BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
        if(events&BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            const char *msg = evutil_socket_error_to_string(err);
            log_printf(connio, PLVL_ERR, "Server connection closed with socket error %d : %s\n", err, msg);
        }
        if(events&BEV_EVENT_EOF) {
            log_printf(connio, PLVL_DEBUG, "Server connection closed by peer\n");
        }
        if(events&BEV_EVENT_TIMEOUT) {
            log_printf(connio, PLVL_WARN, "Server connection timeout\n");
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

        if(header[0]!=0xca || header[1]==0 || !(header[2]&pva_flags::Server)) {
            log_hex_printf(connio, PLVL_ERR, header, sizeof(header), "Protocol decode fault.  Force disconnect.\n");
            bev.reset();
            break;
        }

        if(header[2]&pva_flags::Control) {
            switch (header[3]) {
            case pva_ctrl_msg::SetEndian:
                // while we don't enforce.  This should be the very first message sent.
                peerBE = header[2]&pva_flags::MSB;
                break;
            default:
                // Set/AckMarker never used
                break;
            }
            evbuffer_drain(rx, 8);
            continue;

        }
        // application message

        const bool be = header[2]&pva_flags::MSB;
        if(be!=peerBE) {
            // wonderful PVA is redundant in communicating peer byte order.
            // Which is included in every header _and_ the special SetEndian control message.
            // While they really should be consistent, the original impl. only uses SetEndian
            log_printf(connio, PLVL_CRIT, "Peer messages with inconsistent endian\n");
        }

        // a bit verbose :P
        sbuf<uint8_t> L(&header[4], 4);
        uint32_t len = 0;
        from_wire(L, len, peerBE);
        assert(!L.err);

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
            log_printf(connio, PLVL_CRIT, "Peer segmentation violation %c%c 0x%02x==0x%02x\n",
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
                log_printf(connio, PLVL_DEBUG, "Ignore unexpected command 0x%02x\n", segCmd);
                evbuffer_drain(segBuf.get(), evbuffer_get_length(segBuf.get()));
                break;
#define CASE(Op) case pva_app_msg::Op: handle_##Op(); break
                CASE(Echo);
                CASE(ConnValid);
                CASE(Search);
                CASE(AuthZ);

                CASE(CreateChan);
                CASE(DestroyChan);

                CASE(GetOp);
                CASE(PutOp);
                CASE(PutGetOp);
                CASE(RPCOp);
                CASE(CancelOp);
                CASE(DestroyOp);
                CASE(Introspect);

                CASE(Message);
#undef CASE
            }
            // handlers may be cleared bev to force disconnect

            // silently drain any unprocessed body (forward compatibility)
            if(auto n = evbuffer_get_length(segBuf.get()))
                evbuffer_drain(segBuf.get(), n);
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
    try {
        static_cast<ServerConn*>(ptr)->bevEvent(events);
    }catch(std::exception& e){
        log_printf(connio, PLVL_CRIT, "Unhandled error in bev event callback: %s\n", e.what());
        static_cast<ServerConn*>(ptr)->cleanup();
    }
}

void ServerConn::bevReadS(struct bufferevent *bev, void *ptr)
{
    try {
        static_cast<ServerConn*>(ptr)->bevRead();
    }catch(std::exception& e){
        log_printf(connio, PLVL_CRIT, "Unhandled error in bev read callback: %s\n", e.what());
        static_cast<ServerConn*>(ptr)->cleanup();
    }
}

void ServerConn::bevWriteS(struct bufferevent *bev, void *ptr)
{
    try {
        static_cast<ServerConn*>(ptr)->bevWrite();
    }catch(std::exception& e){
        log_printf(connio, PLVL_CRIT, "Unhandled error in bev write callback: %s\n", e.what());
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
    try {
        if(peer->sa_family!=AF_INET) {
            log_printf(connsetup, PLVL_CRIT, "Rejecting !ipv4 client\n");
            evutil_closesocket(sock);
            return;
        }
        auto self = static_cast<ServIface*>(raw);
        self->connections.emplace_back(self, sock, peer, socklen);
    }catch(std::exception& e){
        log_printf(connio, PLVL_CRIT, "Unhandled error in accept callback: %s\n", e.what());
        evutil_closesocket(sock);
    }
}

} // namespace pvxsimpl
