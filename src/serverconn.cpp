/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "serverconn.h"

#include <limits>
#include <system_error>
#include <utility>

#include <osiSock.h>
#include <epicsGuard.h>
#include <epicsAssert.h>

#include <pvxs/log.h>

#ifdef PVXS_ENABLE_OPENSSL
#include "openssl.h"
#endif

// limit on size of TX buffer above which we suspend RX.
// defined as multiple of OS socket TX buffer size
static constexpr size_t tcp_tx_limit_mult = 2u;

namespace pvxs {
namespace impl {
DEFINE_INST_COUNTER(ServerChannelControl);
DEFINE_INST_COUNTER(ServerChan);
DEFINE_INST_COUNTER(ServerConn);
DEFINE_INST_COUNTER(ServerSource);
}

std::set<std::string> PeerCredentials::roles() const
{
    std::set<std::string> ret;
    osdGetRoles(account, ret);
    return ret;
}

std::ostream& operator<<(std::ostream& strm, const PeerCredentials& cred)
{
#ifdef PVXS_ENABLE_OPENSSL
    if(cred.isTLS)
        strm<<"TLS ";
#endif

    strm<<cred.method;
    if(!cred.issuer_id.empty())
        strm<<":"<<cred.issuer_id;
    if(!cred.serial.empty())
        strm<<":"<<cred.serial;
    if(!cred.authority.empty()) {
        strm<<":";
        std::string authority = cred.authority;
        size_t pos = 0;
        while((pos = authority.find('\n', pos)) != std::string::npos) {
            authority.replace(pos, 1, " -> ");
            pos += 4; // Move past the replacement string
        }
        strm<<authority;
    }
    strm<<"/"<<cred.account<<"@"<<cred.peer;
    return strm;
}

namespace server {

DEFINE_INST_COUNTER2(Server::Pvt, ServerPvt);
std::set<std::string> ClientCredentials::roles() const { return PeerCredentials::roles(); };


}} // namespace pvxs::server

namespace pvxs {namespace impl {

// message related to client state and errors
DEFINE_LOGGER(connsetup, "pvxs.tcp.init");
// related to low level send/recv
DEFINE_LOGGER(certs, "pvxs.certs.con");
DEFINE_LOGGER(connio, "pvxs.tcp.io");
DEFINE_LOGGER(remote, "pvxs.remote.log");

#ifdef PVXS_ENABLE_OPENSSL
DEFINE_LOGGER(stapling, "pvxs.stapling");
#endif

ServerConn::ServerConn(ServIface* iface, evutil_socket_t sock, struct sockaddr *peer, int socklen)
  : ConnBase(false,
           iface->isTLS,
           iface->server->effective.sendBE(),
            evbufferevent(__FILE__, __LINE__, bufferevent_socket_new(iface->server->acceptor_loop.base, sock, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS)),
            SockAddr(peer))
    ,iface(iface)
    ,tcp_tx_limit(evsocket::get_buffer_size(sock, true) * tcp_tx_limit_mult)
{
    log_debug_printf(connio, "Client %s connects%s, RX readahead %zu TX limit %zu\n", peerName.c_str(),
                       iface->isTLS ? " TLS" :
                      "", readahead, tcp_tx_limit);
    {
        int opt = 1;
        if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt))<0) {
            auto err(SOCKERRNO);
            log_warn_printf(connio, "Unable to TCP_NODELAY: %d on %d\n", err, sock);
        }
    }

#ifdef PVXS_ENABLE_OPENSSL
    if (iface->isTLS) {
        assert(iface->server->tls_context->ctx);
        const auto ssl(SSL_new(iface->server->tls_context->ctx.get()));
        if (!ssl) throw ossl::SSLError("SSL_new()");

        if (!iface->server->tls_context->stapling_disabled && !iface->server->tls_context->status_check_disabled) {
            try {
                log_debug_printf(stapling, "Server OCSP Stapling: installing callback%s\n", "");
                ossl::configureServerOCSPCallback(iface->server, ssl);  // Staple response
            } catch (certs::OCSPParseException& e) {
                log_debug_printf(stapling, "Server OCSP Stapling: failed to install callback: %s\n", e.what());
            } catch (std::exception& e) {
                log_debug_printf(stapling, "Server OCSP Stapling: failed to install callback: %s\n", e.what());
            }
        }

        const auto rawconn = bev.release();
        // BEV_OPT_CLOSE_ON_FREE will free on error
        evbufferevent tlsconn(__FILE__, __LINE__,
                              bufferevent_openssl_filter_new(iface->server->acceptor_loop.base, rawconn, ssl, BUFFEREVENT_SSL_ACCEPTING,
                                                             BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS));
        bev = std::move(tlsconn);

        // added with libevent 2.2.1-alpha
        //(void)bufferevent_ssl_set_flags(bev.get(), BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
        // deprecated, but not yet removed
        bufferevent_openssl_set_allow_dirty_shutdown(bev.get(), 1);
    }
#endif
    {
        auto cred(std::make_shared<server::ClientCredentials>());
        cred->peer = peerName;
        cred->iface = iface->name;
        // paranoia placeholder prior to handle_CONNECTION_VALIDATION()
        cred->method = cred->account = "anonymous";
        this->cred = std::move(cred);
    }

    // TODO Sends the event to handle the, sets timeout, and
    bufferevent_setcb(bev.get(), &bevReadS, &bevWriteS, &bevEventS, this);

    const timeval tmo(totv(iface->server->effective.tcpTimeout));
    bufferevent_set_timeouts(bev.get(), &tmo, &tmo);

    const auto tx = bufferevent_get_output(bev.get());

    std::vector<uint8_t> buf(128);

    // queue connection validation message
    {
        VectorOutBuf M(sendBE, buf);
        to_wire(M, Header{pva_ctrl_msg::SetEndian, pva_flags::Control|pva_flags::Server, 0});

        const auto save = M.save();
        M.skip(8, __FILE__, __LINE__); // placeholder for header
        const auto bstart = M.save();

        // serverReceiveBufferSize, not used
        to_wire(M, static_cast<uint32_t>(0x10000));
        // serverIntrospectionRegistryMaxSize, also not used
        to_wire(M, static_cast<uint16_t>(0x7fff));

        /* list given in reverse order of priority.
         * Old pvAccess* was missing a "break" when looping,
         * so it took the last known plugin.
         */
        to_wire(M, Size{
#ifdef PVXS_ENABLE_OPENSSL
          iface->isTLS ? 3u :
#endif
          2u});
        to_wire(M, "anonymous");
        to_wire(M, "ca");
#ifdef PVXS_ENABLE_OPENSSL
        if(iface->isTLS)
            to_wire(M, "x509");
#endif
        const auto bend = M.save();

        FixedBuf H(sendBE, save, 8);
        to_wire(H, Header{CMD_CONNECTION_VALIDATION, pva_flags::Server, uint32_t(bend-bstart)});

        assert(M.good() && H.good());

        if(evbuffer_add(tx, buf.data(), M.save()-buf.data()))
            throw BAD_ALLOC();

        statTx += M.save()-buf.data();
    }

    if(bufferevent_enable(bev.get(), EV_READ|EV_WRITE))
        throw std::logic_error("Unable to enable BEV");
}

ServerConn::~ServerConn() = default;

const std::shared_ptr<ServerChan>& ServerConn::lookupSID(uint32_t sid)
{
    auto it = chanBySID.find(sid);
    if(it==chanBySID.end()) {
        static decltype (it->second) empty{};
        return empty;
        //throw std::runtime_error(SB()<<"Client "<<peerName<<" non-existent SID "<<sid);
    }
    return it->second;
}

void ServerConn::handle_ECHO()
{
    log_debug_printf(connsetup, "PVA: %s ==> ECHO\n", peerName.c_str());
    // Client requests echo as a keep-alive check

    auto tx = bufferevent_get_output(bev.get());
    uint32_t len = evbuffer_get_length(segBuf.get());

    to_evbuf(tx, Header{CMD_ECHO, pva_flags::Server, len}, sendBE);

    auto err = evbuffer_add_buffer(tx, segBuf.get());
    assert(!err);

    // maybe help reduce latency
    bufferevent_flush(bev.get(), EV_WRITE, BEV_FLUSH);

    statTx += 8u + len;
}

#ifdef PVXS_ENABLE_OPENSSL
void ServerConn::retryConnectionValidationS(evutil_socket_t fd, short evt, void *raw)
{
    const auto conn = static_cast<ServerConn*>(raw);
    conn->retryConnectionValidation();
}

void ServerConn::retryConnectionValidation()
{
    log_debug_printf(connsetup, "Retrying connection validation for %s\n", peerName.c_str());

    if (has_pending_validation) {
        // Process the stored validation data
        proceedWithConnectionValidation();
    }
}
#endif


static
void auth_complete(ServerConn *self, const Status& sts)
{
    (void)evbuffer_drain(self->txBody.get(), evbuffer_get_length(self->txBody.get()));

    {
        EvOutBuf M(self->sendBE, self->txBody.get());
        to_wire(M, sts);
    }

    self->enqueueTxBody(CMD_CONNECTION_VALIDATED);

    log_debug_printf(connsetup, "%s Auth complete with %d\n", self->peerName.c_str(), sts.code);
}

void ServerConn::handle_CONNECTION_VALIDATION()
{
    log_debug_printf(connio, "PVA: %s ==> CONNECTION_VALIDATION\n", peerName.c_str());
    // Client begins (restarts?) Auth handshake

    EvInBuf M(peerBE, segBuf.get(), 16);

    std::string selected;
    Value auth;

    {
        M.skip(4+2+2, __FILE__, __LINE__); // ignore unused buffer, introspection size, and QoS
        from_wire(M, selected);
        from_wire_type_value(M, rxRegistry, auth);

        if(!M.good()) {
            log_err_printf(connio, "%s:%d Client %s Truncated/Invalid ConnValid from client\n",
                           M.file(), M.line(), peerName.c_str());
            bev.reset();
            return;
        }
    }

#ifdef PVXS_ENABLE_OPENSSL
    // Store validation data for potential retry
    pending_selected = selected;
    pending_auth = auth;
    has_pending_validation = true;
#endif

    log_debug_printf(connsetup, "Client %s authenticates using %s and %s\n",
                     peerName.c_str(), selected.c_str(),
                     std::string(SB()<<auth).c_str());


    auto C(std::make_shared<server::ClientCredentials>(*cred));
#ifdef PVXS_ENABLE_OPENSSL
    C->isTLS = iface->isTLS;
#endif

    if(selected=="ca") {
        auth["user"].as<std::string>([&C, &selected](const std::string& user) {
            const auto pos = user.find_last_of('/');
            if ( pos  == std::string::npos) {
                C->account = user;
            } else {
                C->account = user.substr(pos + 1);
            }
            C->method = selected;
        });
    }
#ifdef PVXS_ENABLE_OPENSSL
    // Don't rely on the selected being "x509" - see Hacker Central
    else if (iface->isTLS && selected == "x509" && bev) {
        const auto ctx = bufferevent_openssl_get_ssl(bev.get());
        assert(ctx);
        ossl::SSLContext::getPeerCredentials(*C, ctx);
    }
#endif

    if(C->method.empty()) {
        C->account = C->method = "anonymous";
    }
    C->raw = auth;

    cred = std::move(C);

    log_debug_printf(connsetup, "Client credentials. account: %s, method: %s, authority: %s\n",
                     cred->account.c_str(), cred->method.c_str(), cred->authority.c_str());

    if(selected!="ca" && selected!="anonymous" && selected!="x509") {
        log_debug_printf(connsetup, "Client %s selects unadvertised auth \"%s\"", peerName.c_str(), selected.c_str());
        auth_complete(this, Status{Status::Error, "Client selects unadvertised auth"});
        return;
    }
    log_debug_printf(connsetup, "selected-%s: Client %s selects auth \"%s\" as \"%s\" on \"%s\" authority\n", selected.c_str(), peerName.c_str(), cred->method.c_str(), cred->account.c_str(), cred->authority.c_str());

    // Proceed with the validation
    proceedWithConnectionValidation();
}

#ifdef PVXS_ENABLE_OPENSSL
/**
 * @brief Peer status callback
 *
 * This function is called when the peer status changes.
 *
 * It will be given a status category indicating whether the peer certificate status is GOOD, BAD, or UNKNOWN.
 *
 * - If the peer certificate status is GOOD, and we're waiting for certificate validity
 *   before proceeding with connection validation, it will proceed with connection validation.
 * - If the peer certificate status is BAD, it will disconnect this client connection.
 */
void ServerConn::peerStatusCallback(certs::cert_status_category_t status_category) {
    if (status_category == certs::GOOD_STATUS) {
        log_debug_printf(certs, "Ready to proceed with connection validation: %s %s\n", state == AwaitingPeerCertValidity ? "Awaiting Peer Cert Validity": "Connecting", peerName.c_str());
        proceedWithConnectionValidation();
    } else if (status_category == certs::BAD_STATUS) {
        log_debug_printf(certs, "Cancel Wait for Connection Validation: BAD CERT STATUS%s\n", "");
        disconnect();
    } else {
        log_debug_printf(certs, "Continue Waiting for Connection Validation: UNKNOWN CERT STATUS%s\n", "");
    }

}
#endif


/**
 * @brief Proceed with connection validation
 *
 * This function is called to proceed with connection validation.
 *
 * - If the peer does not have a certificate, or has a certificate that does not require us to wait for certificate validity,
 *   then we will proceed with connection validation.
 *
 * - If the peer has a certificate that requires us to wait for certificate validity before proceeding with connection validation,
 *   and the peer certificate status is GOOD, then we will proceed with connection validation.
 *
 * - If the peer has a certificate that requires us to wait for certificate validity before proceeding with connection validation,
 *   and the peer certificate status is not GOOD, then we will set the state to AwaitingPeerCertValidity and return.
 */
void ServerConn::proceedWithConnectionValidation()
{
#ifdef PVXS_ENABLE_OPENSSL
    if (iface->isTLS && bev) {
        const auto ctx = bufferevent_openssl_get_ssl(bev.get());
        assert(ctx);

        // Check peer certificate status if required
        // we won't be subscribed if we don't need to check peer status before continuing
        if (peer_status && peer_status->isSubscribed() && !isPeerStatusGood()) {
            log_debug_printf(connsetup, "Wait for Client %s certificate status to become GOOD\n", peerName.c_str());

            state = AwaitingPeerCertValidity;
            return; // Backoff - don't complete validation yet until we get the status were waiting for
        }
        log_debug_printf(connsetup, "Have Client %s certificate status Good\n", peerName.c_str());
    }

    // Clear pending validation data since we're completing
    has_pending_validation = false;
#endif

    // No practical way to handle auth failure.
    // So we accept all credentials but may not grant rights.
    auth_complete(this, Status{Status::Ok});
}

void ServerConn::handle_AUTHNZ()
{
    // ignored (so far no auth plugin actually uses)
    log_debug_printf(connsetup, "PVA: %s ==> AUTHNZ\n", peerName.c_str());
}

void ServerConn::handle_PUT_GET() {
    log_debug_printf(connsetup, "PVA: %s ==> PUT_GET\n", peerName.c_str());
}

void ServerConn::handle_CANCEL_REQUEST()
{
    log_debug_printf(connsetup, "PVA: %s ==> CREATE_CHANNEL\n", peerName.c_str());
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid=0, ioid=0;
    from_wire(M, sid);
    from_wire(M, ioid);
    if(!M.good())
        throw std::runtime_error(SB()<<M.file()<<':'<<M.line()<<" Error decoding DestroyOp");

    auto it = opByIOID.find(ioid);
    if(it==opByIOID.end()) {
        log_warn_printf(connsetup, "Client %s Cancel of non-existent Op %u\n", peerName.c_str(), unsigned(ioid));
        return;
    }

    const auto& op = it->second;
    auto chan = op->chan.lock();
    if(!chan || chan->sid!=sid) {
        log_err_printf(connsetup, "Client %s Cancel inconsistent Op\n", peerName.c_str());
        return;
    }

    if(op->state==ServerOp::Executing) {
        op->state = ServerOp::Idle;

        if(op->onCancel)
            op->onCancel();

    } else {
        // an allowed race
        log_debug_printf(connsetup, "Client %s Cancel of non-executing Op\n", peerName.c_str());
    }
}

void ServerConn::handle_DESTROY_REQUEST()
{
    log_debug_printf(connsetup, "PVA: %s ==> DESTROY_REQUEST\n", peerName.c_str());
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid=0, ioid=0;
    from_wire(M, sid);
    from_wire(M, ioid);
    if(!M.good())
        throw std::runtime_error(SB()<<M.file()<<':'<<M.line()<<" Error decoding DestroyOp");

    auto& chan = lookupSID(sid);
    auto it = opByIOID.find(ioid);

    if(!chan || it==opByIOID.end() || 1!=chan->opByIOID.erase(ioid)) {
        log_debug_printf(connsetup, "Client %s can't destroy non-existent op %u:%u\n",
                   peerName.c_str(), unsigned(sid), unsigned(ioid));

    }

    if(it!=opByIOID.end()) {
        auto op = it->second;
        opByIOID.erase(it);
        op->cleanup();
    }
}

void ServerConn::handle_MESSAGE()
{
    log_debug_printf(connsetup, "PVA: %s ==> MESSAGE\n", peerName.c_str());
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t ioid = 0;
    uint8_t mtype = 0;
    std::string msg;

    from_wire(M, ioid);
    from_wire(M, mtype);
    from_wire(M, msg);

    if(!M.good())
        throw std::runtime_error(SB()<<M.file()<<':'<<M.line()<<" Decode error for Message");

    auto it = opByIOID.find(ioid);
    if(it==opByIOID.end()) {
        log_debug_printf(connsetup, "Client %s Message on non-existent ioid\n", peerName.c_str());
        return;
    }
    auto chan = it->second->chan.lock();

    Level lvl;
    switch(mtype) {
    case 0:  lvl = Level::Info; break;
    case 1:  lvl = Level::Warn; break;
    case 2:  lvl = Level::Err; break;
    default: lvl = Level::Crit; break;
    }

    log_printf(remote, lvl, "%s : %s\n",
               chan ? chan->name.c_str() : "<dead>", msg.c_str());
}

std::shared_ptr<ConnBase> ServerConn::self_from_this()
{
    return shared_from_this();
}

// see also ServerChannel_shutdown()
/* reached from:
 * 1. connection close
 */
void ServerConn::cleanup()
{
    log_debug_printf(connsetup, "Client %s Cleanup TCP Connection\n", peerName.c_str());

    iface->server->connections.erase(this);

    // grab maps before cleanup()s would modify
    auto ops(std::move(opByIOID));
    auto chans(std::move(chanBySID));

    for(auto& op : ops) {
        op.second->cleanup();
    }
    for(auto& pair : chans) {
        pair.second->cleanup();
    }
}

void ServerConn::bevEvent(const short events) {
    ConnBase::bevEvent(events);
}

void ServerConn::bevRead()
{
    ConnBase::bevRead();

    if(bev) {
        auto tx = bufferevent_get_output(bev.get());

        if(evbuffer_get_length(tx)>=tcp_tx_limit) {
            // write buffer "full".  stop reading until it drains
            // TODO configure
            (void)bufferevent_disable(bev.get(), EV_READ);
            bufferevent_setwatermark(bev.get(), EV_WRITE, tcp_tx_limit/2, 0);
            log_debug_printf(connio, "%s suspend READ\n", peerName.c_str());
        }
    }
}

void ServerConn::bevWrite()
{
    log_debug_printf(connio, "%s process backlog\n", peerName.c_str());

    auto tx = bufferevent_get_output(bev.get());
    // handle pending monitors

    while(!backlog.empty() && evbuffer_get_length(tx)<tcp_tx_limit) {
        auto fn = std::move(backlog.front());
        backlog.pop_front();

        fn();
    }

    // TODO configure
    if(evbuffer_get_length(tx)<tcp_tx_limit) {
        (void)bufferevent_enable(bev.get(), EV_READ);
        bufferevent_setwatermark(bev.get(), EV_WRITE, 0, 0);
        log_debug_printf(connio, "%s resume READ\n", peerName.c_str());
    }
}


ServIface::ServIface(const SockAddr &addr, server::Server::Pvt *server, bool fallback, bool isTLS)
    : server(server)
    , isTLS(isTLS)
    , bind_addr(addr)
{
    server->acceptor_loop.assertInLoop();
    const auto orig_port = bind_addr.port();

    sock = evsocket(bind_addr.family(), SOCK_STREAM, 0);

    if(evutil_make_listen_socket_reuseable(sock.sock))
        log_warn_printf(connsetup, "Unable to make socket reusable%s", "\n");

    // try to bind to the requested port, then fallback to a random port
    while(true) {
        try {
            sock.bind(bind_addr);
        } catch(std::system_error& e) {
            if(fallback && e.code().value()==SOCK_EADDRINUSE) {
                log_debug_printf(connsetup, "Address %s in use\n", bind_addr.tostring().c_str());
                bind_addr.setPort(0);
                fallback = false;
                continue;
            }
            log_err_printf(connsetup, "Bind to %s fails%s with %d\n",
                           bind_addr.tostring().c_str(),
                           fallback ? "" : " after fallback",
                           e.code().value());
            throw;
        }
        break;
    }

    name = bind_addr.tostring();

    if(orig_port && bind_addr.port() != orig_port) {
        log_warn_printf(connsetup, "Server unable to bind %s port %u, falling back to %s\n", (isTLS ? "TLS" : "TCP"), orig_port, name.c_str());
    }

    // added in libevent 2.1.1
#ifndef LEV_OPT_DISABLED
#  define LEV_OPT_DISABLED 0
#endif

    constexpr int backlog = 4;
    listener = evlisten(__FILE__, __LINE__,
                        evconnlistener_new(server->acceptor_loop.base, onConnS, this, LEV_OPT_DISABLED|LEV_OPT_CLOSE_ON_EXEC, backlog, sock.sock));

    if(LEV_OPT_DISABLED==0)
        evconnlistener_disable(listener.get());
}

void ServIface::onConnS(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *peer, int socklen, void *raw)
{
    auto self = static_cast<ServIface*>(raw);
    try {
        auto conn(std::make_shared<ServerConn>(self, sock, peer, socklen));
        self->server->connections[conn.get()] = std::move(conn);
    }catch(std::exception& e){
        log_exc_printf(connsetup, "Interface %s Unhandled error in accept callback: %s\n", self->name.c_str(), e.what());
        evutil_closesocket(sock);
    }
}

ServerOp::~ServerOp()
{
    // cleanup() should have happened already (from tcp worker)
    // this check may run from any thread, but at this point it should not matter.
    assert(state==Dead);
}

/* reached from:
 * 1. connection close
 * 2. DESTROY_CHANNEL
 * 3. DESTROY_REQUEST
 * 4. individual op DESTROY
 * 5. local user calls ServerChannelControl::close()
 */
void ServerOp::cleanup()
{
    if(state==Dead)
        return;

    if(state==Executing && onCancel) {
        const auto fn(std::move(onCancel));
        fn();
    }

    state = Dead;

    onCancel = nullptr;
    auto closer(std::move(onClose));
    bool notify = closer.operator bool();

    if(const auto ch = chan.lock()) {
        ch->opByIOID.erase(ioid);

        if(const auto conn = ch->conn.lock()) {
            conn->opByIOID.erase(ioid);

            if(notify) {
                conn->iface->server->acceptor_loop.dispatch([closer](){
                    closer("");
                });
                notify = false;
            }
        }
    }

    if(notify)
        closer("");
}

}} // namespace pvxs::impl
