/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiProcess.h>

#include <pvxs/log.h>

#ifdef PVXS_ENABLE_OPENSSL
#include "certstatusmanager.h"
#endif

#include "clientimpl.h"

namespace pvxs {

#ifdef PVXS_ENABLE_OPENSSL
namespace {
DEFINE_LOGGER(stapling, "pvxs.stapling");

/**
 * @brief A callback function for handling OCSP (Online Certificate Status Protocol) responses in an SSL context.
 *
 * This function is intended to be used as a client-side callback for validating the status of certificates using OCSP.
 * Every valid tls_context has an ex_data attached that contains a list of peer statuses keyed off peer cert serial numbers
 * This function will look at the peer certificate that the callback is there to verify and will use this to index
 * into the list to pull up the current status.  It will update the status if the OCSP data in the callback is
 * valid.
 *
 * This means that the status won't need to be verified later as it will have already been retrieved - saving a round trip.
 * These statuses are used later to transition the Connecting state to TlsReady so that a tls connection can be established
 *
 * @param ctx A pointer to the SSL context where the callback is set.
 *
 * @return Typically returns an integer value indicating the SSL_TLSEXT_ERR_OK, SSL_TLSEXT_ERR_ALERT_WARNING,
 * or SSL_TLSEXT_ERR_ALERT_FATAL of the OCSP validation.
 */
int clientOCSPCallback(SSL* ctx, ossl::SSLContext*) {
    log_debug_printf(stapling, "Client OCSP Stapling: %s\n", "clientOCSPCallback");
    // Find out what the peer cert we're verifying is
    X509* peer_cert = SSL_get_peer_certificate(ctx);

    // Get the ex_data from the tls context, return if no peer-statuses to set
    const auto ex_data = ossl::CertStatusExData::fromSSL(ctx);
    if (!ex_data || !ex_data->trusted_store_ptr) {
        log_debug_printf(stapling, "OCSP callback called without establishing root of trust%s\n", "");
        return PVXS_OCSP_STAPLING_ERR;
    }

    try {
        // Try to get the stapled OCSP response
        uint8_t* ocsp_response_ptr;
        const auto len = SSL_get_tlsext_status_ocsp_resp(ctx, &ocsp_response_ptr);

        // If no response received even though we've requested it, then just ignore this callback
        if (!ocsp_response_ptr || len < 0) {
            log_debug_printf(stapling, "No Stapled OCSP response found by %s\n", "client");
            return PVXS_OCSP_STAPLING_OK;
        }

        // Replace cached peer cert with received OCSP response.  Throws if parsing error and catch sets invalid status
        try {
            auto parsed_status = certs::CertStatusManager::parse(ocsp_response_ptr, (size_t)len, ex_data->trusted_store_ptr);
            const auto status = parsed_status.status();

            ex_data->setPeerStatus(peer_cert, status);
            log_debug_printf(stapling, "Client OCSP stapled response is: %s\n", parsed_status.ocsp_status.s.c_str());
            log_debug_printf(stapling, "Client OCSP stapled status date: %s\n", parsed_status.status_date.s.c_str());
            log_debug_printf(stapling, "Client OCSP stapled status valid until: %s\n", parsed_status.status_valid_until_date.s.c_str());
            log_debug_printf(stapling, "Client OCSP stapled revocation date: %s\n", parsed_status.revocation_date.s.c_str());
            return PVXS_OCSP_STAPLING_OK;
        } catch (const certs::OCSPParseException& e) {
            log_warn_printf(stapling, "Stapled OCSP response invalid: %s\n", e.what());
            return PVXS_OCSP_STAPLING_NAK;
        }
    } catch (std::exception& e) {
        ex_data->setPeerStatus(peer_cert, certs::UnknownCertificateStatus());
        log_err_printf(stapling, "Stapled OCSP response: %s\n", e.what());
    }
    return PVXS_OCSP_STAPLING_ERR;
}

}  // namespace
#endif

namespace client {

DEFINE_LOGGER(io, "pvxs.cli.io");
DEFINE_LOGGER(connsetup, "pvxs.tcp.init");
DEFINE_LOGGER(certs, "pvxs.certs.con");
DEFINE_LOGGER(remote, "pvxs.remote.log");
DEFINE_LOGGER(status_cli, "pvxs.st.cli");

Connection::Connection(const std::shared_ptr<ContextImpl>& context,
                       const SockAddr& peerAddr,
                       bool reconn,
                       bool isTLS )
    : ConnBase (true, isTLS, context->effective.sendBE(), nullptr, peerAddr)
    , context(context)
    , echoTimer(__FILE__, __LINE__,
               event_new(context->tcp_loop.base, -1, EV_TIMEOUT|EV_PERSIST, &tickEchoS, this))
{
    if(reconn) {
        log_debug_printf(io, "start holdoff timer for %s\n", peerName.c_str());

        constexpr timeval holdoff{2, 0};
        if(event_add(echoTimer.get(), &holdoff))
            log_err_printf(io, "Server %s error starting echoTimer as holdoff\n", peerName.c_str());

    } else {
        startConnecting();
    }
}

Connection::~Connection()
{
    log_debug_printf(io, "Cleaning connection to %s\n", peerName.c_str());
    cleanup();
}

std::shared_ptr<Connection> Connection::build(const std::shared_ptr<ContextImpl>& context,
                                              const SockAddr& serv, bool reconn, bool tls)
{
    if(!context->isRunning())
        throw std::logic_error("Context close()d");

    auto pair(std::make_pair(serv, tls));
    std::shared_ptr<Connection> ret;
    auto it = context->connByAddr.find(pair);
    if(it==context->connByAddr.end() || !(ret = it->second.lock())) {
        context->connByAddr[pair] = ret = std::make_shared<Connection>(context, serv, reconn, tls);
    }
    return ret;
}

void Connection::startConnecting() {
    assert(!this->bev);

    evsocket sock(peerAddr.family(), SOCK_STREAM, 0);
    decltype(this->bev) bev(__FILE__, __LINE__,
                bufferevent_socket_new(context->tcp_loop.base, -1,
                                       BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS));
#ifdef PVXS_ENABLE_OPENSSL
    if(isTLS) {
        if (!context || !context->isTlsConfigured()) {
            log_debug_printf(connsetup, "Client context not ready for TLS connection%s\n", "");
            return;
        }

        auto ctx(SSL_new(context->tls_context->ctx.get()));
        if(!ctx)
            throw ossl::SSLError("SSL_new");

        // w/ BEV_OPT_CLOSE_ON_FREE calls SSL_free() on error
        bev.reset(bufferevent_openssl_socket_new(context->tcp_loop.base,
                                                 -1,
                                                 ctx,
                                                 BUFFEREVENT_SSL_CONNECTING,
                                                 BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS));

        // added with libevent 2.2.1-alpha
        //(void)bufferevent_ssl_set_flags(bev.get(), BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
        // deprecated, but not yet removed
        bufferevent_openssl_set_allow_dirty_shutdown(bev.get(), 1);

        // Configure client OCSP callback if appropriate and required
        configureClientOCSPCallback(ctx);
    } else
#endif
    {
        bev.reset(bufferevent_socket_new(context->tcp_loop.base,
                                         -1,
                                         BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS));
    }

    bufferevent_setcb(bev.get(), &bevReadS, nullptr, &bevEventS, this);

    timeval tmo(totv(context->effective.tcpTimeout));
    bufferevent_set_timeouts(bev.get(), &tmo, &tmo);

    if(bufferevent_socket_connect(bev.get(), const_cast<sockaddr*>(&peerAddr->sa), peerAddr.size())) {
        // non-blocking connect() failed immediately.
        // try to defer notification.
        state = Disconnected;
        log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %p\n", "ConnBase::state", "Disconnected", "Connection::startConnecting()", context.get());
        constexpr timeval immediate{0, 0};
        if(event_add(echoTimer.get(), &immediate))
            throw std::runtime_error(SB()<<"Unable to begin connecting or schedule deferred notification "<<peerName);
        log_warn_printf(io, "Unable to connect() to %s\n", peerName.c_str());
        return;
    }

    connect(std::move(bev));

    log_debug_printf(io, "Connecting to %s, RX readahead %zu%s\n",
                     peerName.c_str(), readahead, isTLS ? " TLS" : "");
}

#ifdef PVXS_ENABLE_OPENSSL
/**
 * @brief Configure the client OCSP callback if appropriate and if required
 */
void Connection::configureClientOCSPCallback(SSL* ssl) const {
    // If stapling is not disabled
    if (!context->tls_context->stapling_disabled) {
        // And a client was not previously set to request the stapled OCSP Response
        if (SSL_get_tlsext_status_type(ssl) == -1) {
            // Then enable OCSP status request extension
            if (SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp)) {
                log_debug_printf(stapling, "Client OCSP Stapling: Setting up stapling request%s\n", "");
            } else {
                throw ossl::SSLError("Client OCSP Stapling: Error enabling stapling");
            }
            // Set the tls context as the parameter to the callback
            SSL_CTX_set_tlsext_status_arg(context->tls_context->ctx.get(), context->tls_context.get());
            // Set the callback
            SSL_CTX_set_tlsext_status_cb(context->tls_context->ctx.get(), clientOCSPCallback);
        }
    }
}
#endif

/**
 * @brief Create channels for the connection
 *
 * This function is called when a create channel message is received from the server
 * It verifies that the connection is ready to create channels and then proceeds with creating channels
 */
void Connection::createChannels()
{
#ifdef PVXS_ENABLE_OPENSSL
    if (peer_status && peer_status->isSubscribed() && !isPeerStatusGood()) {
        log_debug_printf(certs, "Wait for Server %s certificate status to become GOOD\n", peerName.c_str());
        return; // defer until peer certificate status validated
    }
#endif

    proceedWithCreatingChannels();
}

/**
 * @brief Proceed with creating channels
 *
 * This function is called when a create channel message is received from the server and the connection is ready to create channels
 * It will create the channels and remove them from the pending list
 * If the peer certificate status is being monitored but has not yet been validated, it will set the state to AwaitingPeerCertValidity
 * and return, waiting for the certificate status to be validated before proceeding with creating channels
 */
void Connection::proceedWithCreatingChannels()
{
    if(!ready)
        return; // defer until CONNECTION_VALIDATED

    (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

    auto todo = std::move(pending);

    for(auto& pair : todo) {
        auto chan = pair.second.lock();
        if(!chan || chan->state!=Channel::Connecting)
            continue;

        {
            (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

            EvOutBuf R(sendBE, txBody.get());

            to_wire(R, uint16_t(1u));
            to_wire(R, chan->cid);
            to_wire(R, chan->name);
        }
        chan->statTx += enqueueTxBody(CMD_CREATE_CHANNEL);

        creatingByCID[chan->cid] = chan;
        chan->state = Channel::Creating;
        log_debug_printf(status_cli, "%24.24s = %-12s : Connection::proceedWithCreatingChannels(): %s\n", "Channel::state", "Creating", chan->name.c_str());
        log_debug_printf(io, "Server %s creating channel '%s' (%u)\n", peerName.c_str(), chan->name.c_str(), unsigned(chan->cid));
    }
}

void Connection::sendDestroyRequest(uint32_t sid, uint32_t ioid)
{
    if(!bev)
        return;
    {
        (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

        EvOutBuf R(sendBE, txBody.get());

        to_wire(R, sid);
        to_wire(R, ioid);
    }
    enqueueTxBody(CMD_DESTROY_REQUEST);

}

void Connection::bevEvent(short events) {
    ConnBase::bevEvent(events);

    // Handle BEV_EVENT_CONNECTED specifically for a client
    if(bev && events & BEV_EVENT_CONNECTED) {
        log_debug_printf(io, "PVA-NETWORK: %s ==> BEV_EVENT_CONNECTED\n", peerName.c_str());
        connTime = epicsTime::getCurrent();

        auto peerCred(std::make_shared<ServerCredentials>());
        peerCred->peer = peerName;
        peerCred->method = "anonymous";
#ifdef PVXS_ENABLE_OPENSSL
        peerCred->isTLS = isTLS;

        if (isTLS) {
            const auto ctx = bufferevent_openssl_get_ssl(bev.get());
            if (ctx) {
                ossl::SSLContext::getPeerCredentials(*peerCred, ctx);
            }
        }

#endif
        cred = std::move(peerCred);

        {
            // after async connect() to avoid winsock specific race.
            auto fd(bufferevent_getfd(bev.get()));
            int opt = 1;
            if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt))<0) {
                auto err(SOCKERRNO);
                log_warn_printf(io, "Unable to TCP_NODELAY: %d on %d\n", err, fd);
            }
        }

        if(bufferevent_enable(bev.get(), EV_READ|EV_WRITE))
            throw std::logic_error("Unable to enable BEV");

        // start echo timer
        // tcpTimeout(40) -> 15 second echo period
        // bound echo to range [1, 15]
        timeval tmo(totv(std::max(1.0, std::min(15.0, context->effective.tcpTimeout*3.0/8.0))));
        if(event_add(echoTimer.get(), &tmo))
            log_err_printf(io, "Server %s error starting echoTimer\n", peerName.c_str());

        state = Connected;
        log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %p\n", "ConnBase::state", "Connected", "Connection::bevEvent()", context.get());
    }
}

/**
 * @brief Peer status callback
 *
 * This function is called when the peer status changes.
 *
 * It will be given a status category indicating whether the peer certificate status is GOOD, BAD, or UNKNOWN.
 *
 * - If the peer certificate status is GOOD, and we're waiting for certificate validity before creating channels,
 *   it will set the state to Connected and proceed with creating channels.
 * - If the peer certificate status is BAD, it will disconnect from the server
 */
#ifdef PVXS_ENABLE_OPENSSL
void Connection::peerStatusCallback(certs::cert_status_category_t status_category) {
    if (status_category == certs::GOOD_STATUS) {
        log_debug_printf(certs, "Ready to proceed with creating channels: %s %s\n", "Connecting", peerName.c_str());
        ready = true;
        log_debug_printf(status_cli, "%24.24s = %-12s : %-41s\n", "Connection::ready", ready ? "true" : "false", "Connection::peerStatusCallback()");
        proceedWithCreatingChannels();
    } else if (status_category == certs::BAD_STATUS) {
        log_debug_printf(certs, "Cancel Wait to Creating Channels: BAD CERT STATUS%s\n", "");
        disconnect();
    } else {
        log_debug_printf(certs, "Continue Waiting to Create Channels: UNKNOWN CERT STATUS%s\n", "");
    }
}
#endif

std::shared_ptr<ConnBase> Connection::self_from_this()
{
    return shared_from_this();
}

void Connection::cleanup()
{
    ready = false;
    if(status_cli.test(Level::Debug)) {
        for(auto& pair : pending) {
            if(const auto chan = pair.second.lock())
                log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "Connection::ready", ready ? "true" : "false", "Connection::cleanup()", chan->name.c_str());
        }
        for(auto& pair : chanBySID) {
            if(const auto chan = pair.second.lock())
                log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "Connection::ready", ready ? "true" : "false", "Connection::cleanup()", chan->name.c_str());
        }
        for(auto& pair : creatingByCID) {
            if(const auto chan = pair.second.lock())
                log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "Connection::ready", ready ? "true" : "false", "Connection::cleanup()", chan->name.c_str());
        }
    }

    context->connByAddr.erase(std::make_pair(peerAddr, isTLS));

    if(bev)
        bev.reset();

    if(event_del(echoTimer.get()))
        log_err_printf(io, "Server %s error stopping echoTimer\n", peerName.c_str());

    // return Channels to Searching state
    std::set<std::shared_ptr<Channel>> todo;
    for(auto& pair : pending) {
        if(auto chan = pair.second.lock())
            todo.insert(chan);
    }
    for(auto& pair : chanBySID) {
        if(auto chan = pair.second.lock())
            todo.insert(chan);
    }
    for(auto& pair : creatingByCID) {
        if(auto chan = pair.second.lock())
            todo.insert(chan);
    }

    for(auto& chan : todo) {
        chan->disconnect(chan);
    }

    // Channel::disconnect() should clean
    assert(opByIOID.empty());

    // paranoia
    pending.clear();
    chanBySID.clear();
}

void Connection::handle_CONNECTION_VALIDATION()
{
    log_debug_printf(io, "PVA: %s ==> CONNECTION_VALIDATION\n", peerName.c_str());

    EvInBuf M(peerBE, segBuf.get(), 16);

    // unused
    //   serverReceiveBufferSize
    //   serverIntrospectionRegistryMaxSize
    M.skip(4u + 2u, __FILE__, __LINE__);

    Size nauth{};
    from_wire(M, nauth);

    std::string selected;

    /* Server list given in reverse order of priority.
     * Old pvAccess* was missing a "break" when looping,
     * so it took the last known plugin.
     */
    for(auto n : range(nauth.size)) {
        (void)n;

        std::string method;
        from_wire(M, method);

        if(method=="ca" || (method=="anonymous" && selected!="ca"))
            selected = method;
#ifdef PVXS_ENABLE_OPENSSL
        else if (isTLS && method == "x509" && context->isTlsConfigured())
            selected = method;
#endif
    }

    if(!M.good()) {
        log_err_printf(io, "%s:%d Server %s sends invalid CONNECTION_VALIDATION.  Disconnect...\n",
                       M.file(), M.line(), peerName.c_str());
        bev.reset();
        return;
    }

    if(!selected.empty()) {
        log_debug_printf(io, "Server %s selecting auth '%s'\n", peerName.c_str(), selected.c_str());

    } else {
        selected = "anonymous";
        log_warn_printf(io, "Server %s no supported auth.  try to force '%s'\n", peerName.c_str(), selected.c_str());
    }

    Value cred;
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

        EvOutBuf R(sendBE, txBody.get());

        // serverReceiveBufferSize, not used
        to_wire(R, uint32_t(0x10000));
        // serverIntrospectionRegistryMaxSize, also not used
        to_wire(R, uint16_t(0x7fff));
        // QoS, not used (quality?)
        to_wire(R, uint16_t(0));

        to_wire(R, selected);

        to_wire(R, Value::Helper::desc(cred));
        if(cred)
            to_wire_full(R, cred);
    }
    state = Validated;
    log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "ConnBase::state", "Validated", "Connection::handle_CONNECTION_VALIDATION()", peerName.c_str());
    enqueueTxBody(CMD_CONNECTION_VALIDATION);
}

void Connection::handle_CONNECTION_VALIDATED()
{
    log_debug_printf(io, "PVA: %s ==> CONNECTION_VALIDATED\n", peerName.c_str());
    EvInBuf M(peerBE, segBuf.get(), 16);

    Status sts{};
    from_wire(M, sts);

    if(!M.good()) {
        log_crit_printf(io, "%s:%d Server %s sends invalid CONNECTION_VALIDATED.  Disconnecting...\n",
                        M.file(), M.line(), peerName.c_str());
        bev.reset();
        return;

    } else if(!sts.isSuccess()) {
        log_err_printf(io, "Server %s refuses auth.  Trying to proceed w/o cred\n", peerName.c_str());

    } else {
        log_debug_printf(io, "Server %s accepts auth%s%s\n", peerName.c_str(),
                         sts.msg.empty() ? "" : " ", sts.msg.c_str());
    }

#ifdef PVXS_ENABLE_OPENSSL
    ready = !isTLS || context->isTlsReady();
#else
    ready = true;
#endif
    if(status_cli.test(Level::Debug)) {
        for(auto& pair : pending) {
            const auto chan = pair.second.lock();
            if(!chan || chan->state!=Channel::Connecting)
                continue;
            log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "Connection::ready", ready ? "true" : "false", "Connection::handle_CONNECTION_VALIDATED()", chan->name.c_str());
        }
    }

    createChannels();

    if(nameserver) {
        log_info_printf(io, "(re)connected to nameserver %s\n", peerName.c_str());
        context->poke();
    }
}

void Connection::handle_CREATE_CHANNEL()
{
    log_debug_printf(io, "PVA: %s ==> CREATE_CHANNEL\n", peerName.c_str());
    const auto rxlen = 8u + evbuffer_get_length(segBuf.get());
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t cid, sid;
    Status sts{};

    from_wire(M, cid);
    from_wire(M, sid);
    from_wire(M, sts);
    // "spec" calls for uint16_t Access Rights here, but pvAccessCPP don't include this (it's useless anyway)

    if(!M.good()) {
        log_crit_printf(io, "%s:%d Server %s sends invalid CREATE_CHANNEL.  Disconnecting...\n",
                        M.file(), M.line(), peerName.c_str());
        bev.reset();
        return;
    }

    std::shared_ptr<Channel> chan;
    {
        const auto it = creatingByCID.find(cid);
        if(it==creatingByCID.end() || !(chan = it->second.lock())) {

            if(it!=creatingByCID.end())
                creatingByCID.erase(it);

            if(sts.isSuccess()) {
                // we now have a channel which is no longer interesting.
                log_debug_printf(io, "Server %s disposing of newly stale channel\n", peerName.c_str());

                {
                    (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

                    EvOutBuf R(sendBE, txBody.get());
                    to_wire(R, sid);
                    to_wire(R, cid);
                }
                enqueueTxBody(CMD_DESTROY_CHANNEL);
            }
            return;
        }
        creatingByCID.erase(it);
    }
    chan->statRx += rxlen;

    if(!sts.isSuccess()) {
        if(chan->forcedServer.addr.family()==AF_UNSPEC) {
            // server refuses to create a channel, but presumably responded positively to search.
            // try again

            log_warn_printf(io, "Server %s refuses channel to '%s' : %s\n", peerName.c_str(),
                            chan->name.c_str(), sts.msg.c_str());

            chan->state = Channel::Searching;
            context->searchBuckets[context->currentBucket].push_back(chan);
            log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "Channel::state", "Searching", "Connection::handle_CREATE_CHANNEL()", chan->name.c_str());
        } else {
            // server refused after we bypassed search, so can't use usual retry method.
            // refuse to create a tight retry loop, and drop on the floor for now.
            // retry on reconnect.
            log_err_printf(io, "Server %s refuses direct channel to '%s' : %s\n", peerName.c_str(),
                            chan->name.c_str(), sts.msg.c_str());
            return;
        }
    } else {
        chan->state = Channel::Active;
        log_debug_printf(status_cli, "%24.24s = %-12s : %-41s: %s\n", "Channel::state", "Active", "Connection::handle_CREATE_CHANNEL()", chan->name.c_str());
        chan->sid = sid;

        chanBySID[sid] = chan;

        log_debug_printf(io, "Server %s active channel to '%s' %u:%u\n", peerName.c_str(),
                         chan->name.c_str(), unsigned(chan->cid), unsigned(chan->sid));

        chan->createOperations();

        auto conns(chan->connectors); // copy list

        struct Connected connEvt(peerName, connTime, cred);
        for(auto& conn : conns) {
            if(!conn->_connected.exchange(true, std::memory_order_relaxed) && conn->_onConn)
                conn->_onConn(connEvt);
        }
    }
}

void Connection::handle_DESTROY_CHANNEL()
{
    log_debug_printf(io, "PVA: %s ==> DESTROY_CHANNEL\n", peerName.c_str());
    uint32_t cid=0, sid=0;
    {
        EvInBuf M(peerBE, segBuf.get(), 16);

        from_wire(M, sid);
        from_wire(M, cid);

        if(!M.good()) {
            log_crit_printf(io, "%s:%d Server %s sends invalid DESTROY_CHANNEL.  Disconnecting...\n",
                            M.file(), M.line(), peerName.c_str());
            bev.reset();
            return;
        }
    }

    std::shared_ptr<Channel> chan;
    {
        auto it = chanBySID.find(sid);
        if(it==chanBySID.end() || !(chan = it->second.lock())) {
            log_debug_printf(io, "Server %s destroys non-existent channel %u:%u\n",
                             peerName.c_str(), unsigned(cid), unsigned(sid));
            return;
        }
    }

    chanBySID.erase(sid);
    chan->disconnect(chan);

    log_debug_printf(io, "Server %s destroys channel '%s' %u:%u\n",
                     peerName.c_str(), chan->name.c_str(), unsigned(cid), unsigned(sid));
}

void Connection::handle_MESSAGE()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t ioid = 0;
    uint8_t mtype = 0;
    std::string msg;

    from_wire(M, ioid);
    from_wire(M, mtype);
    from_wire(M, msg);

    if(!M.good())
        throw std::runtime_error(SB()<<M.file()<<':'<<M.line()<<" Decode error for Message");

    auto lvl(mtype2level(mtype));
    const char *chan = "<no channel>";

    auto it = opByIOID.find(ioid);
    if(it!=opByIOID.end()) {
        if(auto op = it->second.handle.lock()) {
            chan = op->chan->name.c_str();
    }
    }

    log_printf(remote, lvl, "%s : %s\n",
               chan, msg.c_str());
}

void Connection::tickEcho()
{
    if(state==Holdoff) {
        log_debug_printf(io, "Server %s holdoff expires\n", peerName.c_str());

        if(event_del(echoTimer.get()))
            log_err_printf(io, "Server %s error Disabling echoTimer\n", peerName.c_str());

        startConnecting();

    }else if(state==Disconnected) {
        // deferred notification of early connect() failure.
        // TODO: avoid a misleading "closed by peer" error
        bevEvent(BEV_EVENT_EOF);

    } else {
        log_debug_printf(io, "Server %s ping\n", peerName.c_str());

        if(!bev)
            return;

        auto tx = bufferevent_get_output(bev.get());

        to_evbuf(tx, Header{CMD_ECHO, 0u, 0u}, sendBE);

        // maybe help reduce latency
        bufferevent_flush(bev.get(), EV_WRITE, BEV_FLUSH);

        statTx += 8;
    }
}

void Connection::tickEchoS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Connection*>(raw)->tickEcho();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in echo timer callback: %s\n", e.what());
    }
}
} // namespace client
} // namespace pvxs
