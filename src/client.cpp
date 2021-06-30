/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <set>
#include <tuple>

#include <osiSock.h>
#include <dbDefs.h>
#include <epicsThread.h>
#include <epicsGuard.h>

#include <pvxs/log.h>
#include <clientimpl.h>

DEFINE_LOGGER(setup, "pvxs.client.setup");
DEFINE_LOGGER(io, "pvxs.client.io");
DEFINE_LOGGER(duppv, "pvxs.client.dup");

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

namespace pvxs {
namespace client {

constexpr timeval bucketInterval{1,0};
constexpr size_t nBuckets = 30u;

// try not to fragment with usual MTU==1500
constexpr size_t maxSearchPayload = 1400;

constexpr timeval channelCacheCleanInterval{10,0};

constexpr timeval beaconCleanInterval{2*180, 0};

constexpr timeval tcpNSCheckInterval{10, 0};

Disconnect::Disconnect()
    :std::runtime_error("Disconnected")
    ,time(epicsTime::getCurrent())
{}

Disconnect::~Disconnect() {}

RemoteError::RemoteError(const std::string& msg)
    :std::runtime_error(msg)
{}

RemoteError::~RemoteError() {}

Finished::~Finished() {}

Connected::Connected(const std::string& peerName)
    :std::runtime_error("Connected")
    ,peerName(peerName)
    ,time(epicsTime::getCurrent())
{}

Connected::~Connected() {}

Interrupted::Interrupted()
    :std::runtime_error ("Interrupted")
{}
Interrupted::~Interrupted() {}

Timeout::Timeout()
    :std::runtime_error ("Interrupted")
{}
Timeout::~Timeout() {}

Channel::Channel(const std::shared_ptr<ContextImpl>& context, const std::string& name, uint32_t cid)
    :context(context)
    ,name(name)
    ,cid(cid)
{}

Channel::~Channel()
{
    disconnect(nullptr);
}

void Channel::createOperations()
{
    if(state!=Channel::Active)
        return;

    auto todo = std::move(pending);

    for(auto& wop : todo) {
        auto op = wop.lock();
        if(!op)
            continue;

        uint32_t ioid;
        do {
            ioid = conn->nextIOID++;
        } while(conn->opByIOID.find(ioid)!=conn->opByIOID.end());

        //conn->opByIOID.insert(std::make_pair(ioid, RequestInfo(sid, ioid, op)));
        auto pair = conn->opByIOID.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(ioid),
                                           std::forward_as_tuple(sid, ioid, op));
        opByIOID[ioid] = &pair.first->second;

        op->ioid = ioid;

        op->createOp();
    }
}

// call on disconnect or CMD_DESTROY_CHANNEL
// detach from Connection and notify Connect and *Op
void Channel::disconnect(const std::shared_ptr<Channel>& self)
{
    assert(!self || this==self.get());
    auto current(std::move(conn));

    switch(state) {
    case Channel::Connecting:
        current->pending.erase(cid);
        break;
    case Channel::Creating:
        current->creatingByCID.erase(cid);
        break;
    case Channel::Active:
        current->chanBySID.erase(sid);
        break;
    default:
        break;
    }

    if((state==Creating || state==Active) && current && current->bev) {
        {
            (void)evbuffer_drain(current->txBody.get(), evbuffer_get_length(current->txBody.get()));

            EvOutBuf R(hostBE, current->txBody.get());

            to_wire(R, sid);
            to_wire(R, cid);
        }
        statTx += current->enqueueTxBody(CMD_DESTROY_CHANNEL);
    }

    state = Channel::Searching;
    sid = 0xdeadbeef; // spoil

    auto conns(connectors); // copy list

    for(auto& interested : conns) {
        if(interested->_connected.exchange(false, std::memory_order_relaxed) && interested->_onDis)
            interested->_onDis();
    }

    auto ops(std::move(opByIOID));
    for(auto& pair : ops) {
        auto op = pair.second->handle.lock();
        current->opByIOID.erase(pair.first);
        if(op)
            op->disconnected(op);
    }

    if(!self) { // in ~Channel
        // searchBuckets cleaned in tickSearch()

    } else if(forcedServer.family()==AF_UNSPEC) { // begin search

        context->searchBuckets[context->currentBucket].push_back(self);

        log_debug_printf(io, "Server %s detach channel '%s' to re-search\n",
                         current ? current->peerName.c_str() : "<disconnected>",
                         name.c_str());

    } else { // reconnect to specific server
        // TODO: holdoff to prevent fast reconnect loop

        conn = Connection::build(context, forcedServer);

        conn->pending[cid] = self;
        state = Connecting;

        conn->createChannels();

    }
}

Connect::~Connect() {}

ConnectImpl::~ConnectImpl() {}

const std::string& ConnectImpl::name() const
{
    return _name;
}
bool ConnectImpl::connected() const
{
    return _connected.load(std::memory_order_relaxed);
}

std::shared_ptr<Connect> ConnectBuilder::exec()
{
    if(!ctx)
        throw std::logic_error("NULL Builder");

    auto syncCancel(_syncCancel);
    auto context(ctx->impl->shared_from_this());

    auto op(std::make_shared<ConnectImpl>(context->tcp_loop, _pvname));
    op->_onConn = std::move(_onConn);
    op->_onDis = std::move(_onDis);

    std::shared_ptr<ConnectImpl> external(op.get(), [op, syncCancel](ConnectImpl*) mutable {
        // from user thread
        auto temp(std::move(op));
        auto loop(temp->loop);
        // std::bind for lack of c++14 generalized capture
        // to move internal ref to worker for dtor
        loop.tryInvoke(syncCancel, std::bind([](std::shared_ptr<ConnectImpl>& op) {
                      // on worker

                      // ordering of dispatch()/call() ensures creation before destruction
                      assert(op->chan);
                      op->chan->connectors.remove(op.get());
                  }, std::move(temp)));
    });

    context->tcp_loop.dispatch([op, context]() {
        // on worker

        op->chan = Channel::build(context, op->_name, std::string());

        bool cur = op->_connected = op->chan->state==Channel::Active;
        if(cur && op->_onConn)
            op->_onConn();
        else if(!cur && op->_onDis)
            op->_onDis();

        op->chan->connectors.push_back(op.get());
    });

    return external;
}

Value ResultWaiter::wait(double timeout)
{
    Guard G(lock);
    while(outcome==Busy) {
        UnGuard U(G);
        if(!notify.wait(timeout))
            throw Timeout();
    }
    if(outcome==Done)
        return result();
    else
        throw Interrupted();
}

void ResultWaiter::complete(Result&& result, bool interrupt)
{
    {
        Guard G(lock);
        if(outcome!=Busy)
            return;
        this->result = std::move(result);
        outcome = interrupt ? Abort : Done;
    }
    notify.signal();
}

OperationBase::OperationBase(operation_t op, const evbase& loop)
    :Operation(op)
    ,loop(loop)
{}

OperationBase::~OperationBase() {}

const std::string& OperationBase::name()
{
    return chan->name;
}

Value OperationBase::wait(double timeout)
{
    if(!waiter)
        throw std::logic_error("Operation has custom .result() callback");
    return waiter->wait(timeout);
}

void OperationBase::interrupt()
{
    if(waiter)
        waiter->complete(Result(), true);
}

RequestInfo::RequestInfo(uint32_t sid, uint32_t ioid, std::shared_ptr<OperationBase>& handle)
    :sid(sid)
    ,ioid(ioid)
    ,op(handle->op)
    ,handle(handle)
{}

std::shared_ptr<Channel> Channel::build(const std::shared_ptr<ContextImpl>& context,
                                        const std::string& name,
                                        const std::string& server)
{
    SockAddr forceServer;
    decltype (context->chanByName)::key_type namekey(name, server);

    if(!server.empty()) {
        forceServer.setAddress(server.c_str(), context->effective.tcp_port);
    }

    std::shared_ptr<Channel> chan;

    auto it = context->chanByName.find(namekey);
    if(it!=context->chanByName.end()) {
        chan = it->second;
        chan->garbage = false;
    }

    if(!chan) {
        while(context->chanByCID.find(context->nextCID)!=context->chanByCID.end())
            context->nextCID++;

        chan = std::make_shared<Channel>(context, name, context->nextCID);

        context->chanByCID[chan->cid] = chan;
        context->chanByName[namekey] = chan;

        if(server.empty()) {
            context->searchBuckets[context->currentBucket].push_back(chan);

            context->poke(true);

        } else { // bypass search and connect so a specific server
            chan->forcedServer = forceServer;
            chan->conn = Connection::build(context, forceServer);

            chan->conn->pending[chan->cid] = chan;
            chan->state = Connecting;

            chan->conn->createChannels();

        }
    }

    return chan;
}

Operation::~Operation() {}

Subscription::~Subscription() {}

Context::Context(const Config& conf)
    :pvt(std::make_shared<Pvt>(conf))
{
    pvt->impl->startNS();
}

Context::~Context() {}

const Config& Context::config() const
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    return pvt->impl->effective;
}

void Context::hurryUp()
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    pvt->impl->manager.loop().call([this](){
        pvt->impl->poke(true);
    });
}

void Context::cacheClear(const std::string& name, cacheAction action)
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    pvt->impl->tcp_loop.call([this, name, action](){
        // run twice to ensure both mark and sweep of all unused channels
        log_debug_printf(setup, "cacheClear('%s')\n", name.c_str());
        pvt->impl->cacheClean(name, action);
        pvt->impl->cacheClean(name, action);
    });
}

void Context::ignoreServerGUIDs(const std::vector<ServerGUID>& guids)
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    pvt->impl->manager.loop().call([this, &guids](){
        pvt->impl->ignoreServerGUIDs = guids;
    });
}

Report Context::report(bool zero) const
{
    Report ret;

    pvt->impl->tcp_loop.call([this, &ret, zero](){

        for(auto& pair : pvt->impl->connByAddr) {
            auto conn = pair.second.lock();
            if(!conn)
                continue;

            ret.connections.emplace_back();
            auto& sconn = ret.connections.back();
            sconn.peer = conn->peerName;
            sconn.tx = conn->statTx;
            sconn.rx = conn->statRx;

            if(zero) {
                conn->statTx = conn->statRx = 0u;
            }

            // omit stats for transitory conn->creatingByCID

            for(auto& pair : conn->chanBySID) {
                auto chan = pair.second.lock();
                if(!chan)
                    continue;

                sconn.channels.emplace_back();
                auto& schan = sconn.channels.back();
                schan.name = chan->name;
                schan.tx = chan->statTx;
                schan.rx = chan->statRx;

                if(zero) {
                    chan->statTx = chan->statRx = 0u;
                }
            }
        }

    });

    return ret;
}

static
Value buildCAMethod()
{
    using namespace pvxs::members;

    return TypeDef(TypeCode::Struct, {
                       String("user"),
                       String("host"),
                   }).create();
}

ContextImpl::ContextImpl(const Config& conf, const evbase& tcp_loop)
    :effective(conf)
    ,caMethod(buildCAMethod())
    ,searchTx(AF_INET, SOCK_DGRAM, 0)
    ,tcp_loop(tcp_loop)
    ,searchRx(event_new(tcp_loop.base, searchTx.sock, EV_READ|EV_PERSIST, &ContextImpl::onSearchS, this))
    ,searchTimer(event_new(tcp_loop.base, -1, EV_TIMEOUT, &ContextImpl::tickSearchS, this))
    ,manager(UDPManager::instance())
    ,beaconCleaner(event_new(manager.loop().base, -1, EV_TIMEOUT|EV_PERSIST, &ContextImpl::tickBeaconCleanS, this))
    ,cacheCleaner(event_new(tcp_loop.base, -1, EV_TIMEOUT|EV_PERSIST, &ContextImpl::cacheCleanS, this))
    ,nsChecker(event_new(tcp_loop.base, -1, EV_TIMEOUT|EV_PERSIST, &ContextImpl::onNSCheckS, this))
{
    effective.expand();

    searchBuckets.resize(nBuckets);

    std::set<SockAddr> bcasts;
    for(auto& addr : searchTx.interfaces()) {
        addr.setPort(0u);
        bcasts.insert(addr);
    }

    {
        osiSockAddr any{};
        any.ia.sin_family = AF_INET;
        if(bind(searchTx.sock, &any.sa, sizeof(any.ia)))
            throw std::runtime_error("Unable to bind random UDP port");

        socklen_t alen = sizeof(any);
        if(getsockname(searchTx.sock, &any.sa, &alen))
            throw std::runtime_error("Unable to readback random UDP port");

        searchRxPort = ntohs(any.ia.sin_port);

        log_debug_printf(setup, "Using UDP Rx port %u\n", searchRxPort);
    }

    {
        int val = 1;
        if(setsockopt(searchTx.sock, SOL_SOCKET, SO_BROADCAST, (char *)&val, sizeof(val)))
            log_err_printf(setup, "Unable to setup beacon sender SO_BROADCAST: %d\n", SOCKERRNO);
    }
    enable_SO_RXQ_OVFL(searchTx.sock);

    for(auto& addr : effective.addressList) {
        SockAddr saddr(AF_INET);
        try {
            saddr.setAddress(addr.c_str(), effective.udp_port);
        }catch(std::runtime_error& e) {
            log_err_printf(setup, "%s  Ignoring %s\n", e.what(), addr.c_str());
            continue;
        }
        auto top = ntohl(saddr->in.sin_addr.s_addr)>>24u;
        auto ismcast = top>224 && top<239;
        bool isbcast = bcasts.find(saddr.withPort(0))!=bcasts.end(); // TODO: exclude port
        auto isucast = !isbcast && !ismcast;

        log_info_printf(io, "Searching to %s%s\n", saddr.tostring().c_str(), (isucast?" unicast":""));
        searchDest.emplace_back(saddr, isucast);
    }

    for(auto& addr : effective.nameServers) {
        SockAddr saddr(AF_INET);
        try {
            saddr.setAddress(addr.c_str(), 5075);
        }catch(std::runtime_error& e) {
            log_err_printf(setup, "%s  Ignoring...\n", e.what());
        }

        log_info_printf(io, "Searching to TCP %s\n", saddr.tostring().c_str());
        nameServers.emplace_back(saddr, nullptr);
    }

    for(auto& iface : effective.interfaces) {
        SockAddr addr(AF_INET, iface.c_str(), effective.udp_port);
        log_info_printf(io, "Listening for beacons on %s\n", addr.tostring().c_str());
        beaconRx.push_back(manager.onBeacon(addr, [this](const UDPManager::Beacon& msg) {
            onBeacon(msg);
        }));
    }

    for(auto& listener : beaconRx) {
        listener->start();
    }

    if(event_add(searchTimer.get(), &bucketInterval))
        log_err_printf(setup, "Error enabling search timer\n%s", "");
    if(event_add(searchRx.get(), nullptr))
        log_err_printf(setup, "Error enabling search RX\n%s", "");
    if(event_add(beaconCleaner.get(), &beaconCleanInterval))
        log_err_printf(setup, "Error enabling beacon clean timer on\n%s", "");
    if(event_add(cacheCleaner.get(), &channelCacheCleanInterval))
        log_err_printf(setup, "Error enabling channel cache clean timer on\n%s", "");
}

ContextImpl::~ContextImpl() {}

void ContextImpl::startNS()
{
    if(nameServers.empty()) // vector size const after ctor, contents remain mutable
        return;

    tcp_loop.call([this]() {
        // start connections to name servers
        for(auto& ns : nameServers) {
            const auto& serv = ns.first;
            ns.second = Connection::build(shared_from_this(), serv);
            ns.second->nameserver = true;
            log_debug_printf(io, "Connecting to nameserver %s\n", ns.second->peerName.c_str());
        }

        if(event_add(nsChecker.get(), &tcpNSCheckInterval))
            log_err_printf(setup, "Error enabling TCP search reconnect timer\n%s", "");
    });
}

void ContextImpl::close()
{
    // terminate all active connections
    tcp_loop.call([this]() {
        (void)event_del(searchTimer.get());
        (void)event_del(searchRx.get());
        (void)event_del(beaconCleaner.get());
        (void)event_del(cacheCleaner.get());

        auto conns(std::move(connByAddr));
        // explicitly break ref. loop of channel cache
        auto chans(std::move(chanByName));

        for(auto& pair : conns) {
            auto conn = pair.second.lock();
            if(!conn)
                continue;

            conn->cleanup();
        }

        conns.clear();
        chans.clear();

        // internal_self.use_count() may be >1 if
        // we are orphaning some Operations
    });

    tcp_loop.sync();

    // ensure any in-progress callbacks have completed
    manager.sync();
}

void ContextImpl::poke(bool force)
{
    {
        Guard G(pokeLock);
        if(poked)
            return;

        epicsTimeStamp now{};

        double age = -1.0;
        if(!force && (epicsTimeGetCurrent(&now) || (age=epicsTimeDiffInSeconds(&now, &lastPoke))<30.0)) {
            log_debug_printf(setup, "Ignoring hurryUp() age=%.1f sec\n", age);
            return;
        }
        lastPoke = now;
        poked = true;
    }

    log_debug_printf(setup, "hurryUp()%s\n", "");

    timeval immediate{0,0};
    if(event_add(searchTimer.get(), &immediate))
        throw std::runtime_error("Unable to schedule searchTimer");
}

void ContextImpl::onBeacon(const UDPManager::Beacon& msg)
{
    const auto& guid = msg.guid;

    epicsTimeStamp now;
    epicsTimeGetCurrent(&now);

    {
        Guard G(pokeLock);
        auto it = beaconSenders.find(msg.src);
        if(it!=beaconSenders.end() && msg.guid==it->second.guid) {
            it->second.lastRx = now;
            return;
        }

        beaconSenders.emplace(msg.src, BTrack{msg.guid, now});
    }

    log_debug_printf(io, "%s\n",
                     std::string(SB()<<msg.src<<" New server "<<guid<<' '<<msg.server).c_str());

    poke(false);
}

static
void procSearchReply(ContextImpl& self, const SockAddr& src, Buffer& M, bool istcp)
{
    ServerGUID guid;
    SockAddr serv(AF_INET);
    uint16_t port = 0;
    uint8_t found = 0u;

    _from_wire<12>(M, &guid[0], false, __FILE__, __LINE__);
    // searchSequenceID
    // we don't use this and instead rely on ID for individual PVs
    M.skip(4u, __FILE__, __LINE__);

    from_wire(M, serv);
    if(serv.isAny())
        serv = src;
    from_wire(M, port);
    if(istcp && port==0)
        port = src.port();
    serv.setPort(port);

    if(M.size()<4u || M[0]!=3u || M[1]!='t' || M[2]!='c' || M[3]!='p')
        return;
    M.skip(4u, __FILE__, __LINE__);

    from_wire(M, found);
    if(!found)
        return;

    uint16_t nSearch = 0u;
    from_wire(M, nSearch);

    if(M.good()) {
        for(const ServerGUID& ignore : self.ignoreServerGUIDs) {
            if(guid==ignore) {
                log_info_printf(io, "Ignore reply from %s with %s\n",
                                 src.tostring().c_str(), std::string(SB()<<guid).c_str());
                return;
            }
        }
    }

    for(auto n : range(nSearch)) {
        (void)n;

        uint32_t id=0u;
        from_wire(M, id);
        if(!M.good())
            break;

        std::shared_ptr<Channel> chan;
        {
            auto it = self.chanByCID.find(id);
            if(it==self.chanByCID.end())
                continue;

            chan = it->second.lock();
            if(!chan)
                continue;
        }

        log_debug_printf(io, "Search reply for %s\n", chan->name.c_str());

        if(chan->state==Channel::Searching) {
            chan->guid = guid;
            chan->replyAddr = serv;

            chan->conn = Connection::build(self.shared_from_this(), serv);

            chan->conn->pending[chan->cid] = chan;
            chan->state = Channel::Connecting;

            chan->conn->createChannels();

        } else if(chan->guid!=guid) {
            log_err_printf(duppv, "Duplicate PV name %s from %s and %s\n",
                           chan->name.c_str(),
                           chan->replyAddr.tostring().c_str(),
                           serv.tostring().c_str());
        }
    }

}

bool ContextImpl::onSearch()
{
    searchMsg.resize(0x10000);
    SockAddr src;
    uint32_t ndrop = 0u;

    osiSocklen_t alen = src.size();
    const int nrx = recvfromx(searchTx.sock, (char*)&searchMsg[0], searchMsg.size()-1, &src->sa, &alen, &ndrop);

    if(nrx>=0 && ndrop!=0 && prevndrop!=ndrop) {
        log_debug_printf(io, "UDP search reply buffer overflow %u -> %u\n", unsigned(prevndrop), unsigned(ndrop));
        prevndrop = ndrop;
    }

    if(nrx<0) {
        int err = evutil_socket_geterror(searchTx.sock);
        if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
            // nothing to do here
        } else {
            log_warn_printf(io, "UDP search RX Error on : %s\n",
                       evutil_socket_error_to_string(err));
        }
        return false; // wait for more I/O

    } else if(nrx<8) {
        // maybe a zero (body) length packet?
        // maybe an OS error?

        log_info_printf(io, "UDP ignore runt%s\n", "");
        return true;

    } else if(searchMsg[0]!=0xca || searchMsg[1]==0 || (searchMsg[2]&(pva_flags::Control|pva_flags::SegMask))) {
        // minimum header size is 8 bytes
        // ID byte must by 0xCA (because PVA has some paternal envy)
        // ignore incompatible version 0
        // UDP packets can't contain control messages, or use segmentation

        log_info_printf(io, "UDP ignore header%u %02x%02x%02x%02x\n",
                   unsigned(nrx), searchMsg[0], searchMsg[1], searchMsg[2], searchMsg[3]);
        return true;
    }

    log_hex_printf(io, Level::Debug, &searchMsg[0], nrx, "UDP search Rx %d from %s\n", nrx, src.tostring().c_str());

    bool be = searchMsg[2]&pva_flags::MSB;

    FixedBuf M(be, searchMsg.data(), nrx);

    const uint8_t cmd = M[3];
    M.skip(4, __FILE__, __LINE__);

    uint32_t len=0;
    from_wire(M, len);

    if(len > M.size() && M.good()) {
        log_info_printf(io, "UDP ignore header%u %02x%02x%02x%02x\n",
                   unsigned(M.size()), M[0], M[1], M[2], M[3]);
        return true;
    }

    if(cmd==CMD_SEARCH_RESPONSE) {
        procSearchReply(*this, src, M, false);

    } else {
        M.fault(__FILE__, __LINE__);
    }

    if(!M.good()) {
        log_hex_printf(io, Level::Err, &searchMsg[0], nrx,
                "%s:%d Invalid search reply %d from %s\n",
                M.file(), M.line(), nrx, src.tostring().c_str());
    }

    return true;
}

void Connection::handle_SEARCH_RESPONSE()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    procSearchReply(*context, peerAddr, M, true);

    if(!M.good()) {
        log_crit_printf(io, "%s:%d Server %s sends invalid SEARCH_RESPONSE.  Disconnecting...\n",
                        M.file(), M.line(), peerName.c_str());
        bev.reset();
    }
}

void ContextImpl::onSearchS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        log_debug_printf(io, "UDP search Rx event %x\n", evt);
        if(!(evt&EV_READ))
            return;

        // limit number of packets processed before going back to the reactor
        unsigned i;
        const unsigned limit = 40;
        for(i=0; i<limit && static_cast<ContextImpl*>(raw)->onSearch(); i++) {}
        log_debug_printf(io, "UDP search processed %u/%u\n", i, limit);

    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in search Rx callback: %s\n", e.what());
    }
}

void ContextImpl::tickSearch()
{
    {
        Guard G(pokeLock);
        poked = false;
    }

    auto idx = currentBucket;
    currentBucket = (currentBucket+1u)%searchBuckets.size();

    log_debug_printf(io, "Search tick %zu\n", idx);

    decltype (searchBuckets)::value_type bucket;
    searchBuckets[idx].swap(bucket);

    while(!bucket.empty()) {
        searchMsg.resize(0x10000);
        FixedBuf M(true, searchMsg.data(), searchMsg.size());
        M.skip(8, __FILE__, __LINE__); // fill in header after body length known

        // searchSequenceID
        // we don't use this and instead rely on IDs for individual PVs
        to_wire(M, uint32_t(0x66696e64));

        // flags and reserved.
        // initially flags[7] is cleared (bcast)
        auto pflags = M.save();
        to_wire(M, uint32_t(0u));

        // IN6ADDR_ANY_INIT
        to_wire(M, uint32_t(0u));
        to_wire(M, uint32_t(0u));
        to_wire(M, uint32_t(0u));
        to_wire(M, uint32_t(0u));

        auto pport = M.save();
        to_wire(M, uint16_t(searchRxPort));

        to_wire(M, uint8_t(1u));
        to_wire(M, "tcp");

        // placeholder for channel count;
        auto pcount = M.save();
        uint16_t count = 0u;
        M.skip(2u, __FILE__, __LINE__);

        bool payload = false;
        while(!bucket.empty()) {
            auto chan = bucket.front().lock();
            if(!chan || chan->state!=Channel::Searching) {
                bucket.pop_front();
                continue;
            }

            auto save = M.save();
            to_wire(M, uint32_t(chan->cid));
            to_wire(M, chan->name);

            if(!M.good()) {
                // some absurdly long PV name?
                log_err_printf(io, "PV name exceeds search buffer: '%s'\n", chan->name.c_str());
                // drop it on the floor
                bucket.pop_front();
                continue;

            } else if(size_t(M.save() - searchMsg.data()) > maxSearchPayload) {
                assert(payload); // must have something
                // too large, defer
                M.restore(save);
                break;
            }

            count++;

            auto ninc = chan->nSearch = std::min(searchBuckets.size(), chan->nSearch+1u);
            auto next = (idx + ninc)%searchBuckets.size();
            auto nextnext = (next + 1u)%searchBuckets.size();

            // try to smooth out UDP bcast load by waiting one extra tick
            {
                auto nextN = searchBuckets[next].size();
                auto nextnextN = searchBuckets[nextnext].size();

                if(nextN > nextnextN && (nextN-nextnextN > 100u))
                    next = nextnext;
            }

            auto& nextBucket = searchBuckets[next];

            nextBucket.splice(nextBucket.end(),
                              bucket,
                              bucket.begin());
            payload = true;
        }
        assert(M.good());

        if(!payload)
            break;

        {
            FixedBuf C(true, pcount, 2u);
            to_wire(C, count);
        }
        size_t consumed = M.save() - searchMsg.data();
        {
            FixedBuf H(true, searchMsg.data(), 8);
            to_wire(H, Header{CMD_SEARCH, 0, uint32_t(consumed-8u)});
        }
        for(auto& pair : searchDest) {
            *pflags = pair.second ? 0x80 : 0x00;

            int ntx = sendto(searchTx.sock, (char*)searchMsg.data(), consumed, 0, &pair.first->sa, pair.first.size());

            if(ntx<0) {
                int err = evutil_socket_geterror(searchTx.sock);
                auto lvl = Level::Warn;
                if(err==EINTR || err==EPERM)
                    lvl = Level::Debug;
                log_printf(io, lvl, "Search tx error (%d) %s\n",
                           err, evutil_socket_error_to_string(err));

            } else if(unsigned(ntx)<consumed) {
                log_warn_printf(io, "Search truncated %u < %u",
                           unsigned(ntx), unsigned(consumed));

            } else {
                log_debug_printf(io, "Search to %s %s\n", pair.first.tostring().c_str(),
                                 pair.second ? "ucast" : "bcast");
            }
        }
        *pflags |= 0x80; // TCP search is always "unicast"
        // TCP search replies should always come back on the same connection,
        // so zero out the meaningless response port.
        pport[0] = pport[1] = 0;

        for(auto& pair : nameServers) {
            auto& serv = pair.second;

            if(!serv->ready || !serv->bev)
                continue;

            auto tx = bufferevent_get_output(serv->bev.get());

            // arbitrarily skip searching if TX buffer is too full
            // TODO: configure limit?
            if(evbuffer_get_length(tx) > 64*1024u)
                continue;

            (void)evbuffer_add(tx, (char*)searchMsg.data(), consumed);
            // fail silently, will retry
        }

    }

    if(event_add(searchTimer.get(), &bucketInterval))
        log_err_printf(setup, "Error re-enabling search timer on\n%s", "");
}

void ContextImpl::tickSearchS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<ContextImpl*>(raw)->tickSearch();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in search timer callback: %s\n", e.what());
    }
}

void ContextImpl::tickBeaconClean()
{
    epicsTimeStamp now;
    epicsTimeGetCurrent(&now);

    Guard G(pokeLock);

    auto it = beaconSenders.begin();
    while(it!=beaconSenders.end()) {
        auto cur = it++;

        double age = epicsTimeDiffInSeconds(&now, &cur->second.lastRx);

        if(age < -15.0 || age > 2.1*180.0) {
            auto& guid = cur->second.guid;
            log_debug_printf(io, "%s\n",
                             std::string(SB()<<" Lost server "<<guid<<' '<<cur->first).c_str());

            beaconSenders.erase(cur);
        }
    }
}

void ContextImpl::tickBeaconCleanS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<ContextImpl*>(raw)->tickBeaconClean();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in beacon cleaner timer callback: %s\n", e.what());
    }
}

void ContextImpl::onNSCheck()
{
    for(auto& ns : nameServers) {
        if(ns.second && ns.second->bev) // connecting or connected
            continue;

        ns.second = Connection::build(shared_from_this(), ns.first);
        ns.second->nameserver = true;
        log_debug_printf(io, "Reconnecting nameserver %s\n", ns.second->peerName.c_str());
    }
}

void ContextImpl::onNSCheckS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<ContextImpl*>(raw)->onNSCheck();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in TCP nameserver timer callback: %s\n", e.what());
    }
}

void ContextImpl::cacheClean(const std::string& name, Context::cacheAction action)
{
    auto next(chanByName.begin()),
         end(chanByName.end());

    while(next!=end) {
        auto cur(next++);

        if(!name.empty() && cur->first.first!=name)
            continue;

        else if(action!=Context::Clean || cur->second.use_count()<=1) {
            cur->second->garbage = true;

            if(action==Context::Clean && !cur->second->garbage) {
                // mark for next sweep
                log_debug_printf(setup, "Chan GC mark '%s':'%s'\n",
                                 cur->first.first.c_str(), cur->first.second.c_str());

            } else {
                log_debug_printf(setup, "Chan GC sweep '%s':'%s'\n",
                                 cur->first.first.c_str(), cur->first.second.c_str());

                auto trash(std::move(cur->second));

                // explicitly break ref. loop of channel cache
                chanByName.erase(cur);

                if(action==Context::Disconnect) {
                    trash->disconnect(trash);
                }
            }
        }
    }
}

void ContextImpl::cacheCleanS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<ContextImpl*>(raw)->cacheClean(std::string(), Context::Clean);
        static_cast<ContextImpl*>(raw)->tickBeaconClean();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in beacon cleaner timer callback: %s\n", e.what());
    }
}

Context::Pvt::Pvt(const Config& conf)
    :loop("PVXCTCP", epicsThreadPriorityCAServerLow)
    ,impl(std::make_shared<ContextImpl>(conf, loop.internal()))
{}

Context::Pvt::~Pvt()
{
    impl->close();
}

} // namespace client

} // namespace pvxs
