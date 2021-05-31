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

Channel::Channel(const std::shared_ptr<Context::Pvt>& context, const std::string& name, uint32_t cid)
    :context(context)
    ,name(name)
    ,cid(cid)
{}

Channel::~Channel()
{
    context->chanByCID.erase(cid);
    // searchBuckets cleaned in tickSearch()
    if((state==Creating || state==Active) && conn && conn->bev) {
        {
            (void)evbuffer_drain(conn->txBody.get(), evbuffer_get_length(conn->txBody.get()));

            EvOutBuf R(hostBE, conn->txBody.get());

            to_wire(R, sid);
            to_wire(R, cid);
        }
        conn->enqueueTxBody(CMD_DESTROY_CHANNEL);
    }
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

void Channel::disconnect(const std::shared_ptr<Channel>& self)
{
    self->state = Channel::Searching;
    self->sid = 0xdeadbeef; // spoil
    context->searchBuckets[context->currentBucket].push_back(self);

    log_debug_printf(io, "Server %s detach channel '%s' to re-search\n",
                     conn ? conn->peerName.c_str() : "<disconnected>",
                     self->name.c_str());

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

OperationBase::OperationBase(operation_t op, const std::shared_ptr<Channel>& chan)
    :Operation(op)
    ,chan(chan)
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

std::shared_ptr<Channel> Channel::build(const std::shared_ptr<Context::Pvt>& context, const std::string& name)
{

    std::shared_ptr<Channel> chan;

    auto it = context->chanByName.find(name);
    if(it!=context->chanByName.end()) {
        chan = it->second;
        chan->garbage = false;
    }

    if(!chan) {
        while(context->chanByCID.find(context->nextCID)!=context->chanByCID.end())
            context->nextCID++;

        chan = std::make_shared<Channel>(context, name, context->nextCID);
        context->chanByCID[chan->cid] = chan;
        context->chanByName[chan->name] = chan;

        context->searchBuckets[context->currentBucket].push_back(chan);

        context->poke(true);
    }

    return chan;
}

Operation::~Operation() {}

Subscription::~Subscription() {}

Context::Context(const Config& conf)
{
    /* Here be dragons.
     *
     * We keep two different ref. counters.
     * - "externel" counter which keeps a server running.
     * - "internal" which only keeps server storage from being destroyed.
     *
     * External refs are held as Server::pvt.  Internal refs are
     * held by various in-progress operations (OpBase sub-classes)
     * Which need to safely access server storage, but should not
     * prevent a server from stopping.
     */
    auto internal(std::make_shared<Pvt>(conf));
    internal->internal_self = internal;
    cnt_ClientPvtLive.fetch_add(1u);

    // external
    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        auto temp(std::move(internal));
        try {
            temp->close();
        }catch(std::exception& e){
            // called through ~shared_ptr and can't propagate exceptions.
            // log and continue...
            log_exc_printf(setup, "Error while closing Context (%s) : %s\n",
                           typeid(e).name(), e.what());
        }
        cnt_ClientPvtLive.fetch_sub(1u);
    });
    // we don't keep a weak_ptr to the external reference.
    // Caller is entirely responsible for keeping this server running
}

Context::~Context() {}

const Config& Context::config() const
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    return pvt->effective;
}

void Context::hurryUp()
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    pvt->manager.loop().call([this](){
        pvt->poke(true);
    });
}

void Context::cacheClear()
{
    if(!pvt)
        throw std::logic_error("NULL Context");

    pvt->tcp_loop.call([this](){
        // run twice to ensure both mark and sweep of all unused channels
        pvt->cacheClean();
        pvt->cacheClean();
    });
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

Context::Pvt::Pvt(const Config& conf)
    :effective(conf)
    ,caMethod(buildCAMethod())
    ,searchTx(AF_INET, SOCK_DGRAM, 0)
    ,tcp_loop("PVXCTCP", epicsThreadPriorityCAServerLow)
    ,searchRx(event_new(tcp_loop.base, searchTx.sock, EV_READ|EV_PERSIST, &Pvt::onSearchS, this))
    ,searchTimer(event_new(tcp_loop.base, -1, EV_TIMEOUT, &Pvt::tickSearchS, this))
    ,manager(UDPManager::instance())
    ,beaconCleaner(event_new(manager.loop().base, -1, EV_TIMEOUT|EV_PERSIST, &Pvt::tickBeaconCleanS, this))
    ,cacheCleaner(event_new(tcp_loop.base, -1, EV_TIMEOUT|EV_PERSIST, &Pvt::cacheCleanS, this))
{
    effective.expand();

    searchBuckets.resize(nBuckets);

    std::set<std::string> bcasts;
    for(auto& addr : searchTx.interfaces()) {
        addr.setPort(0u);
        bcasts.insert(addr.tostring());
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
        auto isbcast = bcasts.find(addr)!=bcasts.end();
        SockAddr saddr(AF_INET);
        try {
            saddr.setAddress(addr.c_str(), effective.udp_port);
        }catch(std::runtime_error& e) {
            log_err_printf(setup, "%s  Ignoring %s\n", e.what(), addr.c_str());
        }
        auto top = ntohl(saddr->in.sin_addr.s_addr)>>24u;
        auto isucast = !isbcast && top<239 && top>224;

        log_info_printf(io, "Searching to %s%s\n", saddr.tostring().c_str(), (isucast?" unicast":""));
        searchDest.emplace_back(saddr, isucast);
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

Context::Pvt::~Pvt() {}

void Context::Pvt::close()
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

void Context::Pvt::poke(bool force)
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

void Context::Pvt::onBeacon(const UDPManager::Beacon& msg)
{
    const auto& guid = msg.guid;

    epicsTimeStamp now;
    epicsTimeGetCurrent(&now);

    auto it = beaconSenders.find(msg.src);
    if(it!=beaconSenders.end() && msg.guid==it->second.guid) {
        it->second.lastRx = now;
        return;
    }

    beaconSenders.emplace(msg.src, BTrack{msg.guid, now});

    log_debug_printf(io, "%s New server %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %s\n",
               msg.src.tostring().c_str(),
               guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7], guid[8], guid[9], guid[10], guid[11],
               msg.server.tostring().c_str());

    poke(false);
}

bool Context::Pvt::onSearch()
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
        std::array<uint8_t, 12> guid;
        SockAddr serv;
        uint16_t port = 0;
        uint8_t found = 0u;

        _from_wire<12>(M, &guid[0], false);
        // searchSequenceID
        // we don't use this and instead rely on ID for individual PVs
        M.skip(4u, __FILE__, __LINE__);

        from_wire(M, serv);
        if(serv.isAny())
            serv = src;
        from_wire(M, port);
        serv.setPort(port);

        if(M.size()<4u || M[0]!=3u || M[1]!='t' || M[2]!='c' || M[3]!='p')
            return true;
        M.skip(4u, __FILE__, __LINE__);

        from_wire(M, found);
        if(!found)
            return true;

        uint16_t nSearch = 0u;
        from_wire(M, nSearch);

        for(auto n : range(nSearch)) {
            (void)n;

            uint32_t id=0u;
            from_wire(M, id);
            if(!M.good())
                break;

            std::shared_ptr<Channel> chan;
            {
                auto it = chanByCID.find(id);
                if(it==chanByCID.end())
                    continue;

                chan = it->second.lock();
                if(!chan)
                    continue;
            }

            log_debug_printf(io, "Search reply for %s\n", chan->name.c_str());

            if(chan->state==Channel::Searching) {
                chan->guid = guid;
                chan->replyAddr = serv;

                auto it = connByAddr.find(serv);
                if(it==connByAddr.end() || !(chan->conn = it->second.lock())) {
                    connByAddr[serv] = chan->conn = std::make_shared<Connection>(internal_self.lock(), serv);
                }

                chan->conn->pending.push_back(chan);
                chan->state = Channel::Connecting;

                chan->conn->createChannels();

            } else if(chan->guid!=guid) {
                log_err_printf(duppv, "Duplicate PV name %s from %s and %s\n",
                               chan->name.c_str(),
                               chan->replyAddr.tostring().c_str(),
                               serv.tostring().c_str());
            }
        }

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

void Context::Pvt::onSearchS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        log_debug_printf(io, "UDP search Rx event %x\n", evt);
        if(!(evt&EV_READ))
            return;

        // limit number of packets processed before going back to the reactor
        unsigned i;
        const unsigned limit = 40;
        for(i=0; i<limit && static_cast<Pvt*>(raw)->onSearch(); i++) {}
        log_debug_printf(io, "UDP search processed %u/%u\n", i, limit);

    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in search Rx callback: %s\n", e.what());
    }
}

void Context::Pvt::tickSearch()
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
        auto consumed = M.save() - searchMsg.data();
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
    }

    if(event_add(searchTimer.get(), &bucketInterval))
        log_err_printf(setup, "Error re-enabling search timer on\n%s", "");
}

void Context::Pvt::tickSearchS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Pvt*>(raw)->tickSearch();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in search timer callback: %s\n", e.what());
    }
}

void Context::Pvt::tickBeaconClean()
{
    epicsTimeStamp now;
    epicsTimeGetCurrent(&now);

    auto it = beaconSenders.begin();
    while(it!=beaconSenders.end()) {
        auto cur = it++;

        double age = epicsTimeDiffInSeconds(&now, &cur->second.lastRx);

        if(age < -15.0 || age > 2.1*180.0) {
            auto& guid = cur->second.guid;
            log_debug_printf(io, "Lost server %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %s\n",
                       guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7], guid[8], guid[9], guid[10], guid[11],
                       cur->first.tostring().c_str());

            beaconSenders.erase(cur);
        }
    }
}

void Context::Pvt::tickBeaconCleanS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Pvt*>(raw)->tickBeaconClean();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in beacon cleaner timer callback: %s\n", e.what());
    }
}

void Context::Pvt::cacheClean()
{
    std::set<std::string> trash;

    for(auto& pair : chanByName) {
        if(pair.second.use_count()<=1) {
            if(!pair.second->garbage) {
                // mark for next sweep
                log_debug_printf(setup, "Chan GC mark '%s'\n", pair.first.c_str());
                pair.second->garbage = true;

            } else {
                // sweep
                trash.insert(pair.first);
            }
        }
    }

    // explicitly break ref. loop of channel cache
    for(auto& name : trash) {
        chanByName.erase(name);
        log_debug_printf(setup, "Chan GC sweep '%s'\n", name.c_str());
    }
}

void Context::Pvt::cacheCleanS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Pvt*>(raw)->tickBeaconClean();
    }catch(std::exception& e){
        log_exc_printf(io, "Unhandled error in beacon cleaner timer callback: %s\n", e.what());
    }
}

} // namespace client

} // namespace pvxs
