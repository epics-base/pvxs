/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <set>

#include <osiSock.h>
#include <dbDefs.h>
#include <epicsThread.h>

#include <pvxs/log.h>
#include <clientimpl.h>

DEFINE_LOGGER(setup, "pvxs.client.setup");
DEFINE_LOGGER(io, "pvxs.client.io");
DEFINE_LOGGER(duppv, "pvxs.client.dup");

namespace pvxs {
namespace client {

constexpr timeval bucketInterval{1,0};
constexpr size_t nBuckets = 30u;

constexpr size_t maxSearchPayload = 0x4000;

Channel::Channel(const std::shared_ptr<Context::Pvt>& context, const std::string& name, uint32_t cid)
    :context(context)
    ,name(name)
    ,cid(cid)
{}

Channel::~Channel()
{
    context->chanByCID.erase(cid);
    context->chanByName.erase(name);
    // searchBuckets cleaned in tickSearch()
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

        conn->opByIOID.insert(std::make_pair(ioid, RequestInfo(ioid, op)));
        op->ioid = ioid;

        op->createOp();
    }
}


OperationBase::OperationBase(operation_t op, const std::shared_ptr<Channel>& chan)
    :Operation(op)
    ,chan(chan)
{}

OperationBase::~OperationBase() {}

RequestInfo::RequestInfo(uint32_t ioid, std::shared_ptr<OperationBase>& handle)
    :ioid(ioid)
    ,op(handle->op)
    ,handle(handle)
{}

std::shared_ptr<Channel> Channel::build(const std::shared_ptr<Context::Pvt>& context, const std::string& name)
{

    std::shared_ptr<Channel> chan;

    auto it = context->chanByName.find(name);
    if(it!=context->chanByName.end()) {
        chan = it->second.lock();
    }

    if(!chan) {
        while(context->chanByCID.find(context->nextCID)!=context->chanByCID.end())
            context->nextCID++;

        chan = std::make_shared<Channel>(context, name, context->nextCID);
        context->chanByCID[chan->cid] = chan;
        context->chanByName[chan->name] = chan;

        context->searchBuckets[context->currentBucket].push_back(chan);
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

    // external
    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        internal->close();
        internal.reset();
    });
    // we don't keep a weak_ptr to the external reference.
    // Caller is entirely responsible for keeping this server running
}

Context::~Context() {}

const Config& Context::config() const
{
    return pvt->effective;
}

void Context::poke()
{}

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
{
    effective.expand();

    searchBuckets.resize(nBuckets);

    if(effective.udp_port==0)
        throw std::runtime_error("Client can't use UDP random port");

    std::set<std::string> bcasts;
    {
        ELLLIST list = ELLLIST_INIT;
        osiSockAddr any{};

        osiSockDiscoverBroadcastAddresses(&list, searchTx.sock, &any);

        while(ELLNODE *cur = ellGet(&list)) {
            osiSockAddrNode *node = CONTAINER(cur, osiSockAddrNode, node);

            SockAddr addr(&node->addr.sa, sizeof(node->addr));
            addr.setPort(0u);
            bcasts.insert(addr.tostring());

            free(node);
        }
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

    for(auto& addr : effective.addressList) {
        auto isbcast = bcasts.find(addr)!=bcasts.end();
        SockAddr saddr(AF_INET);
        try {
            saddr.setAddress(addr.c_str());
        }catch(std::runtime_error& e) {
            log_err_printf(setup, "%s  Ignoring...\n", e.what());
        }
        auto top = ntohl(saddr->in.sin_addr.s_addr)>>24u;
        auto isucast = !isbcast && top<239 && top>224;

        saddr.setPort(effective.udp_port);
        searchDest.emplace_back(saddr, isucast);
    }

    // TODO: receive beacons
    //auto manager = UDPManager::instance();


    if(event_add(searchTimer.get(), &bucketInterval))
        log_err_printf(setup, "Error enabling search timer\n%s", "");
    if(event_add(searchRx.get(), nullptr))
        log_err_printf(setup, "Error enabling search RX\n%s", "");
}

Context::Pvt::~Pvt() {}

void Context::Pvt::close()
{
    // terminate all active connections
    tcp_loop.call([this]() {
        (void)event_del(searchTimer.get());
        (void)event_del(searchRx.get());

        decltype (connByAddr) conns(std::move(connByAddr));

        for(auto& pair : conns) {
            auto conn = pair.second.lock();
            if(!conn)
                continue;

            conn->cleanup();
        }
    });
}

bool Context::Pvt::onSearch()
{
    searchMsg.resize(0x10000);
    SockAddr src;

    osiSocklen_t alen = src.size();
    const int nrx = recvfrom(searchTx.sock, (char*)&searchMsg[0], searchMsg.size()-1, 0, &src->sa, &alen);

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
    M.skip(4);

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
        M.skip(4u);

        from_wire(M, serv);
        if(serv.isAny())
            serv = src;
        from_wire(M, port);
        serv.setPort(port);

        if(M.size()<4u || M[0]!=3u || M[1]!='t' || M[2]!='c' || M[3]!='p')
            return true;
        M.skip(4u);

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
        M.fault();
    }

    if(!M.good()) {
        log_hex_printf(io, Level::Err, &searchMsg[0], nrx, "Invalid search reply %d from %s\n", nrx, src.tostring().c_str());
    }

    return true;
}

void Context::Pvt::onSearchS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        log_debug_printf(io, "UDP search Rx event %x\n", evt);
        if(!(evt&EV_READ))
            return;

        // handle up to 4 packets before going back to the reactor
        for(unsigned i=0; i<4 && static_cast<Pvt*>(raw)->onSearch(); i++) {}

    }catch(std::exception& e){
        log_crit_printf(io, "Unhandled error in search Rx callback: %s\n", e.what());
    }
}

void Context::Pvt::tickSearch()
{
    auto idx = currentBucket;
    currentBucket = (currentBucket+1u)%searchBuckets.size();

    log_debug_printf(io, "Search tick %zu\n", idx);

    decltype (searchBuckets)::value_type bucket;
    searchBuckets[idx].swap(bucket);

    while(!bucket.empty()) {
        searchMsg.resize(0x10000);
        FixedBuf M(true, searchMsg.data(), searchMsg.size());
        M.skip(8); // fill in header after body length known

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
        M.skip(2u);

        bool payload = false;
        while(!bucket.empty()) {
            auto chan = bucket.front().lock();
            if(!chan || chan->state!=Channel::Searching) {
                bucket.pop_front();
                continue;
            }

            if(searchMsg.size()<=maxSearchPayload-(5+chan->name.size()))
                break;

            to_wire(M, uint32_t(chan->cid));
            to_wire(M, chan->name);
            count++;

            auto ninc = chan->nSearch = std::min(searchBuckets.size(), chan->nSearch+1u);
            auto next = (idx + ninc)%searchBuckets.size();

            // TODO leveling with next+-1 buckets

            auto& nextBucket = searchBuckets[next];

            nextBucket.splice(nextBucket.end(),
                              bucket,
                              bucket.begin());
            payload = true;
        }

        if(!payload)
            break;

        {
            FixedBuf C(true, pcount, 2u);
            to_wire(C, count);
        }
        auto consumed = M.save() - searchMsg.data();
        {
            FixedBuf H(true, searchMsg.data(), 8);
            to_wire(H, Header{CMD_SEARCH, pva_flags::Server, uint32_t(consumed-8u)});
        }
        for(auto& pair : searchDest) {
            // TODO: unicast/bcast
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
        log_crit_printf(io, "Unhandled error in search timer callback: %s\n", e.what());
    }
}

} // namespace client

} // namespace pvxs
