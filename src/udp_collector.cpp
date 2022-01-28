/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstring>

#include <set>
#include <map>
#include <vector>
#include <tuple>
#include <memory>

#include <epicsThread.h>
#include <epicsMutex.h>
#include <epicsGuard.h>
#include <osiSock.h>

#include <event2/util.h>

#include <pvxs/log.h>
#include "udp_collector.h"
#include "pvaproto.h"

typedef epicsGuard<epicsMutex> Guard;


namespace pvxs {namespace impl {

DEFINE_LOGGER(logio, "pvxs.udp.io");
DEFINE_LOGGER(logsetup, "pvxs.udp.setup");

struct UDPCollector : public UDPManager::Search,
                      public std::enable_shared_from_this<UDPCollector>
{
    UDPManager::Pvt* const manager;
    SockAddr bind_addr; // address our socket is bound to
    SockAddr lo_mcast_addr; // destination endpoint for local mcast forwarding
    SockAddr lo_addr;
    std::set<std::pair<SockAddr, SockAddr>> mcast_grps; // mcast group+iface pairs which our socket has joined
    std::string name;
    evsocket sock;
    evevent rx;
    uint32_t prevndrop{};

    std::vector<uint8_t> buf;

    UDPManager::Beacon beaconMsg;

    std::set<UDPListener*> listeners;

    UDPCollector(UDPManager::Pvt* manager, uint16_t port);
    ~UDPCollector();

    void addListener(UDPListener *l);
    void delListener(UDPListener *l);

    bool handle_one();

    enum origin_t {
        Remote,    // received from interface other than loopback
        Loopback,  // received through loopback
        OriginTag, // payload of CMD_ORIGIN_TAG
    };

    void process_one(const SockAddr& dest, const uint8_t* buf, size_t nrx, origin_t origin);
    static void handle_static(evutil_socket_t fd, short ev, void *raw)
    {
        (void)fd;
        auto self = static_cast<UDPCollector*>(raw);
        try {
            log_debug_printf(logio, "UDP %p event %x\n", self->rx.get(), ev);
            if(!(ev&EV_READ))
                return;

            // handle up to 4 packets before going back to the reactor
            for(unsigned i=0; i<4 && self->handle_one(); i++) {}

        }catch(std::exception& e) {
            log_crit_printf(logio, "Ignoring unhandled exception in UDPManager::handle(): %s\n", e.what());
        }
    }

    void forwardM(const SockAddr& origin, const uint8_t* buf, size_t len);

    // Search interface
public:
    virtual bool reply(const void *msg, size_t msglen) const override;
};


struct UDPManager::Pvt {

    evbase loop;
    IfaceMap ifmap;

    // only manipulate from loop worker thread
    std::map<uint16_t, UDPCollector*> collectors;

    Pvt()
        :loop("PVXUDP", epicsThreadPriorityCAServerLow-4)
    {}
    ~Pvt()
    {
        // we should only be destroyed after that last collector has removed itself
        assert(collectors.empty());
    }

    std::shared_ptr<UDPCollector> collect(const SockAddr& dest)
    {
        std::shared_ptr<UDPCollector> collector;

        if(dest.port()!=0) {
            auto it = collectors.find(dest.port());
            if(it!=collectors.end()) {
                try {
                    collector = it->second->shared_from_this();
                }catch(std::bad_weak_ptr&){
                    // nothing to do
                }
            }
        }

        if(!collector) {
            collector.reset(new UDPCollector(this, dest.port()));
        }
        return collector;
    }
};

UDPCollector::UDPCollector(UDPManager::Pvt *manager, uint16_t requested_port)
    :manager(manager)
    ,bind_addr(SockAddr::any(AF_INET, requested_port))
    ,lo_mcast_addr(bind_addr.family(), "224.0.0.128")
    ,lo_addr(SockAddr::loopback(bind_addr.family()))
    ,sock(bind_addr.family(), SOCK_DGRAM, 0)
    ,rx(event_new(manager->loop.base, sock.sock, EV_READ|EV_PERSIST, &handle_static, this))
    ,beaconMsg(src)
{
    manager->loop.assertInLoop();

    epicsSocketEnableAddressUseForDatagramFanout(sock.sock);
    enable_SO_RXQ_OVFL(sock.sock);
    enable_IP_PKTINFO(sock.sock);

    /* Always bind to wildcard to receive all uni/broad/multicast, and also to send them.
     * Notes:
     * - Linux, it would be possible to bind to the mcast address in order to receive only
     *   packets so destined.  It would also be possible to send mcasts from a socket
     *   so bound.
     * - OSX, it would be possible to bind to the mcast address, but not to send mcasts.
     * - Winsock, it is not possible to bind to the mcast address.
     *
     * So we take the least common denominator across all platforms, which is to bind to the wildcard.
     * This socket may then receive unicasts which need to be forwarded.
     */
    sock.bind(bind_addr);
    name = "UDP "+bind_addr.tostring();

    lo_mcast_addr.setPort(bind_addr.port());
    lo_addr.setPort(bind_addr.port());

    // join local group to receive
    sock.mcast_join(lo_mcast_addr, lo_addr);
    // setup for re-transmit
    sock.mcast_ttl(1); // make default explicit, we will only send to lo_mcast_addr.
    sock.mcast_loop(true);
    sock.mcast_iface(lo_addr);

    mcast_grps.emplace(lo_mcast_addr, lo_addr);

    log_info_printf(logsetup, "Bound %d to %s as lo\n", sock.sock, name.c_str());

    if(event_add(rx.get(), nullptr))
        throw std::runtime_error("Unable to create collector Rx event");

    manager->collectors[bind_addr.port()] = this;
}

UDPCollector::~UDPCollector()
{
    manager->loop.assertInLoop();

    manager->collectors.erase(bind_addr.port());

    // we should only be destroyed after that last listener has removed itself
    assert(listeners.empty());
    manager->loop.assertInLoop();
}

void UDPCollector::addListener(UDPListener *l)
{
    for(const auto& mcast : l->mcasts) {
        const auto tup(std::make_pair(mcast, l->dest));
        if(mcast_grps.find(tup)==mcast_grps.end()) {
            mcast_grps.insert(tup);

            log_debug_printf(logsetup, "collector joining %s on %s\n",
                             mcast.tostring().c_str(),
                             l->dest.tostring().c_str());

            sock.mcast_join(mcast, l->dest);
        }
    }
    listeners.insert(l);
}

void UDPCollector::delListener(UDPListener *l)
{
    listeners.erase(l);

    // TODO: bother to cleanup mcast group membership?
}

// size of a CMD_ORIGIN_TAG prefix header
static constexpr size_t cmd_origin_tag_size = 8 + 16;

bool UDPCollector::handle_one()
{
    SockAddr dest;

    buf.resize(cmd_origin_tag_size + 0x10000 + 1);
    auto rxbuf = &buf[cmd_origin_tag_size];
    auto rxlen = buf.size()-cmd_origin_tag_size-1;

    // For Search messages, we use PV name strings in-place by adding nils.
    // Ensure one extra byte at the end of the buffer for a nil after the last PV name
    recvfromx rx{sock.sock, (char*)rxbuf, rxlen, &src, &dest};
    const int nrx = rx.call();

    if(nrx>=0 && rx.ndrop!=0u && prevndrop!=rx.ndrop) {
        log_debug_printf(logio, "UDP collector socket buffer overflowed %u -> %u\n", unsigned(prevndrop), unsigned(rx.ndrop));
        prevndrop = rx.ndrop;
    }

    if(nrx<0) {
        int err = evutil_socket_geterror(sock.sock);
        if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
            // nothing to do here
        } else {
            log_warn_printf(logio, "UDP RX Error on %s : %s\n", name.c_str(),
                            evutil_socket_error_to_string(err));
        }
        return false; // wait for more I/O

    }

    log_hex_printf(logio, Level::Debug, rxbuf, nrx, "UDP %d Rx %d, %s -> %s @%u (%s)\n",
            sock.sock, nrx, src.tostring().c_str(), dest.tostring().c_str(), unsigned(rx.dstif), bind_addr.tostring().c_str());

    origin_t origin = manager->ifmap.has_address(rx.dstif, lo_addr) ? Loopback : Remote;

    process_one(dest, rxbuf, nrx, origin);
    return true;
}

void UDPCollector::process_one(const SockAddr &dest, const uint8_t *buf, size_t nrx, origin_t origin)
{
    FixedBuf M(true, const_cast<uint8_t*>(buf), nrx);
    Header head{};
    from_wire(M, head); // overwrites M.be

    if(!M.good() || (head.flags&(pva_flags::Control|pva_flags::SegMask))) {
        // UDP packets can't contain control messages, or use segmentation

        log_hex_printf(logio, Level::Debug, &buf[0], nrx, "Ignore UDP message from %s\n", src.tostring().c_str());
        return;
    }

    names.clear();

    if(head.len > M.size() && M.good()) {
        log_info_printf(logio, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                        unsigned(M.size()), M[0], M[1], M[2], M[3],
                name.c_str());
        return;
    }

    switch(head.cmd) {

    case CMD_SEARCH: {
        uint8_t flags = 0;
        SockAddr replyAddr;
        uint16_t port = 0;

        from_wire(M, searchID);
        auto save_flags = M.save();
        from_wire(M, flags);
        mustReply = flags&pva_search_flags::MustReply;

        M.skip(3, __FILE__, __LINE__); // unused/reserved

        auto save_replyAddr = M.save();
        from_wire(M, replyAddr);
        from_wire(M, port);
        if(replyAddr.isAny()) {
            replyAddr = src;
            if(origin==OriginTag) {
                log_err_printf(logio, "CMD_ORIGIN_TAG search with reply to sender never works%s", "\n");
                return;
            }
        }
        replyAddr.setPort(port);

        if(M.good() && origin==Loopback && (flags&pva_search_flags::Unicast) && dest.family()!=AF_UNSPEC) {
            assert(buf==&this->buf[cmd_origin_tag_size]);
            // clear unicast flag in forwarded message
            *save_flags &= ~pva_search_flags::Unicast;
            // recipient of forwarded message must use, and trust, replyAddr in body :(
            {
                FixedBuf R(M.be, save_replyAddr, 16u);
                to_wire(R, replyAddr);
                assert(R.good());
            }
            forwardM(dest, buf, nrx);
            return;
        }

        // so far, only "tcp" transport has ever been seen.
        // however, we will consider and ignore any others which might appear
        bool foundtcp = false;
        Size nproto{0};
        from_wire(M, nproto);
        for(size_t i=0; i<nproto.size && M.good(); i++) {
            Size nchar{0};
            from_wire(M, nchar);

            // shortcut to avoid allocating a std::string
            // "tcp" is the only value we expect to see
            foundtcp |= M.size()>=3 && nchar.size==3 && M[0]=='t' && M[1]=='c' && M[2]=='p';
            M.skip(nchar.size, __FILE__, __LINE__);
        }

        // one Search message can include many PV names.
        uint16_t nchan=0;
        from_wire(M, nchan);

        names.clear();
        names.reserve(nchan);

        for(size_t i=0; i<nchan && M.good(); i++) {
            uint32_t id=0xffffffff; // poison
            Size chlen{0};

            auto mundge = M.save();
            from_wire(M, id);
            from_wire(M, chlen);
            // inject nil for previous PV name
            *mundge = '\0';
            if(foundtcp && chlen.size<=M.size() && M.good()) {
                names.push_back(UDPManager::Search::Name{reinterpret_cast<const char*>(M.save()), id});
            }
            M.skip(chlen.size, __FILE__, __LINE__);
        }

        // used by our reply()
        src = replyAddr;

        if(M.good()) {
            // ensure nil for final PV name
            *M.save() = '\0';

            for(auto L : listeners) {
                if(L->searchCB) {
                    (L->searchCB)(*this);
                }
            }
        }

        break;
    }

    case CMD_BEACON: {
        uint16_t port = 0;

        _from_wire<12>(M, &beaconMsg.guid[0], false, __FILE__, __LINE__);
        M.skip(4, __FILE__, __LINE__); // skip flags, seq, and change count.  unused
        from_wire(M, beaconMsg.server);
        from_wire(M, port);
        if(beaconMsg.server.isAny()) {
            beaconMsg.server = src;
        }
        beaconMsg.server.setPort(port);

        std::string proto;
        from_wire(M, proto);

        // ignore remaining "server status" blob

        if(M.good() && proto=="tcp") {
            for(auto L : listeners) {
                if(L->beaconCB) {
                    (L->beaconCB)(beaconMsg);
                }
            }
        }
        break;
    }

    case CMD_ORIGIN_TAG: {
        SockAddr originaddr; // aka. original destination
        from_wire(M, originaddr);
        M.skip(head.len-16u, __FILE__, __LINE__);

        // only allow one CMD_ORIGIN_TAG message per packet
        // only accept when sent to the mcast address from the loopback address
        //   since we only join the mcast group on loopback this will hopefully
        //   frustrate attempts to inject CMD_ORIGIN_TAG externally.
        if(M.good() && origin==Loopback && dest.compare(lo_mcast_addr,false)==0 && src.isLO()) {
            originaddr.setPort(bind_addr.port());

            process_one(originaddr, M.save(), M.size(), OriginTag);

            return;
        }
        log_debug_printf(logio, "Ignore originated from %s %c%c%c%c\n",
                         originaddr.tostring().c_str(),
                         M.good() ? 'T' : 'F',
                         origin==Loopback ? 'T' : 'F',
                         dest.compare(lo_mcast_addr,false)==0 ? 'T' : 'F',
                         src.isLO() ? 'T' : 'F');

        break;
    }

    default:
        break; // ignore unknown
    }
}

void UDPCollector::forwardM(const SockAddr& origin, const uint8_t *pbuf, size_t plen)
{
    log_debug_printf(logio, "Forward as originated for %s\n",
                     origin.tostring().c_str());

    assert(buf.size() > cmd_origin_tag_size);
    assert(pbuf==&buf[cmd_origin_tag_size]);

    {
        FixedBuf M(true, &buf[0], cmd_origin_tag_size);

        to_wire(M, Header{CMD_ORIGIN_TAG, 0, 16u});
        to_wire(M, origin);
        assert(M.good());
        assert(M.save()==&buf[cmd_origin_tag_size]);
    }

    src = lo_mcast_addr;
    reply(&buf[0], cmd_origin_tag_size+plen);
}

bool UDPCollector::reply(const void *msg, size_t msglen) const
{
    manager->loop.assertInLoop();

    log_hex_printf(logio, Level::Debug, msg, msglen, "Send %s -> %s\n",
                   bind_addr.tostring().c_str(), src.tostring().c_str());

    auto ntx = sendto(sock.sock, (char*)msg, msglen, 0, &src->sa, src.size());
    if(ntx<0) {
        int err = evutil_socket_geterror(sock.sock);
        if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
            // nothing to do here
        } else {
            log_warn_printf(logio, "UDP TX Error on %s -> %s : (%d) %s\n",
                            name.c_str(), src.tostring().c_str(),
                            err, evutil_socket_error_to_string(err));
        }
        return false; // wait for more I/O
    }
    return size_t(ntx)==msglen;
}

static struct udp_gbl_t {
    epicsMutex lock;
    std::weak_ptr<UDPManager::Pvt> inst;
} *udp_gbl;

UDPManager::~UDPManager() {}

evbase& UDPManager::loop()
{
    if(!pvt)
        throw std::logic_error("NULL UDPManager");

    return pvt->loop;
}

namespace {
epicsThreadOnceId collector_once = EPICS_THREAD_ONCE_INIT;
void collector_init(void *unused)
{
    (void)unused;
    try {
        udp_gbl = new udp_gbl_t;
    }catch(std::exception& e){
        log_exc_printf(logsetup, "Unable to alloc udp_gbl: %s\n", e.what());
    }
}
} // namespace

UDPManager UDPManager::instance()
{
    epicsThreadOnce(&collector_once, &collector_init, nullptr);
    assert(udp_gbl);

    Guard G(udp_gbl->lock);

    auto ret = udp_gbl->inst.lock();

    if(!ret) {
        ret.reset(new UDPManager::Pvt);
        udp_gbl->inst = ret;
    }

    return UDPManager(ret);
}

void UDPManager::cleanup()
{
    delete udp_gbl;
    udp_gbl = nullptr;
}

std::unique_ptr<UDPListener> UDPManager::onBeacon(SockAddr& dest,
                                                  std::function<void(const Beacon&)>&& cb)
{
    if(!pvt)
        throw std::invalid_argument("UDPManager null");

    std::unique_ptr<UDPListener> ret;

    pvt->loop.call([this, &ret, &dest, &cb](){
        // from event loop worker

        ret.reset(new UDPListener(pvt, dest));
        ret->beaconCB = std::move(cb);
    });

    return ret;
}

std::unique_ptr<UDPListener> UDPManager::onSearch(SockAddr& dest,
                                                  std::function<void(const Search&)>&& cb)
{
    if(!pvt)
        throw std::invalid_argument("UDPManager null");

    std::unique_ptr<UDPListener> ret;

    pvt->loop.call([this, &ret, &dest, &cb](){
        // from event loop worker

        ret.reset(new UDPListener(pvt, dest));
        ret->searchCB = std::move(cb);
    });

    return ret;
}

void UDPManager::sync()
{
    if(!pvt)
        throw std::invalid_argument("UDPManager null");

    pvt->loop.sync();
}

UDPListener::UDPListener(const std::shared_ptr<UDPManager::Pvt> &manager, SockAddr &dest)
    :manager(manager)
    ,dest(dest)
    ,active(false)
{
    manager->loop.assertInLoop();

    collector = manager->collect(dest);
    dest.setPort(collector->bind_addr.port());
}

UDPListener::~UDPListener()
{
    manager->loop.call([this](){
        // from event loop worker

        if(active)
            collector->delListener(this);

        collector.reset(); // destroy UDPCollector from worker
    });
}

void UDPListener::addMCast(const SockAddr& mcast)
{
    manager->loop.call([this, &mcast](){
        if(active)
            throw std::logic_error("must addMCast() before start()");

        collector->mcast_grps.emplace(mcast.withPort(collector->bind_addr.port()),
                                      dest);
    });
}

void UDPListener::start(bool s)
{
    manager->loop.call([this, s](){
        if(s && !active) {
            collector->addListener(this);

        } else if(!s && active) {
            collector->delListener(this);
        }

        active = s;
    });
}

UDPManager::Search::~Search() {}

}} // namespace pvxs::impl
