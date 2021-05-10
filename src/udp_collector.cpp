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
    const std::shared_ptr<UDPManager::Pvt> manager;
    SockAddr bind_addr;
    std::string name;
    evsocket sock;
    evevent rx;
    uint32_t prevndrop{};

    std::vector<uint8_t> buf;

    UDPManager::Beacon beaconMsg;

    std::set<UDPListener*> listeners;

    UDPCollector(const std::shared_ptr<UDPManager::Pvt>& manager, const SockAddr& bind_addr);
    ~UDPCollector();

    bool handle_one()
    {
        osiSocklen_t alen = src.size();
        uint32_t ndrop = 0u;

        // For Search messages, we use PV name strings in-place by adding nils.
        // Ensure one extra byte at the end of the buffer for a nil after the last PV name
        const int nrx = recvfromx(sock.sock, (char*)&buf[0], buf.size()-1, &src->sa, &alen, &ndrop);

        if(nrx>=0 && ndrop!=0u && prevndrop!=ndrop) {
            log_debug_printf(logio, "UDP collector socket buffer overflowed %u -> %u\n", unsigned(prevndrop), unsigned(ndrop));
            prevndrop = ndrop;
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

        } else if(nrx<8) {
            // maybe a zero (body) length packet?
            // maybe an OS error?

            log_info_printf(logio, "UDP ignore runt on %s\n", name.c_str());
            return true;

        } else if(buf[0]!=0xca || buf[1]==0 || (buf[2]&(pva_flags::Control|pva_flags::SegMask))) {
            // minimum header size is 8 bytes
            // ID byte must by 0xCA (because PVA has some paternal envy)
            // ignore incompatible version 0
            // UDP packets can't contain control messages, or use segmentation

            log_info_printf(logio, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                       unsigned(nrx), buf[0], buf[1], buf[2], buf[3],
                    name.c_str());
            return true;
        }

        log_hex_printf(logio, Level::Debug, &buf[0], nrx, "UDP Rx %d from %s\n", nrx, src.tostring().c_str());

        names.clear();

        bool be = buf[2]&pva_flags::MSB;

        FixedBuf M(be, buf.data(), nrx);

        uint8_t cmd = M[3];

        M.skip(4, __FILE__, __LINE__);
        uint32_t len=0;
        from_wire(M, len);

        if(len > M.size() && M.good()) {
            log_info_printf(logio, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                       unsigned(M.size()), M[0], M[1], M[2], M[3],
                    name.c_str());
            return true;
        }

        switch(cmd) {

        case CMD_SEARCH: {
            uint8_t flags = 0;
            SockAddr replyAddr;
            uint16_t port = 0;

            from_wire(M, searchID);
            from_wire(M, flags);
            mustReply = flags&pva_search_flags::MustReply;
            M.skip(3, __FILE__, __LINE__); // unused/reserved

            from_wire(M, replyAddr);
            from_wire(M, port);
            if(replyAddr.isAny()) {
                replyAddr = src;
            }
            replyAddr.setPort(port);

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

            Size protolen{0};
            from_wire(M, protolen);
            M.skip(protolen.size, __FILE__, __LINE__); // ignore string

            // ignore remaining "server status" blob

            if(M.good()) {
                for(auto L : listeners) {
                    if(L->beaconCB) {
                        (L->beaconCB)(beaconMsg);
                    }
                }
            }
        }
            break;
        }

        return true;
    }
    void handle(short ev)
    {
        log_debug_printf(logio, "UDP %p event %x\n", rx.get(), ev);
        if(!(ev&EV_READ))
            return;

        // handle up to 4 packets before going back to the reactor
        for(unsigned i=0; i<4 && handle_one(); i++) {}
    }
    static void handle_static(evutil_socket_t fd, short ev, void *raw)
    {
        (void)fd;
        try {
            static_cast<UDPCollector*>(raw)->handle(ev);
        }catch(std::exception& e) {
            log_crit_printf(logio, "Ignoring unhandled exception in UDPManager::handle(): %s\n", e.what());
        }
    }

    // Search interface
public:
    virtual bool reply(const void *msg, size_t msglen) const override;
};


struct UDPManager::Pvt : public std::enable_shared_from_this<Pvt> {

    evbase loop;

    // only manipulate from loop worker thread
    std::map<SockAddr, UDPCollector*> collectors;

    Pvt()
        :loop("PVXUDP", epicsThreadPriorityCAServerLow-4)
    {}
    ~Pvt()
    {
        // we should only be destroyed after that last collector has removed itself
        assert(collectors.empty());
    }
};

UDPCollector::UDPCollector(const std::shared_ptr<UDPManager::Pvt>& manager, const SockAddr& bind_addr)
    :manager(manager)
    ,bind_addr(bind_addr)
    ,sock(bind_addr.family(), SOCK_DGRAM, 0)
    ,rx(event_new(manager->loop.base, sock.sock, EV_READ|EV_PERSIST, &handle_static, this))
    ,buf(0x10001)
    ,beaconMsg(src)
{
    manager->loop.assertInLoop();

    epicsSocketEnableAddressUseForDatagramFanout(sock.sock);
    enable_SO_RXQ_OVFL(sock.sock);
    sock.bind(this->bind_addr);
    name = "UDP "+this->bind_addr.tostring();

    log_info_printf(logsetup, "Bound to %s\n", name.c_str());

    if(event_add(rx.get(), nullptr))
        throw std::runtime_error("Unable to create collector Rx event");

    manager->collectors[this->bind_addr] = this;
}

UDPCollector::~UDPCollector()
{
    manager->loop.assertInLoop();

    manager->collectors.erase(this->bind_addr);

    // we should only be destroyed after that last listener has removed itself
    assert(listeners.empty());
    manager->loop.assertInLoop();
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
    udp_gbl = new udp_gbl_t;
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

        ret.reset(new UDPListener(pvt.get(), dest));
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

        ret.reset(new UDPListener(pvt.get(), dest));
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

UDPListener::UDPListener(UDPManager::Pvt *manager, SockAddr &dest)
    :dest(dest)
    ,active(false)
{
    manager->loop.assertInLoop();

    if(dest.port()!=0) {
        auto it = manager->collectors.find(dest);
        if(it!=manager->collectors.end()) {
            try {
                collector = it->second->shared_from_this();
            }catch(std::bad_weak_ptr&){
                // nothing to do
            }
        }
    }

    if(!collector) {
        collector.reset(new UDPCollector(manager->shared_from_this(), dest));
        dest = collector->bind_addr;
    }
}

UDPListener::~UDPListener()
{
    auto manager = collector->manager;
    manager->loop.call([this](){
        // from event loop worker

        if(active)
            collector->listeners.erase(this);

        collector.reset(); // destroy UDPCollector from worker
    });
    // UDPManager may be destroyed at this point, which joins its event loop worker
}

void UDPListener::start(bool s)
{
    collector->manager->loop.call([this, s](){
        if(s && !active) {
            collector->listeners.insert(this);

        } else if(!s && active) {
            collector->listeners.erase(this);
        }

        active = s;
    });
}

bool UDPCollector::reply(const void *msg, size_t msglen) const
{
    manager->loop.assertInLoop();

    int ntx = sendto(sock.sock, (char*)msg, msglen, 0, &src->sa, src.size());
    if(ntx<0) {
        int err = evutil_socket_geterror(sock.sock);
        if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
            // nothing to do here
        } else {
            log_warn_printf(logio, "UDP TX Error on %s : %s\n", name.c_str(),
                       evutil_socket_error_to_string(err));
        }
        return false; // wait for more I/O
    }
    return size_t(ntx)==msglen;
}

UDPManager::Search::~Search() {}

}} // namespace pvxs::impl
