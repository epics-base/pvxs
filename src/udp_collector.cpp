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


namespace pvxsimpl {

DEFINE_LOGGER(logio, "udp.io");
DEFINE_LOGGER(logsetup, "udp.setup");

struct UDPListener : public std::enable_shared_from_this<UDPListener>
{
    std::function<void(UDPManager::Search&)> searchCB;
    std::function<void(UDPManager::Beacon&)> beaconCB;
    std::shared_ptr<UDPCollector> collector;
    const SockAddr dest;
    UDPListener(UDPManager::Pvt *manager, SockAddr& dest);
    ~UDPListener();
};

struct UDPCollector : public UDPManager::Search,
                      public std::enable_shared_from_this<UDPCollector>
{
    const std::shared_ptr<UDPManager::Pvt> manager;
    SockAddr bind_addr;
    std::string name;
    evsocket sock;
    evevent rx;

    std::vector<uint8_t> buf;

    UDPManager::Beacon beaconMsg;

    std::set<UDPListener*> listeners;

    UDPCollector(const std::shared_ptr<UDPManager::Pvt>& manager, const SockAddr& bind_addr);
    ~UDPCollector();

    bool handle_one()
    {
        osiSocklen_t alen = src.size();

        // For Search messages, we use PV name strings in-place by adding nils.
        // Ensure one extra byte at the end of the buffer for a nil after the last PV name
        const int nrx = recvfrom(sock.sock, (char*)&buf[0], buf.size()-1, 0, &src->sa, &alen);

        if(nrx<0) {
            int err = evutil_socket_geterror(sock.sock);
            if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
                // nothing to do here
            } else {
                log_printf(logio, PLVL_WARN, "UDP RX Error on %s : %s\n", name.c_str(),
                           evutil_socket_error_to_string(err));
            }
            return false; // wait for more I/O

        } else if(nrx<8) {
            // maybe a zero (body) length packet?
            // maybe an OS error?

            log_printf(logio, PLVL_INFO, "UDP ignore runt on %s\n", name.c_str());
            return true;

        } else if(buf[0]!=0xca || buf[1]==0 || (buf[2]&(pva_flags::Control|pva_flags::SegMask))) {
            // minimum header size is 8 bytes
            // ID byte must by 0xCA (because PVA has some paternal envy)
            // ignore incompatible version 0
            // UDP packets can't contain control messages, or use segmentation

            log_printf(logio, PLVL_INFO, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                       unsigned(nrx), buf[0], buf[1], buf[2], buf[3],
                    name.c_str());
            return true;
        }

        log_hex_printf(logio, PLVL_DEBUG, &buf[0], nrx, "UDP Rx %d from %s\n", nrx, src.tostring().c_str());

        names.clear();

        sbuf<uint8_t> M(&buf[0], size_t(nrx));

        uint8_t cmd = M[3];

        bool be = M[2]&pva_flags::MSB;
        M += 4;
        uint32_t len=0;
        from_wire(M, len, be);

        if(len > M.size() && !M.err) {
            log_printf(logio, PLVL_INFO, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                       unsigned(M.size()), M[0], M[1], M[2], M[3],
                    name.c_str());
            return true;
        }

        switch(cmd) {

        case pva_app_msg::Search: {
            uint32_t id;
            SockAddr replyAddr;

            from_wire(M, id, be);
            M += 4; // flags and unused/reserved

            from_wire(M, replyAddr, be);
            uint16_t port = 0;
            from_wire(M, port, be);
            replyAddr.setPort(port);

            // so far, only "tcp" transport has ever been seen.
            // however, we will consider and ignore any others which might appear
            bool foundtcp = false;
            size_t nproto=0;
            from_wire(M, Size<size_t>(nproto), be);
            for(size_t i=0; i<nproto && !M.err; i++) {
                size_t nchar=0;
                from_wire(M, Size<size_t>(nchar), be);

                if(M.size()>=3 && nchar==3 && M[0]=='t' && M[1]=='c' && M[2]=='p') {
                    foundtcp = true;
                    M += 3;
                    break;
                }
            }
            if(!foundtcp && !M.err) {
                // so far, not something which should actually happen
                log_printf(logio, PLVL_DEBUG, "  Search w/o proto \"tcp\"\n");
                return true;
            }

            // one Search message can include many PV names.
            uint16_t nchan=0;
            from_wire(M, nchan, be);

            names.clear();
            names.reserve(nchan);

            for(size_t i=0; i<nchan && !M.err; i++) {
                uint32_t id=0xffffffff; // poison
                size_t chlen;

                auto mundge = M.pos;
                from_wire(M, id, be);
                from_wire(M, Size<size_t>(chlen), be);
                // inject nil for previous PV name
                *mundge = '\0';
                if(chlen<=M.size() && !M.err) {
                    names.push_back(reinterpret_cast<const char*>(M.pos));
                }
                M += chlen;
            }

            if(!M.err) {
                // ensure nil for final PV name
                *M.pos = '\0';

                for(auto L : listeners) {
                    if(L->searchCB) {
                        (L->searchCB)(*this);
                    }
                }
            }

            break;
        }

        case pva_app_msg::Beacon: {
            uint16_t port = 0;

            _from_wire<12>(M, &beaconMsg.guid[0], false);
            M += 4; // skip flags, seq, and change count.  unused
            from_wire(M, beaconMsg.server, be);
            from_wire(M, port, be);
            beaconMsg.server.setPort(port);

            size_t protolen=0;
            from_wire(M, Size<size_t>(protolen), be);
            M += protolen; // ignore string

            // ignore remaining "server status" blob

            if(!M.err) {
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
        log_printf(logio, PLVL_DEBUG, "UDP %p event %x\n", rx.get(), ev);
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
            log_printf(logio, PLVL_CRIT, "Ignoring unhandled exception in UDPManager::handle(): %s\n", e.what());
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
    beaconMsg.guid.resize(12);

    epicsSocketEnableAddressUseForDatagramFanout(sock.sock);
    sock.bind(this->bind_addr);
    name = "UDP "+this->bind_addr.tostring();

    log_printf(logsetup, PLVL_INFO, "Bound to %s\n", name.c_str());

    if(event_add(rx.get(), nullptr))
        throw std::runtime_error("Unable to create collector Rx event");
}

UDPCollector::~UDPCollector()
{
    // we should only be destroyed after that last listener has removed itself
    assert(listeners.empty());
    manager->loop.assertInLoop();
}

static struct udp_gbl_t {
    epicsMutex lock;
    std::weak_ptr<UDPManager::Pvt> inst;
} *udp_gbl;

UDPManager::~UDPManager() {}

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

    collector->listeners.insert(this);
}

UDPListener::~UDPListener()
{
    if(!collector)
        return;

    auto manager = collector->manager;
    manager->loop.call([this](){
        // from event loop worker

        collector->listeners.erase(this);

        collector.reset(); // destroy UDPCollector from worker
    });
    // UDPManager may be destroyed at this point, which joins its event loop worker
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
            log_printf(logio, PLVL_WARN, "UDP TX Error on %s : %s\n", name.c_str(),
                       evutil_socket_error_to_string(err));
        }
        return false; // wait for more I/O
    }
    return size_t(ntx)==msglen;
}

UDPManager::Search::~Search() {}

} // namespace pvxsimpl

namespace std {
void default_delete<pvxsimpl::UDPListener>::operator()(pvxsimpl::UDPListener* listener) {
    delete listener;
};
} // namespace std
