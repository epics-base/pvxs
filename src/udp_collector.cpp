/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
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

struct UDPCollector : public std::enable_shared_from_this<UDPCollector>
{
    const std::shared_ptr<UDPManager::Pvt> manager;
    evsockaddr bind_addr;
    std::string name;
    evsocket sock;
    evevent rx;

    std::vector<uint8_t> buf;
    std::vector<sbuf<const uint8_t> > msgs;
    UDPMsg msg;

    std::set<UDPListener*> listeners;

    UDPCollector(const std::shared_ptr<UDPManager::Pvt>& manager, const evsockaddr& bind_addr);
    ~UDPCollector();

    void handle(short ev)
    {
        log_printf(logio, PLVL_DEBUG, "UDP %p event %x\n", rx.ev, ev);
        if(!(ev&EV_READ))
            return;

        for(unsigned i=0; i<4; i++)
        {
            osiSocklen_t alen = sizeof(msg.src->ss);

            const int nrx = recvfrom(sock.sock, (char*)&buf[0], buf.size(), 0, &msg.src->sa, &alen);
            log_printf(logio, PLVL_DEBUG, "recvfrom() -> %d\n", nrx);

            if(nrx<0) {
                int err = evutil_socket_geterror(sock.sock);
                if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
                    // nothing to do here
                } else {
                    log_printf(logio, PLVL_WARN, "UDP RX Error on %s : %s\n", name.c_str(),
                               evutil_socket_error_to_string(err));
                }
                return; // wait for more I/O

            } else if(nrx==0) {
                // maybe a zero (body) length packet?
                // maybe an OS error?
                return;
            }

            msgs.clear();

            sbuf<const uint8_t> packet(&buf[0], size_t(nrx));

            while(!packet.empty() && !packet.err) {
                // do validation early, before fanout.

                // minimum header size is 8 bytes
                // ID byte must by 0xCA (because PVA has some paternal envy)
                // ignore incompatible version 0
                // UDP packets can't contain control messages, or use segmentation

                if(packet.size()<8) {
                    log_printf(logio, PLVL_INFO, "UDP ignore runt on %s\n", name.c_str());
                    return;

                } else if(packet[0]!=0xca || packet[1]==0 || (packet[2]&(pva_flags::Control|pva_flags::SegMask))) {

                    log_printf(logio, PLVL_INFO, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                               unsigned(packet.size()), packet[0], packet[1], packet[2], packet[3],
                            name.c_str());
                    return; // better luck next time?
                }

                auto save = packet;

                bool be = packet[2]&pva_flags::MSB;
                packet += 4;
                uint32_t len=0;
                from_wire(packet, len, be);

                if(len > packet.size() && !packet.err) {
                    log_printf(logio, PLVL_INFO, "UDP ignore header%u %02x%02x%02x%02x on %s\n",
                               unsigned(packet.size()), packet[0], packet[1], packet[2], packet[3],
                            name.c_str());
                    return;
                }
                msgs.push_back(save);
                packet += len;
            }

            if(packet.err) {
                log_printf(logio, PLVL_WARN, "UDP packet decode fails.  Ignoring\n");

            } else if(!msgs.empty()) {
                msgs.emplace_back(nullptr, 0);
                msg.msgs = &msgs[0];

                for(auto L : listeners)
                {
                    if(!L->cb)
                        continue;
                    try {
                        (L->cb)(msg);
                    }catch(std::exception& e){
                        log_printf(logio, PLVL_ERR, "Error in callback: %s\n", e.what());
                    }
                }
            }
        }

    }
    static void handle_static(evutil_socket_t fd, short ev, void *raw)
    {
        (void)fd;
        static_cast<UDPCollector*>(raw)->handle(ev);
    }
};


struct UDPManager::Pvt : public std::enable_shared_from_this<Pvt> {

    evbase loop;

    // only manipulate from loop worker thread
    std::map<evsockaddr, UDPCollector*> collectors;

    Pvt()
    {}
    ~Pvt()
    {
        // we should only be destroyed after that last collector has removed itself
        assert(collectors.empty());
    }
};

UDPCollector::UDPCollector(const std::shared_ptr<UDPManager::Pvt>& manager, const evsockaddr& bind_addr)
    :manager(manager)
    ,bind_addr(bind_addr)
    ,sock(bind_addr.family(), SOCK_DGRAM, 0)
    ,rx(manager->loop.base, sock.sock, EV_READ|EV_PERSIST, &handle_static, this)
    ,buf(0x10000)
    ,msg(this)
{
    epicsSocketEnableAddressUseForDatagramFanout(sock.sock);
    sock.bind(this->bind_addr);
    name = "UDP "+this->bind_addr.tostring();

    log_printf(logsetup, PLVL_INFO, "Bound to %s\n", name.c_str());

    rx.add();
}

UDPCollector::~UDPCollector()
{
    // we should only be destroyed after that last listener has removed itself
    assert(listeners.empty());
    manager->loop.assertInLoop();
}

static epicsMutex* inst_lock;
std::weak_ptr<UDPManager::Pvt> UDPManager::inst;

UDPManager::~UDPManager() {}

namespace {
epicsThreadOnceId collector_once = EPICS_THREAD_ONCE_INIT;
void collector_init(void *unused)
{
    (void)unused;
    inst_lock = new epicsMutex;
}
} // namespace

UDPManager UDPManager::instance()
{
    epicsThreadOnce(&collector_once, &collector_init, nullptr);
    assert(inst_lock);

    Guard G(*inst_lock);

    auto ret = inst.lock();

    if(!ret) {
        ret.reset(new UDPManager::Pvt);
        inst = ret;
    }

    return UDPManager(ret);
}

std::unique_ptr<UDPListener> UDPManager::subscribe(evsockaddr& dest,
                                                   std::function<void(const UDPMsg& msg)>&& cb)
{
    if(!pvt)
        throw std::invalid_argument("UDPManager null");

    std::unique_ptr<UDPListener> ret;

    pvt->loop.call([this, &ret, &dest, &cb](){
        // from event loop worker

        ret.reset(new UDPListener);
        ret->cb = std::move(cb);

        if(dest.port()!=0) {
            auto it = pvt->collectors.find(dest);
            if(it!=pvt->collectors.end()) {
                try {
                    ret->collector = it->second->shared_from_this();
                }catch(std::bad_weak_ptr&){
                    // nothing to do
                }
            }
        }

        if(!ret->collector) {
            ret->collector.reset(new UDPCollector(pvt->shared_from_this(), dest));
        }

        ret->collector->listeners.insert(ret.get());

        ret->dest = dest;
    });

    return ret;
}

UDPListener::~UDPListener()
{
    cancel();
}

void UDPListener::cancel()
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

UDPMsg::UDPMsg(UDPCollector *collector)
    :collector(collector)
{}

bool UDPMsg::reply(const void *msg, size_t msglen) const
{
    int ntx = sendto(collector->sock.sock, (char*)msg, msglen, 0, &src->sa, sizeof(src->ss));
    if(ntx<0) {
        int err = evutil_socket_geterror(collector->sock.sock);
        if(err==SOCK_EWOULDBLOCK || err==EAGAIN || err==SOCK_EINTR) {
            // nothing to do here
        } else {
            log_printf(logio, PLVL_WARN, "UDP TX Error on %s : %s\n", collector->name.c_str(),
                       evutil_socket_error_to_string(err));
        }
        return false; // wait for more I/O
    }
    return size_t(ntx)==msglen;
}

} // namespace pvxsimpl
