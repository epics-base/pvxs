/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifdef _WIN32
#include <mswsock.h>
#endif

#include <cstring>

#include <event2/event.h>
#include <event2/thread.h>

#include <errlog.h>
#include <osiSock.h>
#include <epicsEvent.h>
#include <epicsThread.h>

#include "evhelper.h"
#include "pvaproto.h"
#include <pvxs/log.h>

namespace pvxsimpl {

DEFINE_LOGGER(logerr, "evloop");

struct evbase::Pvt : public epicsThreadRunable
{
    event_base* base;
    epicsThread worker;

    Pvt()
        :base(nullptr)
        ,worker(*this, "UDP",
                epicsThreadGetStackSize(epicsThreadStackBig),
                epicsThreadPriorityCAServerLow-4)
    {
#if defined(EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED)
        evthread_use_windows_threads();

#elif defined(EVTHREAD_USE_PTHREADS_IMPLEMENTED)
        evthread_use_pthreads();

#else
#  error No threading support for this target
        // TODO fallback to libCom ?
#endif
    }

    virtual ~Pvt() {
        if(event_base_loopexit(base, nullptr))
            log_printf(logerr, PLVL_CRIT, "evbase error while interrupting loop for %p\n", base);
        worker.exitWait();
        event_base_free(base);
    }

    virtual void run() override final
    {
        log_printf(logerr, PLVL_INFO, "Enter loop worker for %p\n", base);

        int ret = event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);

        log_printf(logerr, ret ? PLVL_CRIT : PLVL_INFO, "Exit loop worker: %d for %p\n", ret, base);
    }
};

evbase::evbase()
    :pvt(new Pvt)
    ,base(event_base_new())
{
    if(!base) {
        throw std::runtime_error("event_base_new() fails");
    }
    if(evthread_make_base_notifiable(base)) {
        event_base_free(base);
        throw std::runtime_error("evthread_make_base_notifiable() fails");
    }
    pvt->base = base;
    log_printf(logerr, PLVL_INFO, "Starting loop worker for %p\n", base);
    pvt->worker.start();
}

evbase::~evbase()
{
}

static void evhelper_sync_done(evutil_socket_t _fd, short _ev, void *raw)
{
    epicsEvent *wait = static_cast<epicsEvent*>(raw);
    wait->signal();
}

void evbase::sync()
{
    assert(!pvt->worker.isCurrentThread());

    epicsEvent wait;

    if(event_base_once(base, (evutil_socket_t)-1, EV_TIMEOUT, &evhelper_sync_done, &wait, nullptr)!=0)
        throw std::runtime_error("event_base_once fails");

    wait.wait();
}

namespace {
void dispatch_action(evutil_socket_t _fd, short _ev, void *raw)
{
    try {
        // take ownership of raw
        std::unique_ptr<std::function<void()> > action(reinterpret_cast<std::function<void()>*>(raw));
        (*action)();
    }catch(std::exception& e){
        log_printf(logerr, PLVL_CRIT, "evhelper::call unhandled error: %s\n", e.what());
    }
}
}

void evbase::dispatch(std::function<void()>&& fn)
{
    std::unique_ptr<std::function<void()> > action(new std::function<void()>(std::move(fn)));

    if(event_base_once(base, -1, EV_TIMEOUT, &dispatch_action, action.get(), NULL)==0) {
        // successfully queued.  No longer my responsibility
        action.release();
    } else {
        throw std::runtime_error("Unable to queue dispatch()");
    }
}

namespace {
struct action_args {
    std::function<void()> fn;
    epicsEvent wait;
    std::exception_ptr err;
    action_args(std::function<void()>&& fn) :fn(std::move(fn)) {}
};

void call_action(evutil_socket_t _fd, short _ev, void *raw)
{
    action_args* args(reinterpret_cast<action_args*>(raw));
    try {
        try {
            args->fn();
        }catch(std::exception& e){
            args->err = std::current_exception();
        }
        args->wait.signal();
    }catch(std::exception& e){
        log_printf(logerr, PLVL_CRIT, "evhelper::call unhandled error: %s\n", e.what());
        args->wait.signal();
    }
}
}

void evbase::call(std::function<void()>&& fn)
{
    assert(!pvt->worker.isCurrentThread());

    action_args args(std::move(fn));

    if(event_base_once(base, -1, EV_TIMEOUT, &call_action, &args, NULL)==0) {
        // successfully queued.
        args.wait.wait();
        if(args.err) {
            std::rethrow_exception(args.err);
        }
    } else {
        throw std::runtime_error("Unable to queue call()");
    }
}

void evbase::assertInLoop()
{
    assert(pvt->worker.isCurrentThread());
}

evevent::evevent(struct event_base *base, evutil_socket_t sock, short mask, event_callback_fn fn, void *arg)
    :ev(event_new(base, sock, mask, fn, arg))
{
    if(!ev)
        throw std::bad_alloc();
    log_printf(logerr, PLVL_DEBUG, "Create event %p on %p for %d (%x)\n",
               ev, base, (int)sock, mask);
}

evevent::~evevent()
{
    if(ev) {
        log_printf(logerr, PLVL_DEBUG, "Destroy event %p\n", ev);
        event_free(ev);
    }
}

evevent::evevent(evevent&& o) noexcept
    :ev(o.ev)
{
    o.ev = nullptr;
}

evevent& evevent::operator=(evevent&& o) noexcept
{
    if(this!=&o) {
        if(ev)
            event_free(ev);
        ev = o.ev;
        o.ev = nullptr;
    }
    return *this;
}

void evevent::add(const struct timeval *tv)
{
    log_printf(logerr, PLVL_DEBUG, "Add event %p\n", ev);
    if(event_add(ev, tv))
        throw std::runtime_error("event_add() fails");
}

evsockaddr::evsockaddr(int af)
{
    memset(&store, 0, sizeof(store));
    store.sa.sa_family = af;
    if(af!=AF_INET && af!=AF_INET6 && af!=AF_UNSPEC)
        throw std::invalid_argument("Unsupported address family");
}

unsigned short evsockaddr::port() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return ntohs(store.in.sin_port);
    case AF_INET6:return ntohs(store.in6.sin6_port);
    default: return 0;
    }
}

void evsockaddr::setPort(unsigned short port)
{
    switch(store.sa.sa_family) {
    case AF_INET: store.in.sin_port = htons(port); break;
    case AF_INET6:store.in6.sin6_port = htons(port); break;
    default:
        throw std::logic_error("evsockaddr: set family before port");
    }
}

void evsockaddr::setAddress(const char *name)
{
    evsockaddr temp;
    int templen = sizeof(temp.store);
    if(evutil_parse_sockaddr_port(name, &temp->sa, &templen))
        throw std::runtime_error(std::string("Unable to parse as IP addresss: ")+name);
    (*this) = temp;
}

bool evsockaddr::isLO() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_LOOPBACK);
    case AF_INET6: return IN6_IS_ADDR_LOOPBACK(&store.in6.sin6_addr);
    default: return false;
    }
}

std::string evsockaddr::tostring() const
{
    std::ostringstream strm;
    strm<<(*this);
    return strm.str();
}

evsockaddr evsockaddr::any(int af, unsigned port)
{
    evsockaddr ret(af);
    switch(af) {
    case AF_INET:
        ret->in.sin_addr.s_addr = htonl(INADDR_ANY);
        ret->in.sin_port = htons(port);
        break;
    case AF_INET6:
        ret->in6.sin6_addr = IN6ADDR_ANY_INIT;
        ret->in6.sin6_port = htons(port);
        break;
    default:
        throw std::invalid_argument("Unsupported address family");
    }
    return ret;
}

evsockaddr evsockaddr::loopback(int af, unsigned port)
{
    evsockaddr ret(af);
    switch(af) {
    case AF_INET:
        ret->in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ret->in.sin_port = htons(port);
        break;
    case AF_INET6:
        ret->in6.sin6_addr = IN6ADDR_LOOPBACK_INIT;
        ret->in6.sin6_port = htons(port);
        break;
    default:
        throw std::invalid_argument("Unsupported address family");
    }
    return ret;
}

void to_wire(sbuf<uint8_t>& buf, const evsockaddr& val, bool be)
{
    if(buf.err || buf.size()<16) {
        buf.err = true;

    } else if(val.family()==AF_INET) {
        for(unsigned i=0; i<10; i++)
            buf[i]=0;
        buf[10] = buf[11] = 0xff;

        memcpy(buf.pos+12, &val->in.sin_addr.s_addr, 4);

    } else if(val.family()==AF_INET6) {
        static_assert (sizeof(val->in6.sin6_addr)==16, "");
        memcpy(buf.pos, &val->in6.sin6_addr, 16);
    }
    buf += 16;
}

void from_wire(sbuf<const uint8_t> &buf, evsockaddr& val, bool be)
{
    if(buf.err || buf.size()<16) {
        buf.err = true;
        return;
    }

    // win32 lacks IN6_IS_ADDR_V4MAPPED()
    bool ismapped = true;
    for(unsigned i=0u; i<10; i++)
        ismapped &= buf[i]==0;
    ismapped &= buf[10]==0xff;
    ismapped &= buf[11]==0xff;

    if(ismapped) {
        val->in = {};
        val->in.sin_family = AF_INET;
        memcpy(&val->in.sin_addr.s_addr, buf.pos+12, 4);

    } else {
        val->in6 = {};
        val->in6.sin6_family = AF_INET6;

        static_assert (sizeof(val->in6.sin6_addr)==16, "");
        memcpy(&val->in6.sin6_addr, buf.pos, 16);
    }
    buf += 16;
}

std::ostream& operator<<(std::ostream& strm, const evsockaddr& addr)
{
    switch(addr->sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN+1];
        if(evutil_inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf))) {
            buf[sizeof(buf)-1] = '\0'; // paranoia
        } else {
            strm<<"<\?\?\?>";
        }
        strm<<buf<<':'<<ntohs(addr->in.sin_port);
        break;
    }
    case AF_INET6: {
            char buf[INET6_ADDRSTRLEN+1];
            if(evutil_inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf))) {
                buf[sizeof(buf)-1] = '\0'; // paranoia
            } else {
                strm<<"<\?\?\?>";
            }
            strm<<buf<<':'<<ntohs(addr->in6.sin6_port);
            break;
    }
    case AF_UNSPEC:
        strm<<"<>";
        break;
    default:
        strm<<"<\?\?\?>";
    }
    return strm;
}

evsocket::evsocket(evutil_socket_t sock)
    :sock(sock)
{
    if(sock==evutil_socket_t(-1))
        throw std::bad_alloc();

    if(evutil_make_socket_nonblocking(sock)) {
        evutil_closesocket(sock);
        throw std::runtime_error("Unable to make non-blocking socket");
    }
}

evsocket::evsocket(int af, int type, int proto)
    :evsocket(socket(af, type, proto))
{}

evsocket::evsocket(evsocket&& o) noexcept
    :sock(o.sock)
{
    o.sock = evutil_socket_t(-1);
}

evsocket& evsocket::operator=(evsocket&& o) noexcept
{
    if(this!=&o) {
        if(sock!=evutil_socket_t(-1))
            evutil_closesocket(sock);
        sock = o.sock;
        o.sock = evutil_socket_t(-1);
    }
    return *this;
}

evsocket::~evsocket()
{
    if(sock!=evutil_socket_t(-1))
        evutil_closesocket(sock);
}

void evsocket::bind(evsockaddr& addr) const
{
    int ret = ::bind(sock, &addr->sa, sizeof(addr.store));
    if(ret!=0)
        throw std::runtime_error(SB()<<"Bind error to "<<addr<<" : "<<evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    socklen_t slen = sizeof(addr.store);
    ret = getsockname(sock, &addr->sa, &slen);
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to fetch address of newly bound socket\n");
}

void evsocket::mcast_join(const evsockaddr& grp, const evsockaddr& iface) const
{
    if(grp.family()!=iface.family() || grp.family()!=AF_INET)
        throw std::invalid_argument("Unsupported address family");

    ip_mreq req;
    req.imr_multiaddr.s_addr = grp->in.sin_addr.s_addr;
    req.imr_interface.s_addr = iface->in.sin_addr.s_addr;

    int ret = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&req, sizeof(req));
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to join mcast group %s on %s : %s\n",
                   grp.tostring().c_str(), iface.tostring().c_str(),
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_ADD_MEMBERSHIP
}

void evsocket::mcast_ttl(unsigned ttl) const
{
    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl));
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to set mcast TTL : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // ipv6 variant?
}

void evsocket::mcast_loop(bool loop) const
{
    unsigned char val = loop ? 1 : 0;
    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&val, sizeof(val));
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to set mcast loopback : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_MULTICAST_LOOP
}

void evsocket::mcast_iface(const evsockaddr& iface) const
{
    if(iface.family()!=AF_INET)
        throw std::invalid_argument("Unsupported address family");

    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface->in.sin_addr, sizeof(iface->in.sin_addr));
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to set mcast TTL : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_MULTICAST_IF
}


void from_wire(sbuf<const uint8_t>& buf, Size<size_t> size, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;
        return;
    }
    uint8_t s=buf[0];
    buf+=1;
    if(s<254) {
        *size.size = s;

    } else if(s==255) {
        // "null" size.  not sure it is used.  Replicate weirdness of pvDataCPP
        *size.size = -1;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls, be);
        *size.size = ls;
    } else {
        // unreachable
        buf.err = true;
    }
}

} // namespace pvxsimpl
