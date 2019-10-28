/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifdef _WIN32
#include <mswsock.h>
#endif

#include <cstring>
#include <system_error>

#include <event2/event.h>
#include <event2/thread.h>

#include <errlog.h>
#include <osiSock.h>
#include <epicsEvent.h>
#include <epicsThread.h>

#include "evhelper.h"
#include "pvaproto.h"
#include "utilpvt.h"
#include <pvxs/log.h>

namespace pvxsimpl {

DEFINE_LOGGER(logerr, "evloop");

struct evbase::Pvt : public epicsThreadRunable
{
    event_base* base;
    epicsThread worker;

    Pvt(const std::string& name, unsigned prio)
        :base(nullptr)
        ,worker(*this, name.c_str(),
                epicsThreadGetStackSize(epicsThreadStackBig),
                prio)
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

evbase::evbase(const std::string &name, unsigned prio)
    :pvt(new Pvt(name, prio))
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
        log_printf(logerr, PLVL_CRIT, "evhelper::call unhandled error %s : %s\n", typeid(&e).name(), e.what());
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

bool evbase::inLoop()
{
    return pvt->worker.isCurrentThread();
}

void to_wire(sbuf<uint8_t>& buf, const SockAddr &val, bool be)
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

void evsocket::bind(SockAddr& addr) const
{
    int ret = ::bind(sock, &addr->sa, addr.size());
    if(ret!=0) {
        int err = evutil_socket_geterror(sock);
        throw std::system_error(err, std::system_category());
    }

    socklen_t slen = addr.size();
    ret = getsockname(sock, &addr->sa, &slen);
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to fetch address of newly bound socket\n");
}

void evsocket::mcast_join(const SockAddr& grp, const SockAddr& iface) const
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

void evsocket::mcast_iface(const SockAddr& iface) const
{
    if(iface.family()!=AF_INET)
        throw std::invalid_argument("Unsupported address family");

    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface->in.sin_addr, sizeof(iface->in.sin_addr));
    if(ret)
        log_printf(logerr, PLVL_ERR, "Unable to set mcast TTL : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_MULTICAST_IF
}


void from_wire(sbuf<const uint8_t>& buf, Size& size, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;
        return;
    }
    uint8_t s=buf[0];
    buf+=1;
    if(s<254) {
        size.size = s;

    } else if(s==255) {
        // "null" size.  not sure it is used.  Replicate weirdness of pvDataCPP
        size.size = -1;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls, be);
        size.size = ls;
    } else {
        // unreachable
        buf.err = true;
    }
}

} // namespace pvxsimpl
