/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiSock.h>

#ifdef _WIN32
#  include <windows.h>
#  include <mswsock.h>
#endif

#include <cstring>
#include <system_error>
#include <deque>
#include <algorithm>

#include <event2/event.h>
#include <event2/thread.h>

#include <errlog.h>
#include <osiSock.h>
#include <epicsEvent.h>
#include <epicsThread.h>
#include <epicsExit.h>
#include <epicsMutex.h>
#include <epicsGuard.h>

#include "evhelper.h"
#include "pvaproto.h"
#include "utilpvt.h"
#include <pvxs/log.h>

typedef epicsGuard<epicsMutex> Guard;

// EvInBuf prefers to extract slices of this length from a backing buffer
static constexpr
size_t min_slice_size = 1024u;

namespace pvxs {namespace impl {

DEFINE_LOGGER(logerr, "pvxs.loop");

static
epicsThreadOnceId evthread_once = EPICS_THREAD_ONCE_INIT;

static
void evthread_init(void* unused)
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

struct ThreadEvent
{
    std::atomic<epicsThreadPrivateId> pvt{};

    static
    void destroy(void* raw)
    {
        delete static_cast<epicsEvent*>(raw);
    }

    epicsEvent* get()
    {
        epicsThreadPrivateId id = pvt.load();
        if(!id) {
            auto temp = epicsThreadPrivateCreate();
            if(pvt.compare_exchange_strong(id, temp)) {
                // stored
                id = temp;
            } else {
                // race
                epicsThreadPrivateDelete(temp);
                id = pvt.load();
            }
        }

        auto evt = static_cast<epicsEvent*>(epicsThreadPrivateGet(id));

        if(!evt) {
            evt = new epicsEvent();
            epicsThreadPrivateSet(id, evt);
            epicsAtThreadExit(destroy, evt);
        }

        return evt;
    }

    inline epicsEvent* operator->() { return get(); }
};

struct evbase::Pvt : public epicsThreadRunable
{
    SockAttach attach;

    struct Work {
        std::function<void()> fn;
        std::exception_ptr *result;
        epicsEvent *notify;
        Work(const std::function<void()>& fn, std::exception_ptr *result, epicsEvent *notify)
            :fn(fn), result(result), notify(notify)
        {}
    };
    std::deque<Work> actions;

    std::unique_ptr<event_base> base;
    evevent keepalive;
    evevent dowork;
    epicsEvent start_sync;
    epicsMutex lock;

    epicsThread worker;

    Pvt(const std::string& name, unsigned prio)
        :base(nullptr)
        ,worker(*this, name.c_str(),
                epicsThreadGetStackSize(epicsThreadStackBig),
                prio)
    {
        epicsThreadOnce(&evthread_once, &evthread_init, nullptr);

        worker.start();
        start_sync.wait();
        if(!base) {
            throw std::runtime_error("event_base_new() fails");
        }
    }

    virtual ~Pvt()
    {
        join();
    }

    void join()
    {
        if(worker.isCurrentThread())
            log_err_printf(logerr, "evbase self-joining: %s\n", worker.getNameSelf());
        if(event_base_loopexit(base.get(), nullptr))
            log_crit_printf(logerr, "evbase error while interrupting loop for %p\n", base.get());
        worker.exitWait();
    }

    virtual void run() override final
    {
        try {
            decltype (base) tbase(event_base_new());
            if(evthread_make_base_notifiable(tbase.get())) {
                throw std::runtime_error("evthread_make_base_notifiable");
            }

            evevent handle(event_new(tbase.get(), -1, EV_TIMEOUT, &doWorkS, this));
            evevent ka(event_new(tbase.get(), -1, EV_TIMEOUT|EV_PERSIST, &evkeepalive, this));

            base = std::move(tbase);
            dowork = std::move(handle);
            keepalive = std::move(ka);

            timeval tick{1000,0};
            if(event_add(keepalive.get(), &tick))
                throw std::runtime_error("Can't start keepalive timer");

            start_sync.signal();

            log_info_printf(logerr, "Enter loop worker for %p\n", base.get());

            int ret = event_base_loop(base.get(), 0);

            auto lvl = ret ? Level::Crit : Level::Info;
            log_printf(logerr, lvl, "Exit loop worker: %d for %p\n", ret, base.get());

        }catch(std::exception& e){
            log_exc_printf(logerr, "Unhandled exception in event_base run : %s\n",
                            e.what());
            start_sync.signal();
        }
    }

    void doWork()
    {
        decltype (actions) todo;
        {
            Guard G(lock);
            todo = std::move(actions);
        }
        for(auto& work : todo) {
            try {
                work.fn();
            }catch(std::exception& e){
                if(work.result) {
                    Guard G(lock);
                    *work.result = std::current_exception();
                } else {
                    log_exc_printf(logerr, "Unhandled exception in event_base : %s : %s\n",
                                    typeid(e).name(), e.what());
                }
            }
            if(work.notify)
                work.notify->signal();
        }
    }
    static
    void doWorkS(evutil_socket_t sock, short evt, void *raw)
    {
        auto self =static_cast<Pvt*>(raw);
        try {
            self->doWork();
        }catch(std::exception& e){
            log_exc_printf(logerr, "Unhandled error in doWorkS callback: %s\n", e.what());
        }
    }

    static
    void evkeepalive(evutil_socket_t sock, short evt, void *raw)
    {
        auto self = static_cast<Pvt*>(raw);
        log_debug_printf(logerr, "Look keepalive %p\n", self);
    }

};

evbase::evbase(const std::string &name, unsigned prio)
    :pvt(new Pvt(name, prio))
    ,base(pvt->base.get())
{}

evbase::~evbase() {}

void evbase::join()
{
    pvt->join();
}

void evbase::sync()
{
    call([](){});
}

void evbase::dispatch(std::function<void()>&& fn)
{
    bool empty;
    {
        Guard G(pvt->lock);
        empty = pvt->actions.empty();
        pvt->actions.emplace_back(std::move(fn), nullptr, nullptr);
    }

    timeval now{};
    if(empty && event_add(pvt->dowork.get(), &now))
        throw std::runtime_error("Unable to wakeup dispatch()");
}

void evbase::call(std::function<void()>&& fn)
{
    if(pvt->worker.isCurrentThread()) {
        fn();
        return;
    }

    static ThreadEvent done;

    std::exception_ptr result;
    bool empty;
    {
        Guard G(pvt->lock);
        empty = pvt->actions.empty();
        pvt->actions.emplace_back(std::move(fn), &result, done.get());
    }

    timeval now{};
    if(empty && event_add(pvt->dowork.get(), &now))
        throw std::runtime_error("Unable to wakeup call()");

    done->wait();
    Guard G(pvt->lock);
    if(result)
        std::rethrow_exception(result);
}

void evbase::assertInLoop()
{
    if(!pvt->worker.isCurrentThread()) {
        char name[32];
        pvt->worker.getName(name, sizeof(name));
        log_exc_printf(logerr, "Not in evbase working: \"%s\" != \"%s\"\n",
                       name, epicsThread::getNameSelf());
    }
}

bool evbase::inLoop()
{
    return pvt->worker.isCurrentThread();
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
        log_err_printf(logerr, "Unable to fetch address of newly bound socket\n%s", "");
}

void evsocket::mcast_join(const SockAddr& grp, const SockAddr& iface) const
{
    if(grp.family()!=iface.family() || grp.family()!=AF_INET)
        throw std::invalid_argument("Unsupported address family");

    ip_mreq req{};
    req.imr_multiaddr.s_addr = grp->in.sin_addr.s_addr;
    req.imr_interface.s_addr = iface->in.sin_addr.s_addr;

    int ret = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&req, sizeof(req));
    if(ret)
        log_err_printf(logerr, "Unable to join mcast group %s on %s : %s\n",
                   grp.tostring().c_str(), iface.tostring().c_str(),
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_ADD_MEMBERSHIP
}

void evsocket::mcast_ttl(unsigned ttl) const
{
    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl));
    if(ret)
        log_err_printf(logerr, "Unable to set mcast TTL : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // ipv6 variant?
}

void evsocket::mcast_loop(bool loop) const
{
    unsigned char val = loop ? 1 : 0;
    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&val, sizeof(val));
    if(ret)
        log_err_printf(logerr, "Unable to set mcast loopback : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_MULTICAST_LOOP
}

void evsocket::mcast_iface(const SockAddr& iface) const
{
    if(iface.family()!=AF_INET)
        throw std::invalid_argument("Unsupported address family");

    int ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface->in.sin_addr, sizeof(iface->in.sin_addr));
    if(ret)
        log_err_printf(logerr, "Unable to set mcast TTL : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    // IPV6_MULTICAST_IF
}
void to_wire(Buffer& buf, const SockAddr& val)
{
    if(!buf.ensure(16)) {
        buf.fault();
        return;

    } else if(val.family()==AF_INET) {
        for(unsigned i=0; i<10; i++)
            buf[i]=0;
        buf[10] = buf[11] = 0xff;

        memcpy(buf.save()+12, &val->in.sin_addr.s_addr, 4);

    } else if(val.family()==AF_INET6) {
        static_assert (sizeof(val->in6.sin6_addr)==16, "");
        memcpy(buf.save(), &val->in6.sin6_addr, 16);
    }
    buf._skip(16);
}

void from_wire(Buffer &buf, SockAddr& val)
{
    if(!buf.ensure(16)) {
        buf.fault();
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
        memcpy(&val->in.sin_addr.s_addr, buf.save()+12, 4);

    } else {
        val->in6 = {};
        val->in6.sin6_family = AF_INET6;

        static_assert (sizeof(val->in6.sin6_addr)==16, "");
        memcpy(&val->in6.sin6_addr, buf.save(), 16);
    }
    buf._skip(16);
}


bool Buffer::refill(size_t more) { return false; }

FixedBuf::~FixedBuf() {}

VectorOutBuf::~VectorOutBuf() {}

bool VectorOutBuf::refill(size_t more) {
    assert(pos <= limit);
    assert(pos >= backing.data());

    if(err) return false;

    more = ((more-1)|0xff)+1; // round up to multiple of 256
    size_t idx = pos - backing.data(); // save current offset
    try{
        backing.resize(backing.size()+more);
    }catch(std::bad_alloc& e) {
        return false;
    }
    pos = backing.data()+idx;
    limit = backing.data()+backing.size();
    return true;
}

EvOutBuf::~EvOutBuf() { refill(0); }

bool EvOutBuf::refill(size_t more)
{
    if(err) return false;

    evbuffer_iovec vec;
    vec.iov_base = base;
    vec.iov_len  = pos-base;

    if(base && evbuffer_commit_space(backing, &vec, 1))
        throw std::bad_alloc(); // leak?

    limit = base = pos = nullptr;

    if(more) {
        auto n = evbuffer_reserve_space(backing, more, &vec, 1);
        if(n!=1) {
            return false;
        }

        base = pos = (uint8_t*)vec.iov_base;
        limit = base+vec.iov_len;
    }
    return true;
}

EvInBuf::~EvInBuf() { refill(0); }

bool EvInBuf::refill(size_t needed)
{
    if(err) return false;

    // drain consumed
    if(base && evbuffer_drain(backing, pos-base))
        throw std::bad_alloc();

    limit = base = pos = nullptr;

    if(needed) {
        // expand request in an attempt to reduce the number of refill()s
        // but limit to actual backing buffer length, or pullup() will error
        size_t requesting = std::min(std::max(needed, size_t(min_slice_size)),
                                     evbuffer_get_length(backing));


        // ensure new segment contains at least the requested size (one element)
        // (we hope this is mostly a no-op)
        if(!evbuffer_pullup(backing, requesting)) {
            // a logic error in computing requesting?
            return false;
        }

        evbuffer_iovec vec;

        // peek at the next segment
        auto n = evbuffer_peek(backing, -1, nullptr, &vec, 1);
        if(n<=0) { // current (2.1) impl never returns negative
            return false;
        }

        base = pos = (uint8_t*)vec.iov_base;
        limit = base+vec.iov_len;

        if(size() < needed) {
            return false; // insufficient space
        }
    }
    return true;
}

void to_evbuf(evbuffer *buf, const Header& H, bool be)
{
    EvOutBuf M(be, buf, 8);
    to_wire(M, H);
    if(!M.good())
        throw std::bad_alloc();
}

}} // namespace pvxs::impl
