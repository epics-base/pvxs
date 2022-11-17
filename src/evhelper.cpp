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
#include <epicsEvent.h>
#include <epicsThread.h>
#include <epicsExit.h>
#include <epicsMutex.h>
#include <epicsGuard.h>
#include <dbDefs.h>
#include <ellLib.h>

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
DEFINE_LOGGER(logtimer, "pvxs.timer");
DEFINE_LOGGER(logiface, "pvxs.iface");
DEFINE_LOGGER(logsock, "pvxs.sock");

namespace mdetail {
VFunctor0::~VFunctor0() {}
}

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
                assert(id);
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

    std::weak_ptr<Pvt> internal_self;

    struct Work {
        mfunction fn;
        std::exception_ptr *result;
        epicsEvent *notify;
        Work(mfunction&& fn, std::exception_ptr *result, epicsEvent *notify)
            :fn(std::move(fn)), result(result), notify(notify)
        {}
    };
    std::deque<Work> actions;

    owned_ptr<event_base> base;
    evevent keepalive;
    evevent dowork;
    epicsEvent start_sync;
    epicsMutex lock;

    epicsThread worker;
    bool running = true;

    INST_COUNTER(evbase);

    Pvt(const std::string& name, unsigned prio)
        :worker(*this, name.c_str(),
                epicsThreadGetStackSize(epicsThreadStackBig),
                prio)
    {
        threadOnce(&evthread_once, &evthread_init, nullptr);

        worker.start();
        start_sync.wait();
        if(!base) {
            throw std::runtime_error("event_base_new() fails");
        }
    }

    virtual ~Pvt() {}

    void join()
    {
        {
            Guard G(lock);
            running = false;
        }
        if(worker.isCurrentThread())
            log_crit_printf(logerr, "evbase self-joining: %s\n", worker.getNameSelf());
        if(event_base_loopexit(base.get(), nullptr))
            log_crit_printf(logerr, "evbase error while interrupting loop for %p\n", base.get());
        worker.exitWait();
    }

    virtual void run() override final
    {
        INST_COUNTER(evbaseRunning);
        try {
            evconfig conf(event_config_new());
#ifdef __rtems__
            /* with libbsd circa RTEMS 5.1
             * TCP peer close/reset notifications appear to be lost.
             * Maybe due to absence of NOTE_EOF?
             * poll() seems to work though.
             */
            event_config_avoid_method(conf.get(), "kqueue");
#endif
            decltype (base) tbase(event_base_new_with_config(conf.get()));
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

            log_info_printf(logerr, "Enter loop worker for %p using %s\n", base.get(), event_base_get_method(base.get()));

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
                auto fn(std::move(work.fn));
                fn();
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
{
    auto internal(std::make_shared<Pvt>(name, prio));
    internal->internal_self = internal;

    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        auto temp(std::move(internal));
        temp->join();
    });

    base = pvt->base.get();
}

evbase::~evbase() {}

evbase evbase::internal() const
{
    evbase ret;
    ret.pvt = decltype(pvt)(pvt->internal_self);
    ret.base = base;
    return ret;
}

void evbase::join() const
{
    pvt->join();
}

void evbase::sync() const
{
    call([](){});
}

bool evbase::_dispatch(mfunction&& fn, bool dothrow) const
{
    bool empty;
    {
        Guard G(pvt->lock);
        if(!pvt->running) {
            if(dothrow)
                throw std::logic_error("Worker stopped");
            return false;
        }
        empty = pvt->actions.empty();
        pvt->actions.emplace_back(std::move(fn), nullptr, nullptr);
    }

    timeval now{};
    if(empty && event_add(pvt->dowork.get(), &now))
        throw std::runtime_error("Unable to wakeup dispatch()");

    return true;
}

bool evbase::_call(mfunction&& fn, bool dothrow) const
{
    if(pvt->worker.isCurrentThread()) {
        fn();
        return true;
    }

    static ThreadEvent done;

    std::exception_ptr result;
    bool empty;
    {
        Guard G(pvt->lock);
        if(!pvt->running) {
            if(dothrow)
                throw std::logic_error("Worker stopped");
            return false;
        }
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
    return true;
}

void evbase::assertInLoop() const
{
    if(!pvt->worker.isCurrentThread()) {
        char name[32];
        pvt->worker.getName(name, sizeof(name));
        log_exc_printf(logerr, "Not in evbase working: \"%s\" != \"%s\"\n",
                       name, epicsThread::getNameSelf());
    }
}

bool evbase::assertInRunningLoop() const
{
    if(pvt->worker.isCurrentThread())
        return true;

    Guard G(pvt->lock);
    if(!pvt->running)
        return false;

    char name[32];
    pvt->worker.getName(name, sizeof(name));
    log_exc_printf(logerr, "Not in running evbase worker: \"%s\" != \"%s\"\n",
                   name, epicsThread::getNameSelf());
    throw std::logic_error("Not in running evbase worker");
}

bool evsocket::canIPv6;
evsocket::ipstack_t evsocket::ipstack;

evsocket::evsocket(int af, evutil_socket_t sock)
    :sock(sock)
    ,af(af)
{
    if(sock==evutil_socket_t(-1)) {
        int err = evutil_socket_geterror(sock);
#ifdef _WIN32
        if(err==WSANOTINITIALISED) {
            throw std::runtime_error("WSANOTINITIALISED");
        }
#endif
        throw std::system_error(err, std::system_category());
    }
    if(af!=AF_INET && af!=AF_INET6) {
        evutil_closesocket(sock);
        throw std::logic_error("Unsupported address family");
    }

    evutil_make_socket_closeonexec(sock);

    if(evutil_make_socket_nonblocking(sock)) {
        evutil_closesocket(sock);
        throw std::runtime_error("Unable to make non-blocking socket");
    }
}

// Linux specific way to atomically create a socket with O_CLOEXEC
#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC 0
#endif

evsocket::evsocket(int af, int type, int proto)
    :evsocket(af, socket(af, type | SOCK_CLOEXEC, proto))
{
#ifdef __linux__
#  ifndef IP_MULTICAST_ALL
#    define IP_MULTICAST_ALL		49
#  endif
    // Disable non-compliant legacy behavior of Linux IP stack
    if(af==AF_INET && type==SOCK_DGRAM){
        int val = 0;
        if(setsockopt(sock, IPPROTO_IP, IP_MULTICAST_ALL, (char*)&val, sizeof(val))) {
            log_warn_printf(logerr, "Unable to clear IP_MULTICAST_ALL (err=%d).  This may cause problems on multi-homed hosts.\n",
                            evutil_socket_geterror(sock));
        }
    }
#endif
}

evsocket::evsocket(evsocket&& o) noexcept
    :sock(o.sock)
    ,af(o.af)
{
    o.sock = evutil_socket_t(-1);
    o.af = AF_UNSPEC;
}

evsocket& evsocket::operator=(evsocket&& o) noexcept
{
    if(this!=&o) {
        if(sock!=evutil_socket_t(-1))
            evutil_closesocket(sock);
        sock = o.sock;
        af = o.af;
        o.sock = evutil_socket_t(-1);
        o.af = AF_UNSPEC;
    }
    return *this;
}

evsocket::~evsocket()
{
    if(sock!=evutil_socket_t(-1))
        evutil_closesocket(sock);
}

SockAddr evsocket::sockname() const
{
    SockAddr addr;
    socklen_t slen = addr.size();
    if(getsockname(sock, &addr->sa, &slen))
        std::logic_error("Unable to fetch address of newly bound socket");
    return addr;
}

void evsocket::bind(const SockAddr& addr) const
{
    int ret = ::bind(sock, &addr->sa, addr.size());
    if(ret!=0) {
        int err = evutil_socket_geterror(sock);
        throw std::system_error(err, std::system_category());
    }
}

void evsocket::bind(SockAddr& addr) const
{
    const SockAddr& arg = addr;
    bind(arg);
    addr = sockname();
}

void evsocket::listen(int backlog) const
{
    if(::listen(sock, backlog)) {
        int err = evutil_socket_geterror(sock);
        throw std::system_error(err, std::system_category());
    }
}

void evsocket::set_broadcast(bool b) const
{
    int val = b;
    if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&val, sizeof(val)))
        log_err_printf(logerr, "Unable to setup beacon sender SO_BROADCAST: %d\n", SOCKERRNO);
}

#ifndef IPV6_ADD_MEMBERSHIP
#  define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#ifndef IPV6_DROP_MEMBERSHIP
#  define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif

bool evsocket::mcast_join(const MCastMembership& m) const
{
    if(m.af==AF_INET) {
        auto& req = m.req.in;

        if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&req, sizeof(req))) {
            log_err_printf(logerr, "Unable to join mcast4 group: %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));
            return false;
        }

    } else if(m.af==AF_INET6) {
        auto& req = m.req.in6;

        if(setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*)&req, sizeof(req))) {
            log_err_printf(logerr, "Unable to join mcast6 group : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));
            return false;
        }
    }
    return true;
}

void evsocket::mcast_leave(const MCastMembership &m) const
{
    if(m.af==AF_INET) {
        if(setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&m.req.in, sizeof(m.req.in)))
            log_err_printf(logerr, "Unable to leave mcast4 group: %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    } else if(m.af==AF_INET6) {
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char*)&m.req.in6, sizeof(m.req.in6)))
            log_err_printf(logerr, "Unable to leave mcast6 group: %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));
    }
}

void evsocket::mcast_prep_sendto(const SockEndpoint& ep) const
{
    if(ep.addr.family()!=af)
        throw std::logic_error("Inconsistent address family");

    else if(!ep.addr.isMCast())
        return;

    auto& ifmap = IfaceMap::instance();

    if(af==AF_INET) {
        SockAddr iface(AF_INET);
        if(!ep.iface.empty())
            iface = ifmap.address_of(ep.iface);

        if(setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ep.ttl, sizeof(ep.ttl)))
            log_err_printf(logerr, "Unable to set mcast TTL : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));

        if(setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface->in.sin_addr, sizeof(iface->in.sin_addr)))
            log_err_printf(logerr, "Unable to set mcast IF : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    } else if(af==AF_INET6) {
        int index = 0u;
        if(!ep.iface.empty())
            index = ifmap.index_of(ep.iface);

        if(setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&ep.ttl, sizeof(ep.ttl)))
            log_err_printf(logerr, "Unable to set mcast TTL : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));

        if(setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&index, sizeof(index)))
            log_err_printf(logerr, "Unable to set mcast IF : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));
    }
}

void evsocket::mcast_loop(bool loop) const
{
    /* On Linux (at least) IP_MULTICAST_LOOP is not exactly equivalent to IPV6_MULTICAST_LOOP,
     * and we are allowed to set both.  So we do...
     */
    if(af==AF_INET || af==AF_INET6) {
        unsigned char val = loop ? 1 : 0;
        if(setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&val, sizeof(val)))
            log_err_printf(logerr, "Unable to set mcast loopback4 : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));

    }
    if(af==AF_INET6) {
        unsigned int val = loop ? 1 : 0;
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char*)&val, sizeof(val)))
            log_err_printf(logerr, "Unable to set mcast loopback6 : %s\n",
                       evutil_socket_error_to_string(evutil_socket_geterror(sock)));
    }
}

void evsocket::ipv6_only(bool b) const
{
    if(af!=AF_INET6)
        throw std::invalid_argument("Unsupported address family");

    int v=b;
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v, sizeof(v)))
        log_err_printf(logerr, "Unable to set IPv6 only : %s\n",
                   evutil_socket_error_to_string(evutil_socket_geterror(sock)));
}

std::vector<SockAddr> evsocket::broadcasts(const SockAddr* match) const
{
    if(match && match->family()!=AF_INET) {
        throw std::logic_error("osiSockDiscoverBroadcastAddresses() only understands AF_INET");
    }

    std::vector<SockAddr> ret;
    if(af==AF_INET6)
        return ret; // IPv6 does not have broadcast addresses

    evsocket dummy(AF_INET, SOCK_DGRAM, 0);

    osiSockAddr realmatch;
    if(match) {
        memcpy(&realmatch.ia, &(*match)->in, sizeof(realmatch.ia));
    } else {
        realmatch.ia.sin_family = AF_INET;
        realmatch.ia.sin_addr.s_addr = htonl(INADDR_ANY);
        realmatch.ia.sin_port = 0;
    }

    ELLLIST bcasts = ELLLIST_INIT;
    osiSockDiscoverBroadcastAddresses(&bcasts, dummy.sock, &realmatch);

    ret.reserve(ellCount(&bcasts));

    while(ellCount(&bcasts)) {
        auto cur = ellFirst(&bcasts);
        ellDelete(&bcasts, cur);
        osiSockAddrNode *node = CONTAINER(cur, osiSockAddrNode, node);
        if(node->addr.sa.sa_family==AF_INET)
            ret.emplace_back(&node->addr.sa);
        free(node);
    }

    return ret;
}

size_t evsocket::get_buffer_size(evutil_socket_t sock, bool tx)
{
    unsigned ret;
    socklen_t len(sizeof(ret));
    auto err = getsockopt(sock, SOL_SOCKET, tx ? SO_SNDBUF : SO_RCVBUF, (char*)&ret, &len);
    if(err<0 || len!=sizeof(ret)) {
        int err = evutil_socket_geterror(sock);
        throw std::system_error(err, std::system_category());
    }
    return ret;
}

#if defined(_WIN32) && !defined(EAFNOSUPPORT)
#  define EAFNOSUPPORT WSAESOCKTNOSUPPORT
#endif

bool evsocket::init_canIPv6()
{
    try {
        evsocket sock(AF_INET6, SOCK_DGRAM, 0);
        auto addr(SockAddr::loopback(AF_INET6));
        sock.bind(addr);
        return true;

    }catch(std::system_error& e){
        auto err = e.code().value(); // errno
        switch(err) {
        case EAFNOSUPPORT: // socket() fails.  OS kernel not built with IPv6 support
        case SOCK_EADDRNOTAVAIL:// bind() fails.  Missing [::1].  Incomplete IPv6 config
            break;
        default:
            log_warn_printf(logsock, "Unexpected errno %d while probing IPv6: %s\n",
                            err, evutil_socket_error_to_string(err));
            break;
        }
        return false;
    }
}

#if EPICS_VERSION_INT<VERSION_INT(7,0,3,1)
#  define getMonotonic getCurrent
#endif

static epicsThreadOnceId mapOnce = EPICS_THREAD_ONCE_INIT;

static IfaceMap* theinstance;

static
void mapInit(void*)
{
    theinstance = new IfaceMap();
}

IfaceMap& IfaceMap::instance()
{
    threadOnce(&mapOnce, &mapInit);
    assert(theinstance);
    return *theinstance;
}

void IfaceMap::cleanup()
{
    delete theinstance;
    theinstance = nullptr;
}

IfaceMap::IfaceMap()
{
    refresh();
}

void IfaceMap::refresh(bool force)
{
    auto now(epicsTime::getMonotonic());
    auto age = now-updated;
    double threshold = force ? 10.0 : 600.0; // TODO: configurable?
    if(age<threshold && !byIndex.empty())
        return;
    log_debug_printf(logiface, "refresh%s after %.1f sec\n", force?" forced":"", age);
    auto temp = _refresh();
    // cross-index
    decltype (byName) tempN;
    decltype (byAddr) tempA;
    for(auto& pair : temp) {
        auto& iface = pair.second;
        tempN[iface.name] = &iface;
        for(auto& pair : iface.addrs) {
            tempA.emplace(pair.first, std::make_pair(&iface, false));
            if(pair.second.family()==AF_INET)
                tempA.emplace(pair.second, std::make_pair(&iface, true));
        }
    }
    byIndex.swap(temp);
    byName.swap(tempN);
    byAddr.swap(tempA);
    updated = now;
}

namespace {

template<typename FN>
bool try_cache(IfaceMap& self, FN&& fn)
{
    bool force = false;
retry:
    self.refresh(force);
    bool found = fn();
    if(!found && !force) {
        force = true;
        goto retry;
    }
    return found;
}

} // namespace

bool IfaceMap::has_address(uint64_t ifindex, const SockAddr &addr)
{
    Guard G(lock);

    if(addr.isAny())
        return true;

    bool found = try_cache(*this, [this, ifindex, &addr]() {
        auto ifit(byIndex.find(ifindex));
        if(ifit!=byIndex.end()) {
            const auto& addrs = ifit->second.addrs;
            return addrs.find(addr)!=addrs.end();
        }
        return false;
    });
    return found;
}

std::string IfaceMap::name_of(uint64_t index)
{
    Guard G(lock);

    std::string name;
    bool found = try_cache(*this, [this, index, &name](){
        auto it(byIndex.find(index));
        if(it!=byIndex.end()) {
            name = it->second.name;
            return true;
        }
        return false;
    });
    if(!found) {
        // fallback to numeric index
        name = SB()<<index;
    }
    return name;
}

std::string IfaceMap::name_of(const SockAddr& addr)
{
    Guard G(lock);

    std::string name;
    try_cache(*this, [this, addr, &name](){
        auto it(byAddr.find(addr));
        if(it!=byAddr.end()) {
            name = it->second.first->name;
            return true;
        }
        return false;
    });
    return name;
}

uint64_t IfaceMap::index_of(const std::string& name)
{
    Guard G(lock);

    uint64_t ret = 0u;
    try_cache(*this, [&ret, this, name]() {
        auto it = byName.find(name);
        bool hit = it!=byName.end();
        if(hit)
            ret = it->second->index;
        return hit;
    });
    return ret;
}

bool IfaceMap::is_address(const SockAddr& addr)
{
    Guard G(lock);

    return try_cache(*this, [this, addr]() {
        return byAddr.find(addr)!=byAddr.end();
    });
}

bool IfaceMap::is_broadcast(const SockAddr& addr)
{
    Guard G(lock);

    return try_cache(*this, [this, addr]() {
        auto it(byAddr.find(addr));
        return it!=byAddr.end() && it->second.second;
    });
}

SockAddr IfaceMap::address_of(const std::string& name)
{
    Guard G(lock);

    SockAddr ret;
    try_cache(*this, [this, name, &ret]() {
        auto it(byName.find(name));
        if(it!=byName.end() && !it->second->addrs.empty()) {
            ret = it->second->addrs.begin()->first;
        }
        return false;
    });
    return ret;
}

std::set<std::string> IfaceMap::all_external()
{
    std::set<std::string> ret;
    Guard G(lock);
    refresh();
    for(auto& pair : byIndex) {
        ret.emplace(pair.second.name);
    }
    return ret;
}


void to_wire(Buffer& buf, const SockAddr& val)
{
    if(!buf.ensure(16)) {
        buf.fault(__FILE__, __LINE__);
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
        buf.fault(__FILE__, __LINE__);
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
    vec.iov_len  = base ? pos - base : 0u;

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

} // namespace impl

Timer::~Timer() {}

bool Timer::cancel()
{
    if(!pvt)
        throw std::logic_error("NULL Timer");

    auto P(std::move(pvt));

    return P->cancel();
}

Timer::Pvt::~Pvt() {
    log_debug_printf(logtimer, "Timer %p %s\n", this, __func__);
    if(base.assertInRunningLoop())
        (void)cancel();
}

bool Timer::Pvt::cancel()
{
    bool ret = false;
    decltype (cb) trash;

    log_debug_printf(logtimer, "Timer %p pcancel\n", this);

    base.call([this, &ret, &trash](){
        trash = std::move(cb);
        if(auto T = std::move(timer)) {
            log_debug_printf(logtimer, "Timer %p dispose %p\n", this, T.get());
            ret = event_pending(T.get(), EV_TIMEOUT, nullptr);
            (void)event_del(T.get());
        }
    });

    return ret;
}

static
void expire_cb(evutil_socket_t, short, void * raw)
{
    auto self(static_cast<Timer::Pvt*>(raw));
    log_debug_printf(logtimer, "Timer %p expires\n", self);
    assert(self->base.base);

    try {
        self->cb();
    } catch(std::exception& e){
        log_exc_printf(logtimer, "Unhandled exception in Timer callback: %s\n", e.what());
    }
}

Timer Timer::Pvt::buildOneShot(double delay, const evbase& base, std::function<void()>&& cb)
{
    if(!cb)
        throw std::invalid_argument("NULL cb");

    auto internal(std::make_shared<Timer::Pvt>(base, std::move(cb)));

    Timer ret;
    ret.pvt = decltype (internal)(internal.get(), [internal](Timer::Pvt*) mutable {
        // from user thread
        auto temp(std::move(internal));
        auto loop(temp->base);
        // std::bind for lack of c++14 generalized capture
        // to move internal ref to worker for dtor

        loop.tryCall(std::bind([](std::shared_ptr<Timer::Pvt>& internal) {
                         // on worker
                         // ordering of dispatch()/call() ensures creation before destruction
                         internal->cancel();
                     }, std::move(temp)));
    });

    base.call([internal, delay](){
        // on worker
        evevent timer(event_new(internal->base.base, -1, EV_TIMEOUT, &expire_cb, internal.get()));
        internal->timer = std::move(timer);

        auto timo(totv(delay));

        if(event_add(internal->timer.get(), &timo))
            throw std::runtime_error("Unable to start oneshot timer");

        log_debug_printf(logtimer, "Create timer %p as %p with delay %f and %s\n",
                         internal.get(),
                         internal->timer.get(),
                         delay,
                         internal->cb.target_type().name());
    });

    return ret;
}

} // namespace pvxs
