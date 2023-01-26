/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// for signal handling
#include <signal.h>

#include <iomanip>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <atomic>

#include <ctype.h>

#include <pvxs/log.h>
#include <pvxs/util.h>
#include <pvxs/sharedArray.h>
#include <pvxs/data.h>
#include "utilpvt.h"
#include "udp_collector.h"

#include "pvxsVCS.h"

extern "C" {
// unofficial helpers for dynamic loading
PVXS_API
unsigned long pvxs_version_int()
{
    return PVXS_VERSION;
}
PVXS_API
unsigned long pvxs_version_abi_int()
{
    return PVXS_ABI_VERSION;
}
}

namespace pvxs {

DEFINE_LOGGER(log, "pvxs.util");

#define stringifyX(X) #X
#define stringify(X) stringifyX(X)

const char *version_str()
{
    return "PVXS "
            stringify(PVXS_MAJOR_VERSION)
            "."
            stringify(PVXS_MINOR_VERSION)
            "."
            stringify(PVXS_MAINTENANCE_VERSION)
#ifdef PVXS_VCS_VERSION
            " (" PVXS_VCS_VERSION ")"
#endif
            ;
}

unsigned long version_int()
{
    return PVXS_VERSION;
}

unsigned long version_abi_int()
{
    return PVXS_ABI_VERSION;
}


#define CASE(KLASS) std::atomic<size_t> cnt_ ## KLASS{}
#include "instcounters.h"
#undef CASE

std::map<std::string, size_t> instanceSnapshot()
{
    std::map<std::string, size_t> ret;

#define CASE(KLASS) ret[#KLASS] = cnt_ ## KLASS .load(std::memory_order_relaxed)
#include "instcounters.h"
#undef CASE

    return ret;
}

// _assume_ only positive indices will be used
static
std::atomic<int> indentIndex{INT_MIN};

std::ostream& operator<<(std::ostream& strm, const indent&)
{
    auto idx = indentIndex.load(std::memory_order_relaxed);
    if(idx!=INT_MIN) {
        auto n = strm.iword(idx);
        for(auto i : range(n)) {
            (void)i;
            strm<<"    ";
        }
    }
    return strm;
}

Indented::Indented(std::ostream& strm, int depth)
    :strm(&strm)
    ,depth(depth)
{
    auto idx = indentIndex.load();
    if(idx==INT_MIN) {
        auto newidx = std::ostream::xalloc();
        if(indentIndex.compare_exchange_strong(idx, newidx)) {
            idx = newidx;
        } else {
            // lost race.  no way to undo xalloc(), so just wasted...
        }
    }
    strm.iword(idx) += depth;
}

Indented::~Indented()
{
    if(strm)
        strm->iword(indentIndex.load(std::memory_order_relaxed)) -= depth;
}

// _assume_ only positive indices will be used
static
std::atomic<int> detailIndex{INT_MIN};

Detailed::Detailed(std::ostream& strm, int lvl)
    :strm(&strm)
{
    auto idx = detailIndex.load();
    if(idx==INT_MIN) {
        auto newidx = std::ostream::xalloc();
        if(detailIndex.compare_exchange_strong(idx, newidx)) {
            idx = newidx;
        } else {
            // lost race.  no way to undo xalloc(), so just wasted...
        }
    }

    auto& ref = strm.iword(idx);
    this->lvl = ref;
    ref = lvl;
}

Detailed::~Detailed()
{
    if(strm)
        strm->iword(detailIndex.load(std::memory_order_relaxed)) = lvl;
}

int Detailed::level(std::ostream &strm)
{
    int ret = 0;
    auto idx = detailIndex.load(std::memory_order_relaxed);
    if(idx==INT_MIN) {
        strm<<"Hint: Wrap with pvxs::Detailed()\n";
    } else {
        ret = strm.iword(idx);
    }
    return ret;
}

namespace detail {

Escaper::Escaper(const char* v)
    :val(v)
    ,count(v ? strlen(v) : 0)
{}

std::ostream& operator<<(std::ostream& strm, const Escaper& esc)
{
    const char *s = esc.val;
    if(!s) {
        strm<<"<NULL>";
    } else {
        for(size_t n=0; n<esc.count; n++,s++) {
            char c = *s, next;
            switch(c) {
            case '\a': next = 'a'; break;
            case '\b': next = 'b'; break;
            case '\f': next = 'f'; break;
            case '\n': next = 'n'; break;
            case '\r': next = 'r'; break;
            case '\t': next = 't'; break;
            case '\v': next = 'v'; break;
            case '\\': next = '\\'; break;
            case '\'': next = '\''; break;
            case '\"': next = '\"'; break;
            default:
                if(c>=' ' && c<='~') { // isprint()
                    strm.put(c);
                } else {
                    Restore R(strm);
                    strm<<"\\x"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c&0xff);
                }
                continue;
            }
            strm.put('\\').put(next);
        }
    }
    return strm;
}


} // namespace detail

std::ostream& operator<<(std::ostream& strm, const ServerGUID& guid)
{
    Restore R(strm);
    strm.width(2);
    strm<<"0x"<<std::hex<<std::setfill('0');
    for(size_t i=0; i<guid.size(); i++)
        strm<<std::setw(2)<<unsigned(guid[i]);
    return strm;
}

#if !defined(__rtems__) && !defined(vxWorks)

static
std::atomic<evutil_socket_t> onsig{evutil_socket_t(EVUTIL_INVALID_SOCKET)};

static
void SigInt_handler(int signum);

namespace {
struct SocketPair {
    evutil_socket_t s[2];
    SocketPair() {
#ifdef _WIN32
        auto err = evutil_socketpair(AF_INET, SOCK_STREAM, 0, s);
#else
        auto err = evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, s);
#endif
        if(err)
            throw std::bad_alloc();
    }
    ~SocketPair() {
        epicsSocketDestroy(s[0]);
        epicsSocketDestroy(s[1]);
    }
};

} // namespace

struct SigInt::Pvt : public epicsThreadRunable {
    void (*prevINT)(int);
    void (*prevTERM)(int);
    const std::function<void()> handler;

    // either pipe() or socketpair()
    SocketPair wake;

    epicsThread thr;

    Pvt(const std::function<void ()> &&handler)
        :handler(handler)
        ,thr(*this, "SigInt",
             epicsThreadGetStackSize(epicsThreadStackBig),
             epicsThreadPriorityMax)
    {
        evutil_socket_t expect = EVUTIL_INVALID_SOCKET;
        if(!onsig.compare_exchange_strong(expect, wake.s[1])) {
            throw std::logic_error("Only one SigInt may exist in a process");
        }

        prevINT = signal(SIGINT, &SigInt_handler);
        prevTERM = signal(SIGTERM, &SigInt_handler);

        thr.start();
    }

    virtual ~Pvt() {
        // disarm
        signal(SIGINT, prevINT);
        signal(SIGTERM, prevTERM);
        // no new signals will be delivered.
        // may be in-progress handlers on other threads.
        // maybe handler() running in our thread.

        char msg = 'I';
        auto ret = send(wake.s[1], &msg, 1, 0);
        assert(ret==1);
        thr.exitWait();

        evutil_socket_t expect;
        while((expect=onsig) == wake.s[1] && !onsig.compare_exchange_strong(expect, EVUTIL_INVALID_SOCKET))
        {
            // signal handler in progress...
            epicsThreadSleep(0.1);
        }
    }

    virtual void run() override final {
        char msg;
        while(true) {
            auto ret = recv(wake.s[0], &msg, 1, 0);
            if(ret<0 && evutil_socket_geterror(wake.s[0])==SOCK_EINTR) {
                continue; // interrupted by a signal handler, perhaps to notify me?

            } else if(ret>=1) {
                handler();
            }
            break;
        }
    }
};

static
void SigInt_handler(int)
{
    const evutil_socket_t inprog = EVUTIL_INVALID_SOCKET-1;
    evutil_socket_t fd = onsig.load();
    if(fd!=EVUTIL_INVALID_SOCKET && fd!=inprog && onsig.compare_exchange_strong(fd, inprog)) {
        char msg = 'S';
        auto ret = send(fd, &msg, 1, 0);
        (void)ret; // no much can be done here if something goes wrong...
        onsig = fd;
    }
}

SigInt::SigInt(const std::function<void ()> &&handler)
    :pvt(std::make_shared<Pvt>(std::move(handler)))
{}

SigInt::~SigInt() {}

#endif // !defined(__rtems__) && !defined(vxWorks)


SockAddr::SockAddr(int af)
    :store{}
{
    store.sa.sa_family = af;
    if(af!=AF_INET
#ifdef AF_INET6
            && af!=AF_INET6
#endif
            && af!=AF_UNSPEC)
        throw std::invalid_argument("Unsupported address family");
}

SockAddr::SockAddr(const char *address, unsigned short port)
    :SockAddr(AF_UNSPEC)
{
    setAddress(address, port);
}

SockAddr::SockAddr(const sockaddr *addr, socklen_t alen)
    :SockAddr(addr ? addr->sa_family : AF_UNSPEC)
{
    if(!addr)
        return; // treat NULL as AF_UNSPEC

    if(family()==AF_UNSPEC) {}
    else if(family()==AF_INET && (!alen || alen>=sizeof(sockaddr_in))) {}
    else if(family()==AF_INET6 && (!alen || alen>=sizeof(sockaddr_in6))) {}
    else
        throw std::invalid_argument("Unsupported address family");

    if(family()!=AF_UNSPEC)
        memcpy(&store, addr, family()==AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
}

size_t SockAddr::size() const noexcept
{
    switch(store.sa.sa_family) {
    case AF_INET: return sizeof(store.in);
#ifdef AF_INET6
    case AF_INET6: return sizeof(store.in6);
#endif
    default: // AF_UNSPEC and others
        return sizeof(store);
    }
}

unsigned short SockAddr::port() const noexcept
{
    switch(store.sa.sa_family) {
    case AF_INET: return ntohs(store.in.sin_port);
#ifdef AF_INET6
    case AF_INET6:return ntohs(store.in6.sin6_port);
#endif
    default: return 0;
    }
}

void SockAddr::setPort(unsigned short port)
{
    switch(store.sa.sa_family) {
    case AF_INET: store.in.sin_port = htons(port); break;
#ifdef AF_INET6
    case AF_INET6:store.in6.sin6_port = htons(port); break;
#endif
    default:
        throw std::logic_error("SockAddr: set family before port");
    }
}

void SockAddr::setAddress(const char *name, unsigned short defport)
{
    assert(name);
    // too bad evutil_parse_sockaddr_port() treats ":0" as an error...

    /* looking for
     * [ipv6]:port
     * ipv6
     * [ipv6]
     * ipv4:port
     * ipv4
     */
    // TODO: could optimize to find all of these with a single loop
    const char *firstc = strchr(name, ':'),
               *lastc  = strrchr(name, ':'),
               *openb  = strchr(name, '['),
               *closeb = strrchr(name, ']');

    if(!openb ^ !closeb) {
        // '[' w/o ']' or vis. versa
        throw std::runtime_error(SB()<<"IPv6 with mismatched brackets \""<<escape(name)<<"\"");
    }

    char scratch[INET6_ADDRSTRLEN+1];
    const char *addr, *port;
    SockAddr temp;
    void *sockaddr;

    if(!firstc && !openb) {
        // no brackets or port.
        // plain ipv4
        addr = name;
        port = nullptr;
        temp->sa.sa_family = AF_INET;
        sockaddr = (void*)&temp->in.sin_addr.s_addr;

    } else if(firstc && firstc==lastc && !openb) {
        // no bracket and only one ':'
        // ipv4 w/ port
        size_t addrlen = firstc-name;
        if(addrlen >= sizeof(scratch))
            throw std::runtime_error(SB()<<"IPv4 address too long \""<<escape(name)<<"\"");

        memcpy(scratch, name, addrlen);
        scratch[addrlen] = '\0';
        addr = scratch;
        port = lastc+1;
        temp->sa.sa_family = AF_INET;
        sockaddr = (void*)&temp->in.sin_addr.s_addr;

    } else if(firstc && firstc!=lastc && !openb) {
        // no bracket and more than one ':'
        // bare ipv6
        addr = name;
        port = nullptr;
        temp->sa.sa_family = AF_INET6;
        sockaddr = (void*)&temp->in6.sin6_addr;

    } else if(openb) {
        // brackets
        // ipv6, maybe with port
        size_t addrlen = closeb-openb-1u;
        if(addrlen >= sizeof(scratch))
            throw std::runtime_error(SB()<<"IPv6 address too long \""<<escape(name)<<"\"");

        memcpy(scratch, openb+1, addrlen);
        scratch[addrlen] = '\0';
        addr = scratch;
        if(lastc > closeb)
            port = lastc+1;
        else
            port = nullptr;
        temp->sa.sa_family = AF_INET6;
        sockaddr = (void*)&temp->in6.sin6_addr;

    } else {
        throw std::runtime_error(SB()<<"Invalid IP address form \""<<escape(name)<<"\"");
    }

    if(evutil_inet_pton(temp->sa.sa_family, addr, sockaddr)<=0) {
        // not a plain IP4/6 address.
        // Fall back to synchronous DNS lookup (could be sloooow)

        GetAddrInfo info(addr);

        // We may get a mixture of IP v4 and/or v6 addresses.
        // For maximum compatibility, we always prefer IPv4

        for(const auto addr : info) {
            if(addr.family()==AF_INET || (addr.family()==AF_INET6 && temp.family()==AF_UNSPEC)) {
                temp = addr;
                if(addr.family()==AF_INET)
                    break;
            }
        }

        if(temp.family()==AF_UNSPEC) // lookup succeeded, but no addresses.  Can this happen?
            throw std::runtime_error(SB()<<"Not a valid host name or IP address \""<<escape(name)<<"\"");
    }

    if(port)
        temp.setPort(parseTo<uint64_t>(port));
    else
        temp.setPort(defport);

    (*this) = temp;
}

bool SockAddr::isAny() const noexcept
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_ANY);
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_UNSPECIFIED(&store.in6.sin6_addr);
#endif
    default: return false;
    }
}

bool SockAddr::isLO() const noexcept
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_LOOPBACK);
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_LOOPBACK(&store.in6.sin6_addr);
#endif
    default: return false;
    }
}

bool SockAddr::isMCast() const noexcept
{
    switch(store.sa.sa_family) {
    case AF_INET: return IN_MULTICAST(ntohl(store.in.sin_addr.s_addr));
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_MULTICAST(&store.in6.sin6_addr);
#endif
    default: return false;
    }
}

SockAddr SockAddr::map4to6() const
{
    SockAddr ret;
    if(family()==AF_INET) {
        static_assert (sizeof(ret->in6.sin6_addr)==16, "");
        ret->in6.sin6_family = AF_INET6;
        ret->in6.sin6_addr.s6_addr[10] = 0xff;
        ret->in6.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&ret->in6.sin6_addr.s6_addr[12], &store.in.sin_addr.s_addr, 4u);

        ret->in6.sin6_port = store.in.sin_port;

    } else if(family()==AF_INET6) {
        ret = *this;

    } else {
        throw std::logic_error("Invalid address family");
    }
    return ret;
}

std::string SockAddr::tostring() const
{
    std::ostringstream strm;
    strm<<(*this);
    return strm.str();
}

SockAddr SockAddr::any(int af, unsigned port)
{
    SockAddr ret(af);
    switch(af) {
    case AF_INET:
        ret->in.sin_addr.s_addr = htonl(INADDR_ANY);
        ret->in.sin_port = htons(port);
        break;
#ifdef AF_INET6
    case AF_INET6:
        ret->in6.sin6_addr = IN6ADDR_ANY_INIT;
        ret->in6.sin6_port = htons(port);
        break;
#endif
    default:
        throw std::invalid_argument("Unsupported address family");
    }
    return ret;
}

SockAddr SockAddr::loopback(int af, unsigned port)
{
    SockAddr ret(af);
    switch(af) {
    case AF_INET:
        ret->in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ret->in.sin_port = htons(port);
        break;
#ifdef AF_INET6
    case AF_INET6:
        ret->in6.sin6_addr = IN6ADDR_LOOPBACK_INIT;
        ret->in6.sin6_port = htons(port);
        break;
#endif
    default:
        throw std::invalid_argument("Unsupported address family");
    }
    return ret;
}

std::ostream& operator<<(std::ostream& strm, const SockAddr& addr)
{
    switch(addr->sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN+1];
        if(evutil_inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf))) {
            buf[sizeof(buf)-1] = '\0'; // paranoia
        } else {
            strm<<"<\?\?\?>";
        }
        strm<<buf;
        if(ntohs(addr->in.sin_port))
            strm<<':'<<ntohs(addr->in.sin_port);
        break;
    }
#ifdef AF_INET6
    case AF_INET6: {
            char buf[INET6_ADDRSTRLEN+1];
            if(evutil_inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf))) {
                buf[sizeof(buf)-1] = '\0'; // paranoia
                strm<<'['<<buf<<']';

            } else {
                strm<<"<\?\?\?>";
            }
            if(addr->in6.sin6_scope_id)
                strm<<"%"<<addr->in6.sin6_scope_id;
            if(auto port = ntohs(addr->in6.sin6_port))
                strm<<':'<<port;
            break;
    }
#endif
    case AF_UNSPEC:
        strm<<"<>";
        break;
    default:
        strm<<"<\?\?\?>";
    }
    return strm;
}

GetAddrInfo::GetAddrInfo(const char *name)
{
    if(auto err = evutil_getaddrinfo(name, nullptr, nullptr, &info)) {
        throw std::runtime_error(SB()<<"Error resolving \""<<escape(name)<<"\" : "<<evutil_gai_strerror(err));
    }
}

GetAddrInfo::~GetAddrInfo()
{
    if(info)
        evutil_freeaddrinfo(info);
}

} // namespace pvxs

namespace pvxs {namespace impl {
struct onceArgs {
    EPICSTHREADFUNC fn;
    void *arg;
    std::exception_ptr err;
};

static
void onceWrapper(void *raw)
{
    auto args = static_cast<onceArgs*>(raw);
    try {
        args->fn(args->arg);
    }catch(...){
        args->err = std::current_exception();
    }
}

void threadOnce(epicsThreadOnceId *id, EPICSTHREADFUNC fn, void *arg)
{
    onceArgs args{fn, arg};
    epicsThreadOnce(id, &onceWrapper, &args);
    if(args.err)
        std::rethrow_exception(args.err);
}

template<>
double parseTo<double>(const std::string& s) {
    size_t idx=0, L=s.size();
    double ret;
    try {
        ret = std::stod(s, &idx);
    }catch(std::invalid_argument& e) {
        throw NoConvert(SB()<<"Invalid input : \""<<escape(s)<<"\"");
    }catch(std::out_of_range& e) {
        throw NoConvert(SB()<<"Out of range : \""<<escape(s)<<"\"");
    }
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        NoConvert(SB()<<"Extraneous characters after double: \""<<escape(s)<<"\"");
    return ret;
}

template<>
uint64_t parseTo<uint64_t>(const std::string& s) {
    size_t idx=0, L=s.size();
    unsigned long long ret;
    try {
        ret = std::stoull(s, &idx, 0);
    }catch(std::invalid_argument& e) {
        throw NoConvert(SB()<<"Invalid input : \""<<escape(s)<<"\"");
    }catch(std::out_of_range& e) {
        throw NoConvert(SB()<<"Out of range : \""<<escape(s)<<"\"");
    }
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        throw NoConvert(SB()<<"Extraneous characters after integer: \""<<escape(s)<<"\"");
    return ret;
}

template<>
int64_t parseTo<int64_t>(const std::string& s) {
    size_t idx=0, L=s.size();
    long long ret;
    try {
        ret = std::stoll(s, &idx, 0);
    }catch(std::invalid_argument& e) {
        throw NoConvert(SB()<<"Invalid input : \""<<escape(s)<<"\"");
    }catch(std::out_of_range& e) {
        throw NoConvert(SB()<<"Out of range : \""<<escape(s)<<"\"");
    }
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        throw NoConvert(SB()<<"Extraneous characters after unsigned: \""<<escape(s)<<"\"");
    return ret;
}

}}
