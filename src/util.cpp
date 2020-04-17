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

#include <pvxs/util.h>
#include <pvxs/sharedArray.h>
#include <pvxs/data.h>
#include "utilpvt.h"
#include "udp_collector.h"

#include "pvxsVCS.h"

namespace pvxs {

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


#define CASE(KLASS) std::atomic<size_t> cnt_ ## KLASS{}

CASE(StructTop);

CASE(UDPListener);
CASE(evbase);

CASE(GPROp);
CASE(Connection);
CASE(Channel);
CASE(ClientPvt);
CASE(ClientPvtLive);
CASE(InfoOp);
CASE(SubScriptionImpl);

CASE(ServerChannelControl);
CASE(ServerChan);
CASE(ServerConn);
CASE(ServerSource);
CASE(ServerPvt);
CASE(ServerIntrospect);
CASE(ServerIntrospectControl);
CASE(ServerGPR);
CASE(ServerGPRConnect);
CASE(ServerGPRExec);
CASE(MonitorOp);
CASE(ServerMonitorControl);
CASE(ServerMonitorSetup);
CASE(SharedPVImpl);
CASE(SubscriptionImpl);

#undef CASE

std::map<std::string, size_t> instanceSnapshot()
{
    std::map<std::string, size_t> ret;

#define CASE(KLASS) ret[#KLASS] = cnt_ ## KLASS .load(std::memory_order_relaxed)

CASE(StructTop);

CASE(UDPListener);
CASE(evbase);

CASE(GPROp);
CASE(Connection);
CASE(Channel);
CASE(ClientPvt);
CASE(ClientPvtLive);
CASE(InfoOp);
CASE(SubScriptionImpl);

CASE(ServerChannelControl);
CASE(ServerChan);
CASE(ServerConn);
CASE(ServerSource);
CASE(ServerPvt);
CASE(ServerIntrospect);
CASE(ServerIntrospectControl);
CASE(ServerGPR);
CASE(ServerGPRConnect);
CASE(ServerGPRExec);
CASE(MonitorOp);
CASE(ServerMonitorControl);
CASE(ServerMonitorSetup);
CASE(SharedPVImpl);
CASE(SubscriptionImpl);

#undef CASE

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

#if !defined(__rtems__) && !defined(vxWorks)

static
std::atomic<SigInt*> thesig{nullptr};

void SigInt::_handle(int num)
{
    auto sig = thesig.load();
    if(!sig)
        return;

    sig->handler();
}

SigInt::SigInt(decltype (handler)&& handler)
    :handler(std::move(handler))
{
    // we can't atomically replace multiple signal handler anyway

    SigInt* expect = nullptr;

    if(!thesig.compare_exchange_weak(expect, this))
        throw std::logic_error("Only one SigInt allowed");

    prevINT = signal(SIGINT, &_handle);
    prevTERM = signal(SIGTERM, &_handle);
}

SigInt::~SigInt()
{
    signal(SIGINT, prevINT);
    signal(SIGTERM, prevTERM);

    thesig.store(nullptr);
}

#endif // !defined(__rtems__) && !defined(vxWorks)

SockAddr::SockAddr(int af)
{
    memset(&store, 0, sizeof(store));
    store.sa.sa_family = af;
    if(af!=AF_INET
#ifdef AF_INET6
            && af!=AF_INET6
#endif
            && af!=AF_UNSPEC)
        throw std::invalid_argument("Unsupported address family");
}

SockAddr::SockAddr(int af, const char *address, unsigned short port)
    :SockAddr(af)
{
    setAddress(address, port);
}

SockAddr::SockAddr(const sockaddr *addr, ev_socklen_t len)
    :SockAddr(addr->sa_family)
{
    if(len<0 || len>ev_socklen_t(size()))
        throw std::invalid_argument("Truncated Address");
    memcpy(&store, addr, len);
}

size_t SockAddr::size() const
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

unsigned short SockAddr::port() const
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

void SockAddr::setAddress(const char *name, unsigned short port)
{
    SockAddr temp;
    int templen = sizeof(temp.store);
    if(evutil_parse_sockaddr_port(name, &temp->sa, &templen))
        throw std::runtime_error(std::string("Unable to parse as IP addresss: ")+name);
    if(temp.port()==0)
        temp.setPort(port);
    (*this) = temp;
}

bool SockAddr::isAny() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_ANY);
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_UNSPECIFIED(&store.in6.sin6_addr);
#endif
    default: return false;
    }
}

bool SockAddr::isLO() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_LOOPBACK);
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_LOOPBACK(&store.in6.sin6_addr);
#endif
    default: return false;
    }
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
            } else {
                strm<<"<\?\?\?>";
            }
            strm<<buf;
            if(ntohs(addr->in6.sin6_port))
                strm<<':'<<ntohs(addr->in6.sin6_port);
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

} // namespace pvxs

namespace pvxs {namespace impl {

template<>
double parseTo<double>(const std::string& s) {
    size_t idx=0, L=s.size();
    double ret = std::stod(s, &idx);
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        throw std::invalid_argument(SB()<<"Extraneous charactors after double: \""<<escape(s)<<"\"");
    return ret;
}

template<>
uint64_t parseTo<uint64_t>(const std::string& s) {
    size_t idx=0, L=s.size();
    unsigned long long ret = std::stoull(s, &idx, 0);
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        throw std::invalid_argument(SB()<<"Extraneous charactors after integer: \""<<escape(s)<<"\"");
    return ret;
}

template<>
int64_t parseTo<int64_t>(const std::string& s) {
    size_t idx=0, L=s.size();
    long long ret = std::stoll(s, &idx, 0);
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        throw std::invalid_argument(SB()<<"Extraneous charactors after unsigned: \""<<escape(s)<<"\"");
    return ret;
}

void indent(std::ostream& strm, unsigned level) {
    for(auto i : range(level)) {
        (void)i;
        strm<<"    ";
    }
}

}}
