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
            idx = indentIndex.load();
        }
    }
    strm.iword(idx) += depth;
}

Indented::~Indented()
{
    if(strm)
        strm->iword(indentIndex.load()) -= depth;
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
            idx = detailIndex.load();
        }
    }

    auto& ref = strm.iword(idx);
    this->lvl = ref;
    ref = lvl;
}

Detailed::~Detailed()
{
    if(strm)
        strm->iword(detailIndex.load()) = lvl;
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
    SigInt* expect = nullptr;

    if(!thesig.compare_exchange_strong(expect, this))
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

void enable_SO_RXQ_OVFL(SOCKET sock)
{
#ifdef SO_RXQ_OVFL
    // Linux specific feature exposes OS dropped packet count
    {
        int val = 1;
        if(setsockopt(sock, SOL_SOCKET, SO_RXQ_OVFL, (char*)&val, sizeof(val)))
            log_warn_printf(log, "Unable to set SO_RXQ_OVFL: %d\n", SOCKERRNO);
    }
#endif
}

int recvfromx(SOCKET sock, void *buf, size_t buflen, sockaddr* peer, osiSocklen_t* peerlen, uint32_t *ndrop)
{
#ifdef SO_RXQ_OVFL
    alignas (alignof (cmsghdr)) char cbuf[CMSG_SPACE(4u)];
    iovec iov = {buf, buflen};
    msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1u;
    msg.msg_name = peer;
    msg.msg_namelen = peerlen ? *peerlen : 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    int ret = recvmsg(sock, &msg, 0);

    if(ret>=0) {
        if(peerlen)
            *peerlen = msg.msg_namelen;

        if(msg.msg_flags & MSG_CTRUNC)
            log_debug_printf(log, "MSG_CTRUNC %zu, %zu\n", msg.msg_controllen, sizeof(cbuf));

        if(ndrop) {
            for(cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr ; hdr = CMSG_NXTHDR(&msg, hdr)) {
                if(hdr->cmsg_level==SOL_SOCKET && hdr->cmsg_type==SO_RXQ_OVFL && hdr->cmsg_len>=CMSG_LEN(4u)) {
                    memcpy(ndrop, CMSG_DATA(hdr), 4u);
                }
            }
        }
    }

    return ret;

#else
    return recvfrom(sock, (char*)buf, buflen, 0, peer, peerlen);
#endif
}

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
    SockAddr temp(AF_INET);
    if(aToIPAddr(name, port, &temp->in))
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
