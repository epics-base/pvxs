/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiSock.h>

#ifdef __has_include
#  if defined(_WIN32) && __has_include(<afunix.h>)
#    include <afunix.h>
#    define WIN_HAS_AFUNIX
#  endif
#endif

#ifdef __linux__
#include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
#endif

// for signal handling
#include <signal.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <atomic>

#include <climits>
#include <fstream>
#include <iterator>
#include <list>
#include <map>
#include <regex>

#include <ctype.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <pwd.h>
#include <libgen.h>
#include <unistd.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#include <pvxs/log.h>
#include <pvxs/util.h>
#include <pvxs/data.h>
#include <pvxs/version.h>

#include "osiFileName.h"
#include "utilpvt.h"
#include "udp_collector.h"
#include "pvxsVCS.h"

#ifdef PVXS_ENABLE_OPENSSL
#include "certfactory.h"
#endif

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

namespace {
struct ICountGbl_t {
    RWLock lock;
    std::map<std::string, std::atomic<size_t>*> counters;
} *ICountGbl;

void ICountInit()
{
    ICountGbl = new ICountGbl_t;
}

} // namespace

void registerICount(const char *name, std::atomic<size_t>& Cnt)
{
    threadOnce<&ICountInit>();
    auto& gbl = *ICountGbl;
    try {
        auto L(gbl.lock.lockWriter());
        if(!gbl.counters.emplace(name, &Cnt).second) { // duplicate name
            return;
        }
    } catch(std::exception& e) { // bad_alloc
        return;
    }
    Cnt++; // bias by +1 to indicate initialization
}

std::map<std::string, size_t> instanceSnapshot()
{
    std::map<std::string, size_t> ret;

    {
        threadOnce<&ICountInit>();
        auto& gbl = *ICountGbl;
        auto L(gbl.lock.lockReader());
        for(auto& pair : gbl.counters) {
            // remove -1 bias for initialized counter
            ret.emplace(pair.first, pair.second->load(std::memory_order_relaxed)-1u);
        }
    }

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
        ret = (int)strm.iword(idx);
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

/* Initially EVUTIL_INVALID_SOCKET
 * Set to a valid socket when "armed"
 * Temporarily set to EVUTIL_INVALID_SOCKET-1 (aka -2) while handler in progress
 * Restored to a valid socket when the handler is finished
 * Reset to EVUTIL_INVALID_SOCKET when "disarmed"
 */
static
std::atomic<evutil_socket_t> onsig{evutil_socket_t(EVUTIL_INVALID_SOCKET)};

static
void SigInt_handler(int signum);

namespace {
struct SocketPair {
    SOCKET s[2];
    SocketPair() {
        compat_socketpair(s);
    }
    SocketPair(const SocketPair&) = delete;
    SocketPair& operator=(const SocketPair&) = delete;
    ~SocketPair() {
        epicsSocketDestroy(s[0]);
        epicsSocketDestroy(s[1]);
    }
};

} // namespace

struct SigInt::Pvt final : private epicsThreadRunable {
    void (*prevINT)(int);
    void (*prevTERM)(int);
    const std::function<void()> handler;

    // either pipe() or socketpair()
    SocketPair wake;

    epicsThread thr;

    explicit
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

void compat_socketpair(SOCKET sock[2])
{
    evutil_socket_t s[2];
    int err = -1;
#if !defined(_WIN32) || defined(WIN_HAS_AFUNIX)
    err = evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, s);
#endif
    if(err)
        err = evutil_socketpair(AF_INET, SOCK_STREAM, 0, s);
    if(err)
        throw std::runtime_error(SB()<<"ERROR: "<<__func__<<" "<<SOCKERRNO);
    sock[0] = (SOCKET)s[0];
    sock[1] = (SOCKET)s[1];
}

void compat_make_socket_nonblocking(SOCKET sock)
{
    if(evutil_make_socket_nonblocking(sock))
        throw std::runtime_error(SB()<<"ERROR: "<<__func__<<" "<<SOCKERRNO);
}


} // namespace pvxs

namespace pvxs {namespace impl {
struct onceArgs {
    threadOnceInfo *info;
    std::exception_ptr err;
};

static
void onceWrapper(void *raw) noexcept
{
    auto args = static_cast<onceArgs*>(raw);
    try {
        args->info->fn();
        args->info->ok = true;
    }catch(...){
        args->err = std::current_exception();
        args->info->ok = false;
    }
}

void threadOnce_(threadOnceInfo *info)
{
    onceArgs args{info};
    epicsThreadOnce(&info->id, &onceWrapper, &args);
    if(args.err)
        std::rethrow_exception(args.err);
    if(!info->ok)
        throw std::logic_error("threadOnce() : Previous failure");
}

template<>
double parseTo<double>(const std::string& s) {
    size_t idx=0, L=s.size();
    double ret;
    try {
        ret = std::stod(s, &idx);
    }catch(std::invalid_argument& e) {
        throw NoConvert(SB()<<"Invalid input : \""<<escape(s)<<"\" : "<<e.what());
    }catch(std::out_of_range& e) {
        throw NoConvert(SB()<<"Out of range : \""<<escape(s)<<"\" : "<<e.what());
    }
    for(; idx<L && isspace(s[idx]); idx++) {}
    if(idx<L)
        throw NoConvert(SB()<<"Extraneous characters after double: \""<<escape(s)<<"\"");
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

template <>
bool parseTo<bool>(const std::string &s) {
    std::string lower;
    std::transform(s.begin(), s.end(), std::back_inserter(lower), ::tolower);
    return lower == "yes" ||lower == "on" || lower == "enabled" || lower == "true" || lower == "1";
}

#ifdef PVXS_ENABLE_OPENSSL
/**
 * @brief create a CertStatusSubscription flag based on a string parameter value
 *
 * YES for "yes"/"true"/"1"
 * NO for "no"/"false"/"0"
 * DEFAULT for default
 *
 * @param input the string parameter value
 * @return the corresponding CertStatusSubscription value
 * @throw std::invalid_argument if the string doesn't match any expected value
 */
template<>
int8_t parseTo<int8_t>(const std::string& input) {
    // Create a lowercase copy of the input string
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                  [](const unsigned char c) { return std::tolower(c); });

    if (lower == "yes" || lower == "true" || lower == "enabled" || lower == "on" || lower == "1") return certs::YES;
    if (lower == "no" || lower == "false" || lower == "disabled" || lower == "off" || lower == "0") return certs::NO;
    if (lower == "default") return certs::DEFAULT;

    // No match found - throw an exception
    throw NoConvert(SB() << "Invalid value: must be 'yes'/'true'/'enabled'/'on'/'1', 'no'/'false'/'disabled'/'off'/'0', or 'default': " << input);
}
#endif

static
std::vector<std::string>
splitLines(const char *inp)
{
    std::vector<std::string> ret;
    while(*inp) {
        auto start = inp;
        // find next EoL or nil
        for(char c=*inp; c!='\0' && c!='\n' && c!='\r'; c=*++inp) {}
        // inp points to EoL or nil
        ret.emplace_back(start, inp); // copy line w/o EoL
        // skip past one EoL ("\n", "\r\n", or "\n\r")
        if(inp[0]=='\n' && inp[1]=='\r') inp+=2u;
        else if(inp[0]=='\r' && inp[1]=='\n') inp+=2u;
        else if(inp[0]=='\n') inp+=1u;
    }
    return ret;
}

void strDiff(std::ostream& out,
             const char *lhs,
             const char *rhs)
{
    if(!lhs)
        lhs = "<null>";
    if(!rhs)
        rhs = "<null>";
    auto l_lines(splitLines(lhs));
    auto r_lines(splitLines(rhs));
    size_t L, R;

    for(L=0u, R=0u; L<l_lines.size() && R<r_lines.size();) {
        // diagonal search out from current positions
        for(size_t dist=0u; true; dist++) { // iterate out
            for(size_t C=0u; C<=dist; C++) { // iterate across
                size_t testL = L+C;
                size_t testR = R+(dist-C);

                if(testL>=l_lines.size() && testR>=r_lines.size()) {
                    goto done;
                }

                if(testL>=l_lines.size() || testR>=r_lines.size()) {
                    continue;
                }

                if(l_lines[testL]==r_lines[testR]) {
                    // found matching line

                    for(; L < testL; L++) {
                        out<<"- \""<<escape(l_lines[L])<<"\"\n";
                    }
                    for(; R < testR; R++) {
                        out<<"+ \""<<escape(r_lines[R])<<"\"\n";
                    }
                    out<<"  \""<<escape(l_lines[testL])<<"\"\n";

                    L = testL+1u;
                    R = testR+1u;
                    goto next;
                }
            }
        }
next:
        continue; // oh for lack of a "break N;"
    }
done:
    // print trailing
    for(; L < l_lines.size(); L++) {
        out<<"- \""<<escape(l_lines[L])<<"\"\n";
    }
    for(; R < r_lines.size(); R++) {
        out<<"+ \""<<escape(r_lines[R])<<"\"\n";
    }
}

/**
 * @brief Convert given path to expand tilde, dot and dot-dot at beginning
 * @param path the containing tilde, dot and/or dot-dot
 * @return the expanded path
 */
std::string convertPath(std::string &path) {
    std::string abs_path;

    if (!path.empty()) {
        if (path[0] == '~') {
            char const *home = getenv("HOME");
            if (home || ((home = getenv("USERPROFILE")))) {
                abs_path = home + path.substr(1);
            }
#ifndef _WIN32
           else {
                auto pw = getpwuid(getuid());
                if (pw) abs_path = pw->pw_dir + path.substr(1);
            }
        } else if (path[0] == '.') {
            char temp[PATH_MAX];
            if (getcwd(temp, sizeof(temp)) != nullptr) {
                if (path.size() > 1 && path[1] == '.') {
                    // Handle '..' to get parent directory
                    abs_path = dirname(temp);
                    // Append the rest of the path after the '..'
                    abs_path += path.substr(2);
                } else {
                    // Handle '.'
                    abs_path = temp + path.substr(1);  // remove '.' then append
                }
            }
#endif
        }
    }

    if (abs_path.empty()) {
        abs_path = path;
    }

    return (path = abs_path);
}

/**
 * @brief Ensure that the directory specified in the path exist
 * @param filepath the file path containing an optional directory component
 * @param convert_path true to convert path first
 */
void PVXS_API ensureDirectoryExists(std::string &filepath, const bool convert_path) {
    std::string temp_path = convert_path ? convertPath(filepath) : filepath;

    const auto delimiter = std::string(OSI_PATH_SEPARATOR);
    size_t pos = 0;
    std::string path = "";
    struct stat info {};
    while ((pos = temp_path.find(delimiter)) != std::string::npos) {
        std::string token = temp_path.substr(0, pos);
        path += token + delimiter;
        temp_path.erase(0, pos + delimiter.length());
        if (stat(path.c_str(), &info) != 0 || !(info.st_mode & S_IFDIR)) {
#ifdef _WIN32
            mkdir(path.c_str());  // Windows version takes only the path
#else
            mkdir(path.c_str(), S_IRWXU);  // Unix version takes path and permissions
#endif
        }
    }
}

std::string getHomeDir() {
#ifdef _WIN32
    const char* home = getenv("USERPROFILE");
    if (!home) {
        home = getenv("HOMEDRIVE");
        if (home) {
            static std::string homePath;
            const char* homedir = getenv("HOMEPATH");
            if (homedir) {
                homePath = std::string(home) + homedir;
                return homePath;
            }
        }
    }
#else
    const auto pw = getpwuid(getuid());
    const char* home = pw ? pw->pw_dir : nullptr;
    if (!home) {
        home = getenv("HOME");
    }
#endif
    return home ? std::string(home) : std::string("");
}

std::string getFileContents(const std::string &file_name) {
    std::ifstream ifs(file_name);
    std::string contents((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    if (!contents.empty() && contents.back() == '\n') {
        contents.pop_back();
    }

    return contents;
}


std::string getXdgConfigHome() {
#ifdef _WIN32
    const auto default_home = getHomeDir();
#else
    const auto default_home = getHomeDir() + "/.config";
#endif
    const char* config_home = getenv("XDG_CONFIG_HOME");
    return config_home ? config_home : default_home;
}

std::string getXdgDataHome() {
#ifdef _WIN32
    const auto default_data_home = "C:\\ProgramData";
#else
    const auto default_data_home = getHomeDir() + "/.local/share";
#endif
    const char* data_home = getenv("XDG_DATA_HOME");
    return data_home ? data_home : default_data_home;
}

std::string getXdgPvaConfigHome() {
    const std::string suffix = SB() << OSI_PATH_SEPARATOR << "pva" << OSI_PATH_SEPARATOR << versionString() ;
    return getXdgConfigHome() + suffix;
}

std::string getXdgPvaDataHome() {
    const std::string suffix = SB() << OSI_PATH_SEPARATOR << "pva" << OSI_PATH_SEPARATOR << versionString() ;
    return getXdgDataHome() + suffix;
}

#define stringifyX(X) #X
#define stringify(X) stringifyX(X)

std::string versionString() {
    return stringify(PVXS_MAJOR_VERSION) "."  stringify(PVXS_MINOR_VERSION);
}
#undef stringify
#undef stringifyX

}}
