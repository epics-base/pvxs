/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef UTILPVT_H
#define UTILPVT_H

#include <osiSock.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <synchapi.h>
#  include <errhandlingapi.h>
#  include <ws2ipdef.h>
#else
#  include <pthread.h>
#endif

#include <atomic>
#include <memory>
#include <set>
#include <string>
#include <sstream>
#include <type_traits>

#include <event2/util.h>

#include <compilerDependencies.h>

#include <pvxs/version.h>
#include <pvxs/util.h>

#ifndef EPICS_ALWAYS_INLINE
#  if __GNUC__
#    define EPICS_ALWAYS_INLINE __inline__ __attribute__((always_inline))
#  else
#    define EPICS_ALWAYS_INLINE inline
#  endif
#endif

namespace pvxs {namespace impl {

//! in-line string builder (eg. for exception messages)
//! eg. @code throw std::runtime_error(SB()<<"Some message"<<42); @endcode
struct SB {
    std::ostringstream strm;
    SB() {}
    operator std::string() const { return strm.str(); }
    template<typename T>
    SB& operator<<(const T& i) { strm<<i; return *this; }
};

namespace idetail {
template <typename I>
struct Range {
    I a, b;

    struct iterator {
        typedef std::forward_iterator_tag iterator_category;
        typedef I         value_type;
        typedef ptrdiff_t difference_type;
        typedef I*        pointer;
        typedef I&        reference;
        I val;
        explicit constexpr iterator(I val) :val(val) {}
        EPICS_ALWAYS_INLINE I operator*() const { return val; }
        EPICS_ALWAYS_INLINE iterator& operator++() { val++; return *this; }
        EPICS_ALWAYS_INLINE iterator operator++(int) { return iterator{val++}; }
        EPICS_ALWAYS_INLINE bool operator==(const iterator& o) const { return val==o.val; }
        EPICS_ALWAYS_INLINE bool operator!=(const iterator& o) const { return val!=o.val; }
    };

    EPICS_ALWAYS_INLINE iterator begin() const { return iterator{a}; }
    EPICS_ALWAYS_INLINE iterator cbegin() const { return begin(); }
    EPICS_ALWAYS_INLINE iterator end() const { return iterator{b}; }
    EPICS_ALWAYS_INLINE iterator cend() const { return end(); }
};
} // namespace idetail

template<typename I>
constexpr idetail::Range<I> range(I end) { return idetail::Range<I>{I(0), end}; }

template<typename I>
constexpr idetail::Range<I> range(I begin, I end) { return idetail::Range<I>{begin, end}; }

template<typename T>
T parseTo(const std::string& s); // not implemented

template<>
PVXS_API
double parseTo<double>(const std::string& s);
template<>
PVXS_API
uint64_t parseTo<uint64_t>(const std::string& s);
template<>
PVXS_API
int64_t parseTo<int64_t>(const std::string& s);

#ifdef _WIN32
#  define RWLOCK_TYPE SRWLOCK
#  define RWLOCK_INIT(PLOCK)    InitializeSRWLock(PLOCK)
#  define RWLOCK_DTOR(PLOCK)    do{(void)(PLOCK);}while(0)
#  define RWLOCK_WLOCK(PLOCK)   AcquireSRWLockExclusive(PLOCK)
#  define RWLOCK_WUNLOCK(PLOCK) ReleaseSRWLockExclusive(PLOCK)
#  define RWLOCK_RLOCK(PLOCK)   AcquireSRWLockShared(PLOCK)
#  define RWLOCK_RUNLOCK(PLOCK) ReleaseSRWLockShared(PLOCK)
#else
#  define RWLOCK_TYPE pthread_rwlock_t
#  define RWLOCK_INIT(PLOCK)    pthread_rwlock_init(PLOCK, nullptr)
#  define RWLOCK_DTOR(PLOCK)    pthread_rwlock_destroy(PLOCK)
#  define RWLOCK_WLOCK(PLOCK)   pthread_rwlock_wrlock(PLOCK)
#  define RWLOCK_WUNLOCK(PLOCK) pthread_rwlock_unlock(PLOCK)
#  define RWLOCK_RLOCK(PLOCK)   pthread_rwlock_rdlock(PLOCK)
#  define RWLOCK_RUNLOCK(PLOCK) pthread_rwlock_unlock(PLOCK)
#endif

class RWLock
{
    RWLOCK_TYPE lock;
public:
    inline RWLock() { RWLOCK_INIT(&lock); }
    inline ~RWLock() { RWLOCK_DTOR(&lock); }

    RWLock(const RWLock&) = delete;
    RWLock(RWLock&&) = delete;
    RWLock& operator=(const RWLock&) = delete;
    RWLock& operator=(RWLock&&) = delete;

    struct UnlockReader {
        inline void operator()(RWLock *plock) { RWLOCK_RUNLOCK(&plock->lock); }
    };
    inline std::unique_ptr<RWLock, UnlockReader> lockReader() {
        RWLOCK_RLOCK(&lock);
        return std::unique_ptr<RWLock, UnlockReader>{this};
    }

    struct UnlockWriter {
        inline void operator()(RWLock *plock) { RWLOCK_WUNLOCK(&plock->lock); }
    };
    inline std::unique_ptr<RWLock, UnlockWriter> lockWriter() {
        RWLOCK_WLOCK(&lock);
        return std::unique_ptr<RWLock, UnlockWriter>{this};
    }
};

#undef RWLOCK_TYPE
#undef RWLOCK_INIT
#undef RWLOCK_DTOR
#undef RWLOCK_WLOCK
#undef RWLOCK_WUNLOCK
#undef RWLOCK_RLOCK
#undef RWLOCK_RUNLOCK

PVXS_API
void osdGetRoles(const std::string& account, std::set<std::string>& roles);

void logger_shutdown();

// std::max() isn't constexpr until c++14 :(
constexpr size_t cmax(size_t A, size_t B) {
    return A>B ? A : B;
}

// gcc 4.9 has aligned_storage but not aligned_union
#if GCC_VERSION && GCC_VERSION<VERSION_INT(4,10,0,0)

template<typename... Types>
struct max_sizeof {
    static const size_t align = 0;
    static const size_t size = 0;
};

template<typename Head, typename... Types>
struct max_sizeof<Head, Types...> {
    static const size_t align = cmax(alignof(Head), max_sizeof<Types...>::align);
    static const size_t size = cmax(sizeof(Head), max_sizeof<Types...>::size);
};

template <size_t Len, typename... Types>
struct aligned_union
{
    using _info = max_sizeof<Types...>;

    typedef typename std::aligned_storage<cmax(Len, _info::size), _info::align>::type type;
};

#else

template <size_t Len, typename... Types>
using aligned_union = std::aligned_union<Len, Types...>;
#endif

} // namespace impl
using namespace impl;

struct SockAttach {
    SockAttach() { osiSockAttach(); }
    ~SockAttach() { osiSockRelease(); }
};

// Linux specific SO_RXQ_OVFL exposes OS dropped packet counter
void enable_SO_RXQ_OVFL(SOCKET sock);
int recvfromx(SOCKET sock, void *buf, size_t buflen, sockaddr* peer, osiSocklen_t* peerlen, uint32_t *ndrop);

//! representation of a network address
struct PVXS_API SockAddr {
    union store_t {
        sockaddr sa;
        sockaddr_in in;
#ifdef AF_INET6
        sockaddr_in6 in6;
#endif
    };
private:
    store_t  store;
public:

    explicit SockAddr(int af = AF_UNSPEC);
    explicit SockAddr(int af, const char *address, unsigned short port=0);
    explicit SockAddr(const sockaddr *addr, ev_socklen_t len);
    inline explicit SockAddr(int af, const std::string& address) :SockAddr(af, address.c_str()) {}

    size_t size() const;

    inline unsigned short family() const { return store.sa.sa_family; }
    unsigned short port() const;
    void setPort(unsigned short port);
    SockAddr withPort(unsigned short port) {
        SockAddr temp(*this);
        temp.setPort(port);
        return temp;
    }

    void setAddress(const char *, unsigned short port=0);

    bool isAny() const;
    bool isLO() const;

    store_t* operator->() { return &store; }
    const store_t* operator->() const { return &store; }

    std::string tostring() const;

    static SockAddr any(int af, unsigned port=0);
    static SockAddr loopback(int af, unsigned port=0);

    inline bool operator<(const SockAddr& o) const {
        return evutil_sockaddr_cmp(&store.sa, &o.store.sa, true)<0;
    }
    inline bool operator==(const SockAddr& o) const {
        return evutil_sockaddr_cmp(&store.sa, &o.store.sa, true)==0;
    }
    inline bool operator!=(const SockAddr& o) const {
        return !(*this==o);
    }
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const SockAddr& addr);

inline
timeval totv(double t)
{
    timeval ret;
    ret.tv_sec = t;
    ret.tv_usec = (t - ret.tv_sec)*1e6;
    return ret;
}

//! Scoped restore of std::ostream state (format flags, fill char, and field width)
struct Restore {
    std::ostream& strm;
    std::ios_base::fmtflags pflags;
    std::ostream::char_type pfill;
    std::streamsize pwidth;
    Restore(std::ostream& strm)
        :strm(strm)
        ,pflags(strm.flags())
        ,pfill(strm.fill())
        ,pwidth(strm.width())
    {}
    ~Restore() {
        strm.flags(pflags);
        strm.fill(pfill);
        strm.width(pwidth);
    }
};

template<std::atomic<size_t>* Cnt>
struct InstCounter
{
    InstCounter() {(*Cnt).fetch_add(1, std::memory_order_relaxed);}
    ~InstCounter() {(*Cnt).fetch_sub(1, std::memory_order_relaxed);}
};

#define INST_COUNTER(KLASS) InstCounter<&cnt_ ## KLASS> instances

#define CASE(KLASS) PVXS_API extern std::atomic<size_t> cnt_ ## KLASS
#include "instcounters.h"
#undef CASE

} // namespace pvxs

#endif // UTILPVT_H
