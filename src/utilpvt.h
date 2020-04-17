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
#else
#  include <pthread.h>
#endif

#include <atomic>
#include <memory>
#include <string>
#include <sstream>
#include <type_traits>

#include <compilerDependencies.h>

#include <epicsTypes.h>

#include <pvxs/version.h>
#include <pvxs/util.h>

#ifndef EPICS_ALWAYS_INLINE
#  if __GNUC__
#    define EPICS_ALWAYS_INLINE __inline__ __attribute__((always_inline))
#  else
#    define EPICS_ALWAYS_INLINE inline
#  endif
#endif

#if EPICS_VERSION_INT>=VERSION_INT(3,15,0,0)
#  define HAVE_EPICSPARSE
#  define HAVE_EPICSINT64
#endif

#ifndef HAVE_EPICSINT64
  typedef int64_t epicsInt64;
  typedef uint64_t epicsUInt64;
#endif // HAVE_EPICSINT64

#ifndef HAVE_EPICSPARSE
  PVXS_API int epicsParseInt8(const char* s, epicsInt8* val, int base, char** units);
  PVXS_API int epicsParseInt16(const char* s, epicsInt16* val, int base, char** units);
  PVXS_API int epicsParseInt32(const char* s, epicsInt32* val, int base, char** units);
  PVXS_API int epicsParseInt64(const char* s, epicsInt64* val, int base, char** units);
  PVXS_API int epicsParseUInt8(const char* s, epicsUInt8* val, int base, char** units);
  PVXS_API int epicsParseUInt16(const char* s, epicsUInt16* val, int base, char** units);
  PVXS_API int epicsParseUInt32(const char* s, epicsUInt32* val, int base, char** units);
  PVXS_API int epicsParseUInt64(const char* s, epicsUInt64* val, int base, char** units);
  PVXS_API int epicsParseFloat(const char* s, epicsFloat32* val, char** units);
  PVXS_API int epicsParseDouble(const char* s, epicsFloat64* val, char** units);
# define epicsParseFloat32(str, to, units) epicsParseFloat(str, to, units)
# define epicsParseFloat64(str, to, units) epicsParseDouble(str, to, units)
# define epicsParseLong(str, to, base, units) epicsParseInt32(str, to, base, units)
# define epicsParseULong(str, to, base, units) epicsParseUInt32(str, to, base, units)
# define epicsParseLLong(str, to, base, units) epicsParseInt64(str, to, base, units)
# define epicsParseULLong(str, to, base, units) epicsParseUInt64(str, to, base, units)
#endif // HAVE_EPICSPARSE

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
// specific specializations in util.cpp
template <typename T>
struct as_str {PVXS_API static T op(const char *s);};
} // namespace idetail

template <typename T>
inline T lexical_cast(const char *s)
{
    return idetail::as_str<T>::op(s);
}

template <typename T>
inline T lexical_cast(const std::string& s)
{
    return idetail::as_str<T>::op(s.c_str());
}

void indent(std::ostream& strm, unsigned level);

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

template<std::atomic<size_t>* Cnt>
struct InstCounter
{
    InstCounter() {(*Cnt).fetch_add(1, std::memory_order_relaxed);}
    ~InstCounter() {(*Cnt).fetch_sub(1, std::memory_order_relaxed);}
};

#define INST_COUNTER(KLASS) InstCounter<&cnt_ ## KLASS> instances

#define CASE(KLASS) extern std::atomic<size_t> cnt_ ## KLASS

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

} // namespace pvxs

#endif // UTILPVT_H
