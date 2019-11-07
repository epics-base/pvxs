/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef UTILPVT_H
#define UTILPVT_H


#ifdef _WIN32
#  include <synchapi.h>
#else
#  include <pthread.h>
#endif

#include <string>
#include <sstream>

#include <compilerDependencies.h>

#include <pvxs/version.h>
#include <pvxs/util.h>

namespace pvxsimpl {
using namespace  pvxs;

//! in-line string builder (eg. for exception messages)
//! eg. @code throw std::runtime_error(SB()<<"Some message"<<42); @endcode
struct SB {
    std::ostringstream strm;
    SB() {}
    operator std::string() const { return strm.str(); }
    template<typename T>
    SB& operator<<(T i) { strm<<i; return *this; }
};

namespace detail {
// specific specializations in util.cpp
template <typename T>
struct as_str {PVXS_API static T op(const char *s);};
} // namespace detail

template <typename T>
inline T lexical_cast(const char *s)
{
    return detail::as_str<T>::op(s);
}

template <typename T>
inline T lexical_cast(const std::string& s)
{
    return detail::as_str<T>::op(s.c_str());
}


namespace detail {
template <typename I>
struct Range {
    I a, b;

    struct iterator : std::iterator_traits<std::forward_iterator_tag> {
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
} // namespace detail

template<typename I>
constexpr detail::Range<I> range(I end) { return detail::Range<I>{I(0), end}; }

template<typename I>
constexpr detail::Range<I> range(I begin, I end) { return detail::Range<I>{begin, end}; }

class RWLock
{
#ifdef _WIN32
    SRWLOCK lock;
public:
    inline RWLock() :_reader(*this), _writer(*this) { InitializeSRWLock(&lock); }
#else
    pthread_rwlock_t lock;
public:
    inline RWLock() :_reader(*this), _writer(*this) { pthread_rwlock_init(&lock, nullptr); }
    inline ~RWLock() { pthread_rwlock_destroy(&lock); }
#endif

    RWLock(const RWLock&) = delete;
    RWLock(RWLock&&) = delete;
    RWLock& operator=(const RWLock&) = delete;
    RWLock& operator=(RWLock&&) = delete;

    class Reader {
        RWLock& rw;
    public:
        Reader(RWLock& rw) : rw(rw) {}
#ifdef _WIN32
        inline void lock() { AcquireSRWLockShared(&rw.lock); }
        inline void unlock() { ReleaseSRWLockShared(&rw.lock); }
#else
        inline void lock() { pthread_rwlock_rdlock(&rw.lock); }
        inline void unlock() { pthread_rwlock_unlock(&rw.lock); }
#endif
    } _reader;
    inline Reader& reader() { return _reader; }

    class Writer {
        RWLock& rw;
    public:
        Writer(RWLock& rw) : rw(rw) {}
#ifdef _WIN32
        inline void lock() { AcquireSRWLockExclusive(&rw.lock); }
        inline void unlock() { ReleaseSRWLockExclusive(&rw.lock); }
#else
        inline void lock() { pthread_rwlock_wrlock(&rw.lock); }
        inline void unlock() { pthread_rwlock_unlock(&rw.lock); }
#endif
    } _writer;
    inline Writer& writer() { return _writer; }
};


void logger_shutdown();

} // namespace pvxsimpl

#endif // UTILPVT_H
