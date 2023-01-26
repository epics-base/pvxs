/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_UTIL_H
#define PVXS_UTIL_H

#include <map>
#include <array>
#include <deque>
#include <functional>
#include <iosfwd>
#include <type_traits>
#include <stdexcept>
#include <memory>

#include <osiSock.h>
#include <epicsEvent.h>
#include <epicsMutex.h>
#include <epicsGuard.h>

#include <pvxs/version.h>

namespace pvxs {

namespace detail {
// ref. wrapper to mark string for escaping
class Escaper
{
    const char* val;
    size_t count;
    friend
    PVXS_API
    std::ostream& operator<<(std::ostream& strm, const Escaper& esc);
public:
    PVXS_API explicit Escaper(const char* v);
    constexpr explicit Escaper(const char* v, size_t l) :val(v),count(l) {}
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Escaper& esc);

} // namespace detail

//! Print string to output stream with non-printable characters escaped.
//!
//! Outputs (almost) C-style escapes.
//! Prefers short escapes for newline, tab, quote, etc ("\\n").
//! Falls back to hex escape (eg. "\xab").
//!
//! Unlike C, hex escapes are always 2 chars.  eg. the output "\xabcase"
//! would need to be manually changed to "\xab""case" to be used as C source.
//!
//! @code
//!   std::string blah("this \"is a test\"");
//!   std::cout<<pvxs::escape(blah);
//! @endcode
inline detail::Escaper escape(const std::string& s) {
    return detail::Escaper(s.c_str(), s.size());
}
//! Print nil terminated char array to output stream with non-printable characters escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"");
//! @endcode
inline detail::Escaper escape(const char* s) {
    return detail::Escaper(s);
}
//! Print fixed length char array to output stream with non-printable characters escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"", 6);
//!   // prints 'this \"'
//! @endcode
inline detail::Escaper escape(const char* s,size_t n) {
    return detail::Escaper(s,n);
}

struct ServerGUID : public std::array<uint8_t, 12> {};

PVXS_API
std::ostream& operator<<(std::ostream&, const ServerGUID&);

#if !defined(__rtems__) && !defined(vxWorks)

/** Portable process signal handling in CLI tools.
 *
 * @code
 *     epicsEvent evt;
 *     SigInt handle([&evt]() {
 *          evt.trigger();
 *     });
 *     ... setup network operations
 *     evt.wait();
 *     // completion, or SIGINT
 * @endcode
 *
 * Saves existing handler, which are restored by dtor.
 *
 * @since 1.1.0 "handler" action runs in thread context.
 *              Safe to take locks etc.
 *              Previously handler action ran in signal handler context.
 */
class PVXS_API SigInt {
public:
    //! Install signal handler.
    SigInt(const std::function<void()>&& handler);
    SigInt(const SigInt&) = delete;
    ~SigInt();
    struct Pvt;
private:
    std::shared_ptr<Pvt> pvt;
};

#else // !defined(__rtems__) && !defined(vxWorks)

class SigInt {
    const std::function<void()> handler;
public:
    SigInt(std::function<void()>&& handler) :handler(std::move(handler)) {}
};

#endif // !defined(__rtems__) && !defined(vxWorks)

//! return a snapshot of internal instance counters
PVXS_API
std::map<std::string, size_t> instanceSnapshot();

//! See Indented
struct indent {};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const indent&);

//! Scoped indentation for std::ostream
struct PVXS_API Indented {
    explicit Indented(std::ostream& strm, int depth=1);
    Indented(const Indented&) = delete;
    Indented(Indented&& o) noexcept
        :strm(o.strm)
        ,depth(o.depth)
    {
        o.strm = nullptr;
        o.depth = 0;
    }
    ~Indented();
private:
    std::ostream *strm;
    int depth;
};

struct PVXS_API Detailed {
    explicit Detailed(std::ostream& strm, int lvl=1);
    Detailed(const Detailed&) = delete;
    Detailed(Detailed&& o) noexcept
        :strm(o.strm)
        ,lvl(o.lvl)
    {
        o.strm = nullptr;
        o.lvl = 0;
    }
    ~Detailed();
    static
    int level(std::ostream& strm);
private:
    std::ostream *strm;
    int lvl;
};

/** Describe build and runtime configuration of current system.
 *
 * Print information which may be using for when troubleshooting,
 * or creating a bug report.
 *
 * Printed by CLI "pvxinfo -D" and iocsh "pvxs_target_information".
 *
 * @returns The same ostream passed as argument.
 */
PVXS_API
std::ostream& target_information(std::ostream&);

/** Thread-safe, bounded, multi-producer, multi-consumer FIFO queue.
 *
 * Queue value_type must be movable.  If T is also copy constructable,
 * then push(const T&) may be used.
 *
 * As an exception, the destructor is not re-entrant.  Concurrent calls
 * to methods during destruction will result in undefined behavior.
 *
 * @code
 * MPMCFIFO<std::function<void()>> Q;
 * ...
 * while(auto work = Q.pop()) { // Q.push(nullptr) to break loop
 *     work();
 * }
 * @endcode
 *
 * @since 0.2.0
 */
template<typename T>
class MPMCFIFO {
    mutable epicsMutex lock;
    epicsEvent notifyW, notifyR;
    std::deque<T> Q;
    const size_t nlimit;
    unsigned nwriters=0u, nreaders=0u;

    typedef epicsGuard<epicsMutex> Guard;
    typedef epicsGuardRelease<epicsMutex> UnGuard;
public:
    //! Template parameter
    typedef T value_type;

    //! Construct a new queue
    //! @param limit If non-zero, then emplace()/push() will block while while
    //!              queue size is greater than or equal to this limit.
    explicit MPMCFIFO(size_t limit=0u)
        :nlimit(limit)
    {}
    //! Destructor is not re-entrant
    ~MPMCFIFO() {}

    //! Poll number of elements in the work queue at this moment.
    size_t size() const {
        Guard G(lock);
        return Q.size();
    }
    size_t max_size() const {
        return nlimit ? nlimit : Q.max_size();
    }

    /** Construct a new element into the queue.
     *
     * Will block while full.
     */
    template<typename ...Args>
    void emplace(Args&&... args) {
        bool wakeup;
        {
            Guard G(lock);
            // while full, wait for reader to consume an entry
            while(nlimit && Q.size()>=nlimit) {
                nwriters++;
                {
                    UnGuard U(G);
                    notifyW.wait();
                }
                nwriters--;
            }
            // notify reader when queue becomes not empty
            wakeup = Q.empty() && nreaders;
            Q.emplace_back(std::forward<Args>(args)...);
        }
        if(wakeup)
            notifyR.signal();
    }

    //! Move a new element to the queue
    void push(T&& ent) {
        // delegate to T::T(T&&)
        emplace(std::move(ent));
    }

    //! Copy a new element to the queue
    void push(const T& ent) {
        // delegate to T::T(const T&)
        emplace(ent);
    }

    /** Remove an element from the queue.
     *
     * Blocks while queue is empty.
     */
    T pop() {
        bool wakeupW, wakeupR;
        T ret;
        {
            Guard G(lock);
            // wait for queue to become not empty
            while(Q.empty()) {
                nreaders++;
                {
                    UnGuard U(G);
                    notifyR.wait();
                }
                nreaders--;
            }
            // wakeup a writer since the queue will have an empty entry
            wakeupW = nwriters;
            ret = std::move(Q.front());
            Q.pop_front();
            // wakeup next reader if entries remain
            wakeupR = !Q.empty() && nreaders;
        }
        if(wakeupR)
            notifyR.signal();
        if(wakeupW)
            notifyW.signal();
        return ret;
    }
};

struct Timer;

#ifdef PVXS_EXPERT_API_ENABLED

//! Timer associated with a client::Context or server::Server
//! @since 0.2.0
struct PVXS_API Timer {
    struct Pvt;

    //! dtor implicitly cancel()s
    ~Timer();
    //! Explicit cancel.
    //! @returns true if the timer was running, and now is not.
    bool cancel();

    explicit operator bool() const { return pvt.operator bool(); }

private:
    std::shared_ptr<Pvt> pvt;
    friend struct Pvt;
};

#endif // PVXS_EXPERT_API_ENABLED

} // namespace pvxs

#endif // PVXS_UTIL_H
