/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef EVHELPER_H
#define EVHELPER_H

#include <sstream>
#include <functional>
#include <memory>
#include <string>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>

#include <pvxs/version.h>
#include <utilpvt.h>

#include "pvaproto.h"

// hooks for std::unique_ptr
namespace std {
template<>
struct default_delete<event_config> {
    inline void operator()(event_config* ev) { event_config_free(ev); }
};
template<>
struct default_delete<event_base> {
    inline void operator()(event_base* ev) { event_base_free(ev); }
};
template<>
struct default_delete<event> {
    inline void operator()(event* ev) { event_free(ev); }
};
template<>
struct default_delete<evconnlistener> {
    inline void operator()(evconnlistener* ev) { evconnlistener_free(ev); }
};
template<>
struct default_delete<bufferevent> {
    inline void operator()(bufferevent* ev) { bufferevent_free(ev); }
};
template<>
struct default_delete<evbuffer> {
    inline void operator()(evbuffer* ev) { evbuffer_free(ev); }
};
}

namespace pvxs {namespace impl {

//! unique_ptr which is never constructed with NULL
template<typename T>
struct owned_ptr : public std::unique_ptr<T>
{
    constexpr owned_ptr() {}
    explicit owned_ptr(T* ptr) : std::unique_ptr<T>(ptr) {
        if(!*this)
            throw std::bad_alloc();
    }
};

/* It seems that std::function<void()>(Fn&&) from gcc (circa 8.3) and clang (circa 7.0)
 * always copies the functor/lambda.  We can't allow this when transferring ownership
 * of shared_ptr<> instances to a worker thread as it leaves the caller thread with a
 * reference.
 *
 * std::unique_ptr<int> arg{new int(42)};
 * // eg. with
 * auto lambda = [arg{std::move(arg)}]() { // c++14 capture w/ move
 *     auto trash(std::move(arg));
 * };
 * // or
 * auto lambda = std::bind([](std::unique_ptr<int>& arg) { // c++11 capture w/ move
 *     auto trash(std::move(arg));
 * }, std::move(arg));
 * // the following line tries to copy the unique_ptr which fails to compile
 * std::function<void()> fn(std::move(lambda));
 *
 * So we invent our own limited, non-copyable, version of std::function<void()>.
 */
namespace mdetail {
struct PVXS_API VFunctor0 {
    virtual ~VFunctor0() =0;
    virtual void invoke() =0;
};
template<typename Fn>
struct Functor0 : public VFunctor0 {
    Functor0() = default;
    Functor0(const Functor0&) = delete;
    Functor0(Functor0&&) = default;
    Functor0(Fn&& fn) : fn(std::move(fn)) {}
    virtual ~Functor0() {}

    void invoke() override final { fn(); }
private:
    Fn fn;
};
} // namespace detail

struct mfunction {
    mfunction() = default;
    template<typename Fn>
    mfunction(Fn&& fn)
        :fn{new mdetail::Functor0<Fn>(std::move(fn))}
    {}
    void operator()() const {
        fn->invoke();
    }
    explicit operator bool() const {
        return fn.operator bool();
    }
private:
    std::unique_ptr<mdetail::VFunctor0> fn;
};

struct PVXS_API evbase {
    evbase() = default;
    explicit evbase(const std::string& name, unsigned prio=0);
    ~evbase();

    evbase internal() const;

    void join() const;

    void sync() const;

private:
    bool _dispatch(mfunction&& fn, bool dothrow) const;
    bool _call(mfunction&& fn, bool dothrow) const;
public:

    // queue request to execute in event loop.  return after executed.
    inline
    void call(mfunction&& fn) const {
        _call(std::move(fn), true);
    }
    inline
    bool tryCall(mfunction&& fn) const {
        return _call(std::move(fn), false);
    }

    // queue request to execute in event loop.  return immediately.
    inline
    void dispatch(mfunction&& fn) const {
        _dispatch(std::move(fn), true);
    }
    inline
    bool tryDispatch(mfunction&& fn) const {
        return _dispatch(std::move(fn), false);
    }

    bool tryInvoke(bool docall, mfunction&& fn) const {
        if(docall)
            return tryCall(std::move(fn));
        else
            return tryDispatch(std::move(fn));
    }

    void assertInLoop() const;
    //! Caller must be on the worker, or the worker must be stopped.
    //! @returns true if working is running.
    bool assertInRunningLoop() const;

    inline void reset() { pvt.reset(); }

private:
    struct Pvt;
    std::shared_ptr<Pvt> pvt;
public:
    event_base* base = nullptr;
};

typedef owned_ptr<event_config> evconfig;
typedef owned_ptr<event> evevent;
typedef owned_ptr<evconnlistener> evlisten;
typedef owned_ptr<bufferevent> evbufferevent;
typedef owned_ptr<evbuffer> evbuf;

PVXS_API
void to_wire(Buffer& buf, const SockAddr& val);

PVXS_API
void from_wire(Buffer &buf, SockAddr& val);

struct PVXS_API evsocket
{
    evutil_socket_t sock;

    // default construct an invalid socket
    constexpr evsocket() noexcept :sock(-1) {}

    // construct from a valid (not -1) socket
    explicit evsocket(evutil_socket_t sock);

    // create a new socket
    evsocket(int, int, int);

    // movable
    evsocket(evsocket&& o) noexcept;
    evsocket& operator=(evsocket&&) noexcept;

    // not copyable
    evsocket(const evsocket&) = delete;
    evsocket& operator=(const evsocket&) = delete;

    ~evsocket();

    // test validity
    inline operator bool() const { return sock!=-1; }

    void bind(SockAddr& addr) const;
    //! join mcast group.  Receive mcasts send to this group which arrive on the given interface
    //! @see IP_ADD_MEMBERSHIP
    void mcast_join(const SockAddr& grp, const SockAddr& iface) const;
    //! Set time-to-live out mcasts sent from this socket
    //! @see IP_MULTICAST_TTL
    void mcast_ttl(unsigned ttl) const;
    //! Whether mcasts sent from this socket should be received to local listeners
    //! @see IP_MULTICAST_LOOP
    void mcast_loop(bool loop) const;
    //! Selects interface to use when sending mcasts
    //! @see IP_MULTICAST_IF
    void mcast_iface(const SockAddr& iface) const;

    //! wraps osiSockDiscoverBroadcastAddresses()
    std::vector<SockAddr> interfaces(const SockAddr* match=nullptr);
};

} // namespace impl


#ifdef PVXS_EXPERT_API_ENABLED

struct Timer::Pvt {
    const evbase base;
    std::function<void()> cb;
    evevent timer;

    Pvt(const evbase& base, std::function<void()>&& cb)
        :base(base), cb(std::move(cb))
    {}
    ~Pvt();

    bool cancel();

    static
    Timer buildOneShot(double delay, const evbase &base, std::function<void()>&& cb);

    INST_COUNTER(Timer);
};

#endif // PVXS_EXPERT_API_ENABLED

} // namespace pvxs

#endif /* EVHELPER_H */
