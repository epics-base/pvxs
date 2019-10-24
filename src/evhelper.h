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
#include <event2/bufferevent.h>

#include <pvxs/version.h>
#include <utilpvt.h>

#include "pvaproto.h"

namespace pvxsimpl {
using namespace  pvxs;

struct PVXS_API evbase {
    explicit evbase(const std::string& name, unsigned prio=0);
    ~evbase();
    void start();

    void sync();

    // queue request to execute in event loop.  return immediately.
    void dispatch(std::function<void()>&& fn);
    // queue request to execute in event loop.  return after executed
    void call(std::function<void()>&& fn);

    void assertInLoop();
    bool inLoop();

private:
    struct Pvt;
    std::unique_ptr<Pvt> pvt;
public:
    event_base* const base;
};

struct PVXS_API evevent {
    event *ev;

    constexpr evevent() :ev(nullptr) {}
    evevent(struct event_base *base, evutil_socket_t sock, short mask, event_callback_fn fn, void *arg);
    ~evevent();
    evevent(evevent&&) noexcept;
    evevent& operator=(evevent&&) noexcept;
    evevent(const evevent&) = delete;
    evevent& operator=(const evevent&) = delete;

    operator bool() const { return ev; }
    operator event*() const { return ev; }

    void add(const timeval *tv=nullptr);
};

PVXS_API
void to_wire(sbuf<uint8_t>& buf, const SockAddr& val, bool be);

PVXS_API
void from_wire(sbuf<const uint8_t>& buf, SockAddr& val, bool be);

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
};

} // namespace pvxsimpl

#endif /* EVHELPER_H */
