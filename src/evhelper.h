/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
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

#include "pvaproto.h"

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

//! prepare libevent for use by multiple threads
PVXS_API void evhelper_setup_thread();

//! Block the calling thread until any callback in-progress in the
//! specified loop has completed.
PVXS_API void evhelper_sync(event_base *base);

struct PVXS_API evbase {
    evbase();
    ~evbase();
    void start();

    void sync();

    // queue request to execute in event loop.  return immediately.
    void dispatch(std::function<void()>&& fn);
    // queue request to execute in event loop.  return after executed
    void call(std::function<void()>&& fn);

    void assertInLoop();

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

struct PVXS_API evsockaddr {
    union store_t {
        sockaddr sa;
        sockaddr_storage ss;
        sockaddr_in in;
        sockaddr_in6 in6;
    } store;

    evsockaddr() :evsockaddr(AF_UNSPEC) {}
    explicit evsockaddr(int af);
    explicit evsockaddr(const sockaddr_storage& ss);

    inline unsigned short family() const { return store.sa.sa_family; }
    unsigned short port() const;
    void setPort(unsigned short port);

    void setAddress(const char *);

    bool isLO() const;

    store_t* operator->() { return &store; }
    const store_t* operator->() const { return &store; }

    std::string tostring() const;

    static evsockaddr any(int af, unsigned port=0);
    static evsockaddr loopback(int af, unsigned port=0);

    //! encode as 16-byte ipv6 address
    void wire_encode(uint8_t* buf, bool be) const;
    void wire_decode(const uint8_t* buf, bool be);

    inline bool operator<(const evsockaddr& o) const {
        return evutil_sockaddr_cmp(&store.sa, &o.store.sa, true)<0;
    }
    inline bool operator==(const evsockaddr& o) const {
        return evutil_sockaddr_cmp(&store.sa, &o.store.sa, true)==0;
    }
    inline bool operator!=(const evsockaddr& o) const {
        return !(*this==o);
    }
};

PVXS_API
void to_wire(sbuf<uint8_t>& buf, const evsockaddr& val, bool be);

PVXS_API
void from_wire(sbuf<const uint8_t>& buf, evsockaddr& val, bool be);

PVXS_API
std::ostream& operator<<(std::ostream& strm, const evsockaddr& addr);

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

    void bind(evsockaddr& addr) const;
    //! join mcast group.  Receive mcasts send to this group which arrive on the given interface
    //! @see IP_ADD_MEMBERSHIP
    void mcast_join(const evsockaddr& grp, const evsockaddr& iface) const;
    //! Set time-to-live out mcasts sent from this socket
    //! @see IP_MULTICAST_TTL
    void mcast_ttl(unsigned ttl) const;
    //! Whether mcasts sent from this socket should be received to local listeners
    //! @see IP_MULTICAST_LOOP
    void mcast_loop(bool loop) const;
    //! Selects interface to use when sending mcasts
    //! @see IP_MULTICAST_IF
    void mcast_iface(const evsockaddr& iface) const;
};

} // namespace pvxsimpl

#endif /* EVHELPER_H */
