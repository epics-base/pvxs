/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef OSISOCKEXT_H
#define OSISOCKEXT_H

#include <osiSock.h>

#include <string>

#include <event2/util.h>

#include <pvxs/version.h>

namespace pvxs {

PVXS_API
void osiSockAttachExt();

struct SockAttach {
    SockAttach() { osiSockAttachExt(); }
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
    SockAddr withPort(unsigned short port) const {
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

    inline int compare(const SockAddr& o, bool useport=true) const {
        return evutil_sockaddr_cmp(&store.sa, &o.store.sa, useport);
    }

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

// compare address only, ignore port number
struct SockAddrOnlyLess {
    bool operator()(const SockAddr& lhs, const SockAddr& rhs) const {
        return lhs.compare(rhs, false)<0;
    }
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const SockAddr& addr);

// Linux specific include OS dropped packet counter as cmsg
void enable_SO_RXQ_OVFL(SOCKET sock);
// Include destination address as cmsg
PVXS_API
void enable_IP_PKTINFO(SOCKET sock);

struct recvfromx {
    evutil_socket_t sock;
    void *buf;
    size_t buflen;
    SockAddr* src;
    SockAddr* dst;  // if enable_IP_PKTINFO()
    int64_t dstif;  // if enable_IP_PKTINFO(), destination interface index
    uint32_t ndrop; // if enable_SO_RXQ_OVFL()

    PVXS_API
    int call();
};

} // namespace pvxs

#endif // OSISOCKEXT_H
