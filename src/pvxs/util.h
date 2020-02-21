/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_UTIL_H
#define PVXS_UTIL_H

#include <functional>
#include <ostream>
#include <type_traits>

#include <osiSock.h>
#include <event2/util.h>

#ifdef _WIN32
#  include <ws2ipdef.h>
#endif

#include <pvxs/version.h>

namespace pvxs {

namespace detail {
// ref. wrapper to mark string for escaping
class Escaper
{
    const char* val;
    size_t count;
    friend std::ostream& operator<<(std::ostream& strm, const Escaper& esc);
public:
    PVXS_API explicit Escaper(const char* v);
    constexpr explicit Escaper(const char* v, size_t l) :val(v),count(l) {}
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Escaper& esc);

} // namespace detail

//! Print string to output stream with non-printable charactors escaped.
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
//! Print nil terminated char array to output stream with non-printable charactors escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"");
//! @endcode
inline detail::Escaper escape(const char* s) {
    return detail::Escaper(s);
}
//! Print fixed length char array to output stream with non-printable charactors escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"", 6);
//!   // prints 'this \"'
//! @endcode
inline detail::Escaper escape(const char* s,size_t n) {
    return detail::Escaper(s,n);
}

#if !defined(__rtems__) && !defined(vxWorks)

//! minimal portable process signal handling in CLI tools
class PVXS_API SigInt {
    void (*prevINT)(int);
    void (*prevTERM)(int);
    std::function<void()> handler;
    static void _handle(int);
public:
    SigInt(decltype (handler)&& handler);
    ~SigInt();
};

#else // !defined(__rtems__) && !defined(vxWorks)

class SigInt {
public:
    SigInt(std::function<void()>&& handler) {}
}

#endif // !defined(__rtems__) && !defined(vxWorks)

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

} // namespace pvxs

#endif // PVXS_UTIL_H
