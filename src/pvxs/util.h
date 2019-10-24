/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_UTIL_H
#define PVXS_UTIL_H

#include <ostream>
#include <type_traits>

#include <event2/util.h>

#include <pvxs/version.h>

namespace pvxs {

namespace detail {
// ref. wrapper to mark string for escaping
class Escaper
{
    const char* val;
    friend std::ostream& operator<<(std::ostream& strm, const Escaper& esc);
public:
    constexpr explicit Escaper(const char* v) :val(v) {}
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Escaper& esc);

} // namespace detail

//! Print string to output string with non-printable charactors escaped.
//! @code
//!   std::string blah("this \"is a test\"");
//!   std::cout<<pvxs::escape(blah);
//! @endcode
inline detail::Escaper escape(const std::string& s) {
    return detail::Escaper(s.c_str());
}
//! Print string to output string with non-printable charactors escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"");
//! @endcode
inline detail::Escaper escape(const char* s) {
    return detail::Escaper(s);
}

//! representation of a network address
struct PVXS_API SockAddr {
    union store_t {
        sockaddr sa;
        sockaddr_in in;
#ifdef AF_INET6
        sockaddr_in6 in6;
#endif
    } store;

    SockAddr() :SockAddr(AF_UNSPEC) {}
    explicit SockAddr(int af);

    inline size_t size() const { return sizeof(store); }

    inline unsigned short family() const { return store.sa.sa_family; }
    unsigned short port() const;
    void setPort(unsigned short port);

    void setAddress(const char *);

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
