/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iomanip>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include <ctype.h>

#include <epicsStdlib.h>

#include <pvxs/util.h>
#include <pvxs/sharedArray.h>
#include <pvxs/data.h>
#include "utilpvt.h"
#include "udp_collector.h"

namespace pvxs {

#define stringify(X) #X

const char *version_str()
{
    return "PVXS " stringify(PVXS_MAJOR_VERSION);
}

unsigned long version_int()
{
    return PVXS_VERSION;
}

void cleanup_for_valgrind()
{
    impl::logger_shutdown();
    impl::UDPManager::cleanup();
}

std::ostream& operator<<(std::ostream& strm, ArrayType code)
{
    switch(code) {
#define CASE(CODE) case ArrayType::CODE : strm<<#CODE; break
    CASE(Null);
    CASE(Bool);
    CASE(UInt8);
    CASE(UInt16);
    CASE(UInt32);
    CASE(UInt64);
    CASE(Int8);
    CASE(Int16);
    CASE(Int32);
    CASE(Int64);
    CASE(Float);
    CASE(Double);
    CASE(Value);
#undef CASE
    default:
        strm<<"<\?\?\?>";
    }
    return strm;
}

std::ostream& operator<<(std::ostream& strm, const shared_array<const void>& arr)
{
    switch(arr.original_type()) {
    case ArrayType::Null: strm<<"[null]"; break;
#define CASE(CODE, Type) case ArrayType::CODE: strm<<shared_array_static_cast<const Type>(arr); break
    CASE(Bool, bool);
    CASE(UInt8, uint8_t);
    CASE(UInt16, uint16_t);
    CASE(UInt32, uint32_t);
    CASE(UInt64, uint64_t);
    CASE(Int8, int8_t);
    CASE(Int16, int16_t);
    CASE(Int32, int32_t);
    CASE(Int64, int64_t);
    CASE(Float, float);
    CASE(Double, double);
    CASE(String, std::string);
    CASE(Value, Value);
#undef CASE
    }
    return strm;
}

std::ostream& operator<<(std::ostream& strm, const shared_array<void>& arr)
{
    switch(arr.original_type()) {
    case ArrayType::Null: strm<<"[null]"; break;
#define CASE(CODE, Type) case ArrayType::CODE: strm<<shared_array_static_cast<Type>(arr); break
    CASE(Bool, bool);
    CASE(UInt8, uint8_t);
    CASE(UInt16, uint16_t);
    CASE(UInt32, uint32_t);
    CASE(UInt64, uint64_t);
    CASE(Int8, int8_t);
    CASE(Int16, int16_t);
    CASE(Int32, int32_t);
    CASE(Int64, int64_t);
    CASE(Float, float);
    CASE(Double, double);
    CASE(String, std::string);
    CASE(Value, Value);
#undef CASE
    }
    return strm;
}

namespace detail {

Escaper::Escaper(const char* v)
    :val(v)
    ,count(v ? strlen(v) : 0)
{}

std::ostream& operator<<(std::ostream& strm, const Escaper& esc)
{
    const char *s = esc.val;
    if(!s) {
        strm<<"<NULL>";
    } else {
        for(size_t n=0; n<esc.count; n++,s++) {
            char c = *s, next;
            switch(c) {
            case '\a': next = 'a'; break;
            case '\b': next = 'b'; break;
            case '\f': next = 'f'; break;
            case '\n': next = 'n'; break;
            case '\r': next = 'r'; break;
            case '\t': next = 't'; break;
            case '\v': next = 'v'; break;
            case '\\': next = '\\'; break;
            case '\'': next = '\''; break;
            default:
                if(isprint(c)) {
                    strm.put(c);
                } else {
                    strm<<"\\x"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c&0xff);
                }
                continue;
            }
            strm.put('\\').put(next);
        }
    }
    return strm;
}


} // namespace detail

SockAddr::SockAddr(int af)
{
    memset(&store, 0, sizeof(store));
    store.sa.sa_family = af;
    if(af!=AF_INET
#ifdef AF_INET6
            && af!=AF_INET6
#endif
            && af!=AF_UNSPEC)
        throw std::invalid_argument("Unsupported address family");
}

SockAddr::SockAddr(int af, const char *address, unsigned short port)
    :SockAddr(af)
{
    setAddress(address, port);
}

SockAddr::SockAddr(const sockaddr *addr, ev_socklen_t len)
    :SockAddr(addr->sa_family)
{
    if(len<0 || len>ev_socklen_t(size()))
        throw std::invalid_argument("Truncated Address");
    memcpy(&store, addr, len);
}

size_t SockAddr::size() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return sizeof(store.in);
#ifdef AF_INET6
    case AF_INET6: return sizeof(store.in6);
#endif
    default: // AF_UNSPEC and others
        return sizeof(store);
    }
}

unsigned short SockAddr::port() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return ntohs(store.in.sin_port);
#ifdef AF_INET6
    case AF_INET6:return ntohs(store.in6.sin6_port);
#endif
    default: return 0;
    }
}

void SockAddr::setPort(unsigned short port)
{
    switch(store.sa.sa_family) {
    case AF_INET: store.in.sin_port = htons(port); break;
#ifdef AF_INET6
    case AF_INET6:store.in6.sin6_port = htons(port); break;
#endif
    default:
        throw std::logic_error("SockAddr: set family before port");
    }
}

void SockAddr::setAddress(const char *name, unsigned short port)
{
    SockAddr temp;
    int templen = sizeof(temp.store);
    if(evutil_parse_sockaddr_port(name, &temp->sa, &templen))
        throw std::runtime_error(std::string("Unable to parse as IP addresss: ")+name);
    if(temp.port()==0)
        temp.setPort(port);
    (*this) = temp;
}

bool SockAddr::isAny() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_ANY);
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_UNSPECIFIED(&store.in6.sin6_addr);
#endif
    default: return false;
    }
}

bool SockAddr::isLO() const
{
    switch(store.sa.sa_family) {
    case AF_INET: return store.in.sin_addr.s_addr==htonl(INADDR_LOOPBACK);
#ifdef AF_INET6
    case AF_INET6: return IN6_IS_ADDR_LOOPBACK(&store.in6.sin6_addr);
#endif
    default: return false;
    }
}

std::string SockAddr::tostring() const
{
    std::ostringstream strm;
    strm<<(*this);
    return strm.str();
}

SockAddr SockAddr::any(int af, unsigned port)
{
    SockAddr ret(af);
    switch(af) {
    case AF_INET:
        ret->in.sin_addr.s_addr = htonl(INADDR_ANY);
        ret->in.sin_port = htons(port);
        break;
#ifdef AF_INET6
    case AF_INET6:
        ret->in6.sin6_addr = IN6ADDR_ANY_INIT;
        ret->in6.sin6_port = htons(port);
        break;
#endif
    default:
        throw std::invalid_argument("Unsupported address family");
    }
    return ret;
}

SockAddr SockAddr::loopback(int af, unsigned port)
{
    SockAddr ret(af);
    switch(af) {
    case AF_INET:
        ret->in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ret->in.sin_port = htons(port);
        break;
#ifdef AF_INET6
    case AF_INET6:
        ret->in6.sin6_addr = IN6ADDR_LOOPBACK_INIT;
        ret->in6.sin6_port = htons(port);
        break;
#endif
    default:
        throw std::invalid_argument("Unsupported address family");
    }
    return ret;
}

std::ostream& operator<<(std::ostream& strm, const SockAddr& addr)
{
    switch(addr->sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN+1];
        if(evutil_inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf))) {
            buf[sizeof(buf)-1] = '\0'; // paranoia
        } else {
            strm<<"<\?\?\?>";
        }
        strm<<buf<<':'<<ntohs(addr->in.sin_port);
        break;
    }
#ifdef AF_INET6
    case AF_INET6: {
            char buf[INET6_ADDRSTRLEN+1];
            if(evutil_inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf))) {
                buf[sizeof(buf)-1] = '\0'; // paranoia
            } else {
                strm<<"<\?\?\?>";
            }
            strm<<buf<<':'<<ntohs(addr->in6.sin6_port);
            break;
    }
#endif
    case AF_UNSPEC:
        strm<<"<>";
        break;
    default:
        strm<<"<\?\?\?>";
    }
    return strm;
}

}

namespace pvxs {namespace impl {
namespace idetail {

template<>
unsigned short as_str<unsigned short>::op(const char *s)
{
    epicsUInt16 ret;
    if(int err = epicsParseUInt16(s, &ret, 0, nullptr)) {
        (void)err;
        throw std::runtime_error(SB()<<"Unable to parse as uint16 : "<<s);
    }
    return ret;
}
}

void indent(std::ostream& strm, unsigned level) {
    for(auto i : range(level)) {
        (void)i;
        strm<<"    ";
    }
}

}}
