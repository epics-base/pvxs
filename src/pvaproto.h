/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVAPROTO_H
#define PVAPROTO_H

#include <compilerDependencies.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <type_traits>
#include <initializer_list>

#include <type_traits>

#include <epicsEndian.h>

#include <event2/buffer.h>
#include <pvxs/version.h>

namespace pvxs {namespace impl {

//! view of a slice of a buffer.
//! Don't use directly.  cf. FixedBuf<E>
template<typename E, typename Subclass>
struct BufCommon {
    typedef E value_type;
    typedef void is_buffer;

protected:
    // valid range to read/write is [pos, limit)
    E *pos, *limit;
    bool err;

    constexpr BufCommon(bool be, E* buf, size_t n) :pos(buf), limit(buf+n), err(false), be(be) {}
public:
    const bool be;

    // all sub-classes define
    //   bool refill(size_t more)

    EPICS_ALWAYS_INLINE void fault() { err = true; }
    EPICS_ALWAYS_INLINE bool good() const { return !err; }

    // ensure (be resize/refill) that size()>=i
    inline bool ensure(size_t i) {
        return !err && (i<=size() || static_cast<Subclass*>(this)->refill(i));
    }
    inline void skip(size_t i) {
        do {
            if(i<=size()) {
                pos += i;
                return;
            }
            pos = limit;
            i -= size();
        } while(static_cast<Subclass*>(this)->refill(i));
        fault();
    }

    EPICS_ALWAYS_INLINE bool empty() const { return limit==pos; }
    EPICS_ALWAYS_INLINE size_t size() const { return limit-pos; }

    // the following assume good()==true && !empty()
    EPICS_ALWAYS_INLINE E& operator[](size_t i) const { return pos[i]; }
    EPICS_ALWAYS_INLINE void push(E v) { *pos++ = v; }
    EPICS_ALWAYS_INLINE E pop() { return *pos++; }
    // further assumes size()>=i
    EPICS_ALWAYS_INLINE void _skip(size_t i) { pos+=i; }

    E* save() const { return this->pos; }
};

//! (de)serialization to/from buffers which are fixed size and contigious
template<typename E>
struct FixedBuf : public BufCommon<E, FixedBuf<E> >
{
    typedef BufCommon<E, FixedBuf> base_type;
    EPICS_ALWAYS_INLINE bool refill(size_t more) { return false; }

    template<size_t N>
    constexpr FixedBuf(bool be, E(&buf)[N]) :base_type(be, buf, N) {}
    constexpr FixedBuf(bool be, E* buf, size_t n) :base_type(be, buf, n) {}
    FixedBuf(bool be, std::vector<E>& buf) :base_type(be, buf.data(), buf.size()) {}
};

//! serialize into a vector, resizing as necessary
class VectorOutBuf : public BufCommon<uint8_t, VectorOutBuf>
{
    typedef BufCommon<uint8_t, VectorOutBuf> base_type;
    std::vector<uint8_t>& backing;
public:
    // note: vector::data() is not constexpr in c++11
    VectorOutBuf(bool be, std::vector<uint8_t>& b)
        :base_type(be, b.data(), b.size())
        ,backing(b)
    {}
    PVXS_API bool refill(size_t more);
};

//! serialize into an evbuffer, resizing as necessary
class EvOutBuf : public BufCommon<uint8_t, EvOutBuf>
{
    typedef BufCommon<uint8_t, EvOutBuf> base_type;
    evbuffer * const backing;
    uint8_t* base; // original pos
public:

    EvOutBuf(bool be, evbuffer *b, size_t isize=0)
        :base_type(be, nullptr, 0)
        ,backing(b)
        ,base(nullptr)
    {refill(isize);}
    ~EvOutBuf()
    {refill(0);}
    PVXS_API bool refill(size_t more);
};

//! deserialize from an evbuffer, possibly segmented
class EvInBuf : public BufCommon<uint8_t, EvInBuf>
{
    typedef BufCommon<uint8_t, EvInBuf> base_type;
    evbuffer * const backing;
    uint8_t* base; // original pos after ctor or refill()
public:

    EvInBuf(bool be, evbuffer *b, size_t ifill=0)
        :base_type(be, nullptr, 0)
        ,backing(b)
        ,base(nullptr)
    {refill(ifill);}
    ~EvInBuf()
    {refill(0);}

    PVXS_API bool refill(size_t more);
};

template <unsigned N, typename Buf>
inline void _from_wire(Buf& buf, uint8_t *mem, bool reverse)
{
    if(!buf.ensure(N)) {
        buf.fault();
        return;

    } else if(reverse) {
        // byte order mis-match
        for(unsigned i=0; i<N; i++) {
            mem[i] = buf[N-1-i];
        }
    } else {
        for(unsigned i=0; i<N; i++) {
            mem[i] = buf[i];
        }
    }
    buf._skip(N);
}

/** Read sizeof(T) bytes from buf and store in val
 *
 * @param buf input buffer.  buf[0] through buf[sizeof(T)-1] must be valid.
 * @param val output variable
 * @param be  true if value encoded in buf is in MSBF order, false if in LSBF order
 */
template<typename T, typename Buf, typename std::enable_if<std::is_scalar<T>::value, int>::type =0>
inline void from_wire(Buf& buf, T& val)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    _from_wire<sizeof(T)>(buf, pun.b, buf.be ^ (EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG));
    if(buf.good())
        val = pun.v;
}

//! wrapper to disambiguate size_t from uint32_t or uint64_t.
//!
//! __Always__ initialize w/ zero for sane behavour on error.
//! @code
//!   sbuf M;
//!   Size blen{0};
//!   from_wire(M, blen, be);
//!   for(auto n : range(blen)) { // well defined, even if M.err==true
//! @endcode
struct Size {
    size_t size;
};

template<typename Buf>
void from_wire(Buf& buf, Size& size)
{
    if(!buf.ensure(1)) {
        buf.fault();
        return;
    }
    uint8_t s=buf.pop();
    if(s<254) {
        size.size = s;

    } else if(s==255) {
        // "null" size.  not sure it is used.
        // Replicate weirdness of pvDataCPP
        // FIXME this is almost certainly a bug
        size.size = -1;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls);
        size.size = ls;

    } else {
        // unreachable (64-bit size so far not used)
        buf.fault();
    }
}

struct Status {
    enum type_t {
        Ok  =0,
        Warn=1,
        Error=2,
        Fatal=3,
    } code;
    std::string msg;
    std::string trace;

    inline bool isSuccess() const { return code==Ok || code==Warn; }
};

template<typename Buf>
void to_wire(Buf& buf, const Status& sts)
{
    if(!buf.ensure(1)) {
        buf.fault();

    } else if(sts.code==Status::Ok && sts.msg.empty() && sts.trace.empty()) {
        buf.push(255);

    } else {
        buf.push(sts.code);
        to_wire(buf, sts.msg.c_str());
        to_wire(buf, sts.trace.c_str());
    }
}

template<typename Buf>
void from_wire(Buf& buf, Status& sts)
{
    if(!buf.ensure(1)) {
        buf.fault();

    } else if(255==buf[0]) {
        buf._skip(1);
        sts.code = Status::Ok;
        sts.msg.clear();
        sts.trace.clear();

    } else {
        sts.code = buf.pop();
        from_wire(buf, sts.msg);
        from_wire(buf, sts.trace);
    }
}

template<typename Buf>
void from_wire(Buf& buf, std::string& s)
{
    Size len{0};
    from_wire(buf, len);
    if(!buf.ensure(len.size)) {
        buf.fault();

    } else {
        s = std::string((char*)buf.save(), len.size);
        buf._skip(len.size);
    }
}

// assumes prior buf.ensure(M) where M>=N
template<unsigned N, typename Buf>
inline void _to_wire(Buf& buf, const uint8_t *mem, bool reverse)
{
    if(!buf.ensure(N)) {
        buf.fault();
        return;

    } else if(reverse) {
        // byte order mis-match
        for(unsigned i=0; i<N; i++) {
            buf[N-1-i] = mem[i];
        }
    } else {
        for(unsigned i=0; i<N; i++) {
            buf[i] = mem[i];
        }
    }
    buf._skip(N);
}

/** Write sizeof(T) bytes from buf from val
 *
 * @param buf output buffer.  buf[0] through buf[sizeof(T)-1] must be valid.
 * @param val input variable
 */
template<typename T, typename Buf, typename std::enable_if<sizeof(T)>=2 && std::is_scalar<T>{} && !std::is_pointer<T>{}, int>::type =0>
inline void to_wire(Buf& buf, const T& val)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    pun.v = val;
    _to_wire<sizeof(T)>(buf, pun.b, buf.be ^ (EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG));
}

template<typename T, typename Buf, typename std::enable_if<sizeof(T)==1 && std::is_scalar<T>{}, int>::type =0>
inline void to_wire(Buf& buf, const T& val)
{
    if(!buf.ensure(1)) {
        buf.fault();
    } else {
        buf.push(val);
    }
}

template<typename Buf>
void to_wire(Buf& buf, const Size& size)
{
    if(!buf.ensure(1)) {
        buf.fault();

    } else if(size.size<254) {
        buf.push(size.size);

    } else if(size.size<=0xffffffff) {
        buf.push(254);
        to_wire(buf, uint32_t(size.size));

    } else {
        buf.fault();
    }
}

template<typename Buf>
void to_wire(Buf& buf, const char *s)
{
    Size len{s ? strlen(s) : 0};
    to_wire(buf, len);
    if(!buf.ensure(len.size)) {
        buf.fault();

    } else {
        for(size_t i=0; i<len.size; i++)
            buf.push(s[i]);
    }

}

template<typename Buf>
inline void to_wire(Buf& buf, const std::string& s)
{
    to_wire(buf, s.c_str());
}

template<typename Buf>
void to_wire(Buf& buf, std::initializer_list<uint8_t> bytes)
{
    if(!buf.ensure(bytes.size())) {
        buf.fault();

    } else {
        for (auto byte : bytes) {
            buf.push(byte);
        }
    }

}

/* PVA Message Header
 *
 *       0     1      2      3
 * 0 | 0xCA | ver | flags | cmd |
 * 4 |           size           |
 */

struct pva_version {
    enum {
        client = 2,
        server = 2,
    };
};

/* values from flags field of header
 * flags[0] - 0 app, 1 control
 * flags[1:3] - unused
 * flags[4:5] - 00 - not segmented, 01 - first segment, 11 - middle segment, 10 - last segment
 * flags[6] - 0 - client, 1 - server
 * flags[7] - 0 - LSB, 1 - MSB
 */
struct pva_flags {
    enum type_t : uint8_t {
        Control = 0x01,
        SegNone = 0x00,
        SegFirst= 0x10,
        SegLast = 0x20,
        SegMask = 0x30,
        Server = 0x40,
        MSB = 0x80,
    };
};

struct pva_ctrl_msg {
    enum type_t : uint8_t {
        SetMarker = 0,
        AckMarker = 1,
        SetEndian = 2,
    };
};

enum pva_app_msg_t : uint8_t {
    CMD_BEACON = 0,
    CMD_CONNECTION_VALIDATION = 1,
    CMD_ECHO = 2,
    CMD_SEARCH = 3,
    CMD_SEARCH_RESPONSE = 4,
    CMD_AUTHNZ = 5,
    CMD_ACL_CHANGE = 6,
    CMD_CREATE_CHANNEL = 7,
    CMD_DESTROY_CHANNEL = 8,
    CMD_CONNECTION_VALIDATED = 9,
    CMD_GET = 10,
    CMD_PUT = 11,
    CMD_PUT_GET = 12,
    CMD_MONITOR = 13,
    CMD_ARRAY = 14,
    CMD_DESTROY_REQUEST = 15,
    CMD_PROCESS = 16,
    CMD_GET_FIELD = 17,
    CMD_MESSAGE = 18,
    CMD_MULTIPLE_DATA = 19,
    CMD_RPC = 20,
    CMD_CANCEL_REQUEST = 21,
    CMD_ORIGIN_TAG = 22
};

struct pva_search_flags {
    enum type_t : uint8_t {
        MustReply = 0x01,
        Unicast   = 0x80,
    };
};

struct Header {
    uint8_t cmd, flags;
    uint32_t len;
};

template<typename Buf>
void to_wire(Buf& buf, const Header& H)
{
    if(!buf.ensure(8)) {
        buf.fault();

    } else {
        buf[0] = 0xca;
        buf[1] = (H.flags&pva_flags::Server) ? pva_version::server : pva_version::client;
        buf[2] = H.flags;
        if(buf.be)
            buf[2] |= pva_flags::MSB;
        buf[3] = H.cmd;
        buf._skip(4);
        to_wire(buf, H.len);
    }
}

void to_evbuf(evbuffer *buf, const Header& H, bool be);

}} // namespace pvxs::impl

#endif // PVAPROTO_H
