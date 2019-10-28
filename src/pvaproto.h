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
#include <initializer_list>

#include <type_traits>

#include <epicsEndian.h>

#include <event2/buffer.h>
#include <pvxs/version.h>

namespace pvxsimpl {

//! Hold a bounded slice of some other array.
//! like std::span<T, std::dynamic_extent> (added in c++20)
//! blending in error state tracking like std::iostream
template<typename T>
struct sbuf {
    typedef T value_type;

    T *pos, *limit;
    bool err;

    sbuf(std::vector<T>& buf)
        :sbuf(buf.data(), buf.size())
    {}
    sbuf(T *buf, size_t size)
        :pos(buf), limit(buf+size)
        ,err(false)
    {}

    inline bool empty() const { return limit==pos; }
    inline size_t size() const { return limit-pos; }
    inline T& operator[](size_t i) const { return pos[i]; }

    sbuf& operator+=(size_t n) {
        if(size()<n) {
            err = true;
        } else {
            pos += n;
        }
        return *this;
    }

    // partition owned sequence [0, size) at offset n
    // return [0, n), retain [n, size)
    sbuf split(size_t n) {
        if(size()<n) {
            err = true;
        }
        auto ret = sbuf(pos, n);
        ret.err = err;
        pos += n;
        return ret;
    }
};

template <unsigned N, typename B>
inline void _from_wire(sbuf<B>& buf, uint8_t *mem, bool reverse)
{
    if(buf.err || buf.size()<N) {
        buf.err = true;
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
    buf += N;
}

/** Read sizeof(T) bytes from buf and store in val
 *
 * @param buf input buffer.  buf[0] through buf[sizeof(T)-1] must be valid.
 * @param val output variable
 * @param be  true if value encoded in buf is in MSBF order, false if in LSBF order
 */
template<typename T, typename B, typename std::enable_if<std::is_scalar<T>::value, int>::type =0>
inline void from_wire(sbuf<B>& buf, T& val, bool be)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    _from_wire<sizeof(T)>(buf, pun.b, be ^ (EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG));
    if(!buf.err)
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

template<typename B>
void from_wire(sbuf<B>& buf, Size& size, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;
        return;
    }
    uint8_t s=buf[0];
    buf+=1;
    if(s<254) {
        size.size = s;

    } else if(s==255) {
        // "null" size.  not sure it is used.
        // Replicate weirdness of pvDataCPP
        // FIXME this is almost certainly a bug
        size.size = -1;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls, be);
        size.size = ls;

    } else {
        // unreachable (64-bit size so far not used)
        buf.err = true;
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
};

template<typename B>
void to_wire(sbuf<B>& buf, const Status& sts, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;

    } else if(sts.code==Status::Ok && sts.msg.empty()) {
        *buf.pos++ = 255;

    } else {
        *buf.pos++ = sts.code;
        to_wire(buf, sts.msg.c_str(), be);
    }
}

template<typename B>
void from_wire(sbuf<B>& buf, Status& sts, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;

    } else if(255==*buf.pos) {
        buf.pos++;
        sts.code = Status::Ok;
        sts.msg.clear();

    } else {
        sts.code = *buf.pos++;
        from_wire(buf, sts.msg, be);
    }
}

template<typename B>
void from_wire(sbuf<B>& buf, std::string& s, bool be)
{
    Size len{0};
    from_wire(buf, len, be);
    if(buf.err || buf.size()<len.size) {
        buf.err = true;

    } else {
        s = std::string((char*)buf.pos, len.size);
    }
}

template<unsigned N>
inline void _to_wire(sbuf<uint8_t>& buf, const uint8_t *mem, bool reverse)
{
    if(buf.err || buf.size()<N) {
        buf.err = true;
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
    buf += N;
}

/** Write sizeof(T) bytes from buf from val
 *
 * @param buf output buffer.  buf[0] through buf[sizeof(T)-1] must be valid.
 * @param val input variable
 * @param be  true to encode buf in MSBF order, false in LSBF order
 */
template<typename T, typename B, typename std::enable_if<std::is_scalar<T>::value, int>::type =0>
inline void to_wire(sbuf<B>& buf, const T& val, bool be)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    pun.v = val;
    _to_wire<sizeof(T)>(buf, pun.b, be ^ (EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG));
}

template<typename B>
void to_wire(sbuf<B>& buf, const Size& size, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;

    } else if(size.size<254) {
        *buf.pos++ = size.size;

    } else if(size.size<=0xffffffff) {
        *buf.pos++ = 254;
        to_wire(buf, uint32_t(size.size), be);

    } else {
        buf.err = true;
    }
}

template<typename B>
void to_wire(sbuf<B>& buf, const char *s, bool be)
{
    Size len{s ? strlen(s) : 0};
    to_wire(buf, len, be);
    if(buf.err || buf.size()<len.size) {
        buf.err = true;

    } else {
        for(size_t i=0; i<len.size; i++)
            *buf.pos++ = s[i];
    }

}

template<typename B>
void to_wire(sbuf<B>& buf, std::initializer_list<uint8_t> bytes, bool be)
{
    if(buf.err || buf.size()<bytes.size()) {
        buf.err = true;

    } else {
        for (auto byte : bytes) {
            *buf.pos++ = byte;
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

struct pva_app_msg {
    enum type_t : uint8_t {
        Beacon       = 0x00,
        ConnValid    = 0x01,
        Echo         = 0x02,
        Search       = 0x03,
        SearchReply  = 0x04,
        AuthZ        = 0x05,
        AclChange    = 0x06, // unused so far
        CreateChan   = 0x07,
        DestroyChan  = 0x08,
        ConnValidated= 0x09,
        GetOp        = 0x0A,
        PutOp        = 0x0B,
        PutGetOp     = 0x0C,
        MonitorOp    = 0x0D,
        ArrayOp      = 0x0E, // deprecating
        DestroyOp    = 0x0F,
        ProcessOp    = 0x10,
        Introspect   = 0x11,
        Message      = 0x12,
        MultipleData = 0x13, // premature optimization...
        RPCOp        = 0x14,
        CancelOp     = 0x15,
        OriginTag    = 0x16
    };
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

template<typename B>
void to_wire(sbuf<B>& buf, const Header& H, bool be)
{
    if(buf.err || buf.size()<8) {
        buf.err = true;

    } else {
        buf[0] = 0xca;
        buf[1] = (H.flags&pva_flags::Server) ? pva_version::server : pva_version::client;
        buf[2] = H.flags;
        if(be)
            buf[2] |= pva_flags::MSB;
        buf[3] = H.cmd;
        buf += 4;
        to_wire(buf, H.len, be);
    }
}

} // namespace pvxsimpl

#endif // PVAPROTO_H
