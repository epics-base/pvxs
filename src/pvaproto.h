/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVAPROTO_H
#define PVAPROTO_H

#include <compilerDependencies.h>
#include <cstdint>

#include <type_traits>

#include <epicsEndian.h>

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

//! ref. wrapper to disambiguate in case size_t and uint64_t are the same type
template<typename T>
struct Size {
    T* size;
    explicit Size(T& size) :size(&size) {}
};

template<typename B>
void from_wire(sbuf<B>& buf, Size<size_t> size, bool be)
{
    if(buf.err || buf.empty()) {
        buf.err = true;
        return;
    }
    uint8_t s=buf[0];
    buf+=1;
    if(s<254) {
        *size.size = s;

    } else if(s==255) {
        // "null" size.  not sure it is used.  Replicate weirdness of pvDataCPP
        *size.size = -1;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls, be);
        *size.size = ls;
    } else {
        // unreachable
        buf.err = true;
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
template<typename T, typename std::enable_if<std::is_pod<T>::value, int>::type =0>
inline void to_wire(sbuf<uint8_t>& buf, const T& val, bool be)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    pun.v = val;
    _to_wire<sizeof(T)>(buf, pun.b, be ^ (EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG));
}

PVXS_API
void to_wire(sbuf<uint8_t>& buf, Size<const size_t> size, bool be);

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
    enum type_t {
        Control = 0x01,
        SegMask = 0x30,
        Server = 0x40,
        MSB = 0x80,
    };
};

struct pva_app_msg {
    enum type_t {
        Beacon       = 0x00,
        ConnValid    = 0x01,
        Echo         = 0x02,
        Search       = 0x03,
        SearchReply  = 0x04,
        // unused 0x5, 0x6
        CreateChan   = 0x07,
        DestroyChan  = 0x08,
        // unused 0x9
        GetOp        = 0x0A,
        PutOp        = 0x0B,
        PutGetOp     = 0x0C,
        MonitorOp    = 0x0D,
        ArrayOp      = 0x0E,
        DestoryOp    = 0x0F,
        ProcessOp    = 0x10,
        Introspect   = 0x11,
        Message      = 0x12,
        // unused 0x13
        RPCOp        = 0x14,
        CancelOp     = 0x15,
        // ...
        OriginTag = 0x16
    };
};

} // namespace pvxsimpl

#endif // PVAPROTO_H
