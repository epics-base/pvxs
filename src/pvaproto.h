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
#include <pvxs/sharedArray.h>
#include <pvxs/log.h>
#include "utilpvt.h"

namespace pvxs {namespace impl {

constexpr bool hostBE{EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG};

//! view of a slice of a buffer.
//! Don't use directly.  cf. FixedBuf
struct PVXS_API Buffer {
    typedef uint8_t value_type;
    typedef void is_buffer;

protected:
    // valid range to read/write is [pos, limit)
    uint8_t *pos, *limit;

    // this is a static __FILE__ string
    const char* err = nullptr;
    int errline = -1;

    virtual bool refill(size_t more);

    constexpr Buffer(bool be, uint8_t* buf, size_t n) :pos(buf), limit(buf+n), be(be) {}
    virtual ~Buffer() {}
public:
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    bool be;

    // all sub-classes define
    //   bool refill(size_t more)

    // would be nice to use GCC specific __builtin_FILE() and __builtin_LINE() here,
    // but MSVC has nothing equivalent :(
    EPICS_ALWAYS_INLINE void fault(const char *fname, int lineno) {
        if(!err) {
            err = fname;
            errline = lineno;
        }
    }
    EPICS_ALWAYS_INLINE bool good() const { return !err; }
    inline const char* file() const { return err ? err : "(null)"; }
    EPICS_ALWAYS_INLINE int line() const { return errline; }

    // ensure (be resize/refill) that size()>=i
    inline bool ensure(size_t i) {
        return !err && (i<=size() || refill(i));
    }
    inline void skip(size_t i, const char *fname, int lineno) {
        do {
            if(i<=size()) {
                pos += i;
                return;
            }
            pos = limit;
            i -= size();
        } while(refill(i));
        fault(fname, lineno);
    }

    EPICS_ALWAYS_INLINE bool empty() const { return limit==pos; }
    EPICS_ALWAYS_INLINE size_t size() const { return limit-pos; }

    // the following assume good()==true && !empty()
    EPICS_ALWAYS_INLINE uint8_t& operator[](size_t i) const { return pos[i]; }
    EPICS_ALWAYS_INLINE void push(uint8_t v) { *pos++ = v; }
    EPICS_ALWAYS_INLINE uint8_t pop() { return *pos++; }
    // further assumes size()>=i
    EPICS_ALWAYS_INLINE void _skip(size_t i) { pos+=i; }

    uint8_t* save() const { return pos; }
    void restore(uint8_t* p) { pos = p; }
};

//! (de)serialization to/from buffers which are fixed size and contiguous
struct PVXS_API FixedBuf : public Buffer
{
    typedef Buffer base_type;
    virtual bool refill(size_t more) override final { return false; }

    // for "uint8_t msg[] = "..."; // assumes extraneous trailing nil
    template<size_t N>
    constexpr FixedBuf(bool be, uint8_t(&buf)[N]) :base_type(be, buf, N-1) {}
    constexpr FixedBuf(bool be, uint8_t* buf, size_t n) :base_type(be, buf, n) {}
    FixedBuf(bool be, std::vector<uint8_t>& buf) :base_type(be, buf.data(), buf.size()) {}
    virtual ~FixedBuf();
};

//! serialize into a vector, resizing as necessary
class PVXS_API VectorOutBuf : public Buffer
{
    typedef Buffer base_type;
    std::vector<uint8_t>& backing;
public:
    // note: vector::data() is not constexpr in c++11
    VectorOutBuf(bool be, std::vector<uint8_t>& b)
        :base_type(be, b.data(), b.size())
        ,backing(b)
    {}
    virtual ~VectorOutBuf();
    virtual bool refill(size_t more) override final;

    inline
    size_t consumed() const { return pos - backing.data(); }
};

//! serialize into an evbuffer, resizing as necessary
class PVXS_API EvOutBuf : public Buffer
{
    typedef Buffer base_type;
    evbuffer * const backing;
    uint8_t* base; // original pos
public:

    EvOutBuf(bool be, evbuffer *b, size_t isize=0)
        :base_type(be, nullptr, 0)
        ,backing(b)
        ,base(nullptr)
    {refill(isize);}
    virtual ~EvOutBuf();
    virtual bool refill(size_t more) override final;
};

//! deserialize from an evbuffer, possibly segmented
class PVXS_API EvInBuf : public Buffer
{
    typedef Buffer base_type;
    evbuffer * const backing;
    uint8_t* base; // original pos after ctor or refill()
public:

    EvInBuf(bool be, evbuffer *b, size_t ifill=0)
        :base_type(be, nullptr, 0)
        ,backing(b)
        ,base(nullptr)
    {refill(ifill);}
    virtual ~EvInBuf();

    virtual bool refill(size_t more) override final;
};

// assumes prior buf.ensure(M) where M>=N
template<unsigned N>
inline void _to_wire(Buffer& buf, const uint8_t *mem, bool reverse, const char *fname, int lineno)
{
    if(!buf.ensure(N)) {
        buf.fault(fname, lineno);
        return;

    } else if(reverse) {
        // byte order mismatch
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

template <unsigned N>
inline void _from_wire(Buffer& buf, uint8_t *mem, bool reverse, const char *fname, int lineno)
{
    if(!buf.ensure(N)) {
        buf.fault(fname, lineno);
        return;

    } else if(reverse) {
        // byte order mismatch
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

/** Write sizeof(T) bytes from buf from val
 *
 * @param buf output buffer.  buf[0] through buf[sizeof(T)-1] must be valid.
 * @param val input variable
 */
template<typename T, typename std::enable_if<sizeof(T)>=2 && std::is_scalar<T>::value && !std::is_pointer<T>::value, int>::type =0>
inline void to_wire(Buffer& buf, const T& val)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    pun.v = val;
    _to_wire<sizeof(T)>(buf, pun.b, buf.be ^ hostBE, __FILE__, __LINE__);
}

template<typename T, typename std::enable_if<sizeof(T)==1 && std::is_scalar<T>::value, int>::type =0>
inline void to_wire(Buffer& buf, const T& val)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);
    } else {
        buf.push(val);
    }
}

/** Read sizeof(T) bytes from buf and store in val
 *
 * @param buf input buffer.  buf[0] through buf[sizeof(T)-1] must be valid.
 * @param val output variable
 * @param be  true if value encoded in buf is in MSBF order, false if in LSBF order
 */
template<typename T, typename std::enable_if<std::is_scalar<T>::value, int>::type =0>
inline void from_wire(Buffer& buf, T& val)
{
    union {
        T v;
        uint8_t b[sizeof(T)];
    } pun;
    _from_wire<sizeof(T)>(buf, pun.b, buf.be ^ hostBE, __FILE__, __LINE__);
    if(buf.good())
        val = pun.v;
}

//! wrapper to disambiguate size_t from uint32_t or uint64_t.
//!
//! __Always__ initialize w/ zero for sane behavior on error.
//! @code
//!   sbuf M;
//!   Size blen{0};
//!   from_wire(M, blen, be);
//!   for(auto n : range(blen)) { // well defined, even if M.err==true
//! @endcode
struct Size {
    size_t size;
};

inline
void to_wire(Buffer& buf, const Size& size)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);

    } else if(size.size<254) {
        buf.push(uint8_t(size.size));

    } else if(size.size<=0xffffffff) {
        buf.push(254);
        to_wire(buf, uint32_t(size.size));

    } else {
        buf.fault(__FILE__, __LINE__);
    }
}

inline
void from_wire(Buffer& buf, Size& size, bool allow_null=false)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);
        return;
    }
    uint8_t s=buf.pop();
    if(s<254) {
        size.size = s;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls);
        size.size = ls;

    } else if(s==255 && allow_null) {
        // special "null" which is used (maybe by pvDataJava?) for an empty string
        size.size = size_t(-1);

    } else {
        buf.fault(__FILE__, __LINE__);
    }
}

// Encoded the same as Size, with the added special -1 to represent a "null" value.
// should never by < -1
struct Selector {
    ev_ssize_t select;
    // should always be >= -1, but check < -1 from paranoia
    bool isnull() const { return select<=-1; }
    size_t index() const { return size_t(select); }
};

inline
void to_wire(Buffer& buf, const Selector& sel)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);

    } else if(sel.select<=-1) { // should never be < -1, but paranoia...
        // special "null"  used to encode empty Union
        buf.push(255);

    } else if(sel.select<254) {
        buf.push(uint8_t(sel.select));

    } else if(sel.select<=ev_ssize_t(0xffffffff)) {
        buf.push(254);
        to_wire(buf, uint32_t(sel.select));

    } else {
        buf.fault(__FILE__, __LINE__);
    }
}

inline
void from_wire(Buffer& buf, Selector& sel)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);
        return;
    }
    uint8_t s=buf.pop();
    if(s<254) {
        sel.select = s;

    } else if(s==254) {
        uint32_t ls = 0;
        from_wire(buf, ls);
        sel.select = ls;

    } else if(s==255) {
        // special "null" used to encode empty Union
        sel.select = -1;

    } else {
        buf.fault(__FILE__, __LINE__);
    }
    // assert(sel.select>=-1);
}

inline
void to_wire_str(Buffer& buf, const char *s, size_t cnt)
{
    Size len{cnt};
    to_wire(buf, len);
    if(!buf.ensure(len.size)) {
        buf.fault(__FILE__, __LINE__);

    } else {
        memcpy(buf.save(), s, len.size);
        buf._skip(len.size);
    }

}

inline
void to_wire(Buffer& buf, const char *s)
{
    to_wire_str(buf, s, s ? strlen(s) : 0);
}

inline void to_wire(Buffer& buf, const std::string& s)
{
    to_wire_str(buf, s.c_str(), s.size());
}

inline
void from_wire(Buffer& buf, std::string& s)
{
    Size len{0};
    from_wire(buf, len, true);
    if(len.size==size_t(-1)) { // pvAccessJava will serialize null differently than ""
        s.clear();

    } else if(!buf.ensure(len.size)) {
        buf.fault(__FILE__, __LINE__);

    } else {
        s = std::string((char*)buf.save(), len.size);
        buf._skip(len.size);
    }
}

inline
void to_wire(Buffer& buf, std::initializer_list<uint8_t> bytes)
{
    if(!buf.ensure(bytes.size())) {
        buf.fault(__FILE__, __LINE__);

    } else {
        for (auto byte : bytes) {
            buf.push(byte);
        }
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

    static inline Status error(const std::string& msg, const std::string& trace = std::string())
    {
        return Status{Error, msg, trace};
    }
};

inline
void to_wire(Buffer& buf, const Status& sts)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);

    } else if(sts.code==Status::Ok && sts.msg.empty() && sts.trace.empty()) {
        buf.push(255);

    } else {
        buf.push(sts.code);
        to_wire(buf, sts.msg.c_str());
        to_wire(buf, sts.trace.c_str());
    }
}

inline
void from_wire(Buffer& buf, Status& sts)
{
    if(!buf.ensure(1)) {
        buf.fault(__FILE__, __LINE__);

    } else if(255==buf[0]) {
        buf._skip(1);
        sts.code = Status::Ok;
        sts.msg.clear();
        sts.trace.clear();

    } else {
        sts.code = Status::type_t(buf.pop());
        from_wire(buf, sts.msg);
        from_wire(buf, sts.trace);
    }
}

template<typename E, typename C = E>
static inline
void to_wire(Buffer& buf, const shared_array<const void>& varr)
{
    auto arr = varr.castTo<const E>();
    to_wire(buf, Size{arr.size()});

    if(std::is_pod<C>::value) {
        // optimize handling of types with fixed element size

        auto src = reinterpret_cast<const char*>(arr.data());

        for(size_t nremain = arr.size()*sizeof(C); nremain;) {
            if(!buf.ensure(sizeof(C))) {
                buf.fault(__FILE__, __LINE__);
                break;
            }

            // rounds down to element size.  requires sizeof(C) by a power of 2
            size_t nbytes = std::min(buf.size(), nremain)&~(sizeof(C)-1u);

            if(buf.be==hostBE) { // already in native order, just copy
                memcpy(buf.save(), src, nbytes);

            } else { // must swap byte order
                auto dest = buf.save();

                for(size_t i=0; i<nbytes; i+=sizeof(C)) {
                    for(size_t n=0u; n<sizeof(C); n++) {
                        dest[i + sizeof(C)-1-n] = src[i + n];

                    }
                }
            }

            src += nbytes;
            buf.skip(nbytes, __FILE__, __LINE__);
            nremain -= nbytes;
        }

    } else {
        // handle variable size element types
        for(auto i : range(arr.size())) {
            to_wire(buf, C(arr[i]));
        }
    }
}

template<typename E, typename C = E>
static inline
void from_wire(Buffer& buf, shared_array<const void>& varr)
{
    Size slen{};
    from_wire(buf, slen);
    shared_array<E> arr(slen.size);

    if(std::is_pod<C>::value) {
        // optimize handling of types with fixed element size

        auto dest = reinterpret_cast<char*>(arr.data());

        for(size_t nremain = arr.size()*sizeof(C); nremain;) {
            if(!buf.ensure(sizeof(C))) {
                buf.fault(__FILE__, __LINE__);
                break;
            }

            // rounds down to element size.  requires sizeof(C) by a power of 2
            size_t nbytes = std::min(buf.size(), nremain)&~(sizeof(C)-1u);

            if(buf.be==hostBE) { // already in native order, just copy
                memcpy(dest, buf.save(), nbytes);

            } else { // must swap byte order
                auto src = buf.save();

                for(size_t i=0; i<nbytes; i+=sizeof(C)) {
                    for(size_t n=0u; n<sizeof(C); n++) {
                        dest[i + sizeof(C)-1-n] = src[i + n];

                    }
                }
            }

            dest += nbytes;
            buf.skip(nbytes, __FILE__, __LINE__);
            nremain -= nbytes;
        }

    } else {
        for(auto i : range(arr.size())) {
            C temp{};
            from_wire(buf, temp);
            arr[i] = temp;
        }
    }
    varr = arr.freeze().template castTo<const void>();
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

enum class pva_subcmd {
    Init = 0x08,
    Destroy = 0x10,
    Get  = 0x40,
};

struct Header {
    uint8_t cmd=0u, flags=0u, version=0u;
    uint32_t len=0u;
    constexpr Header() {}
    explicit
    constexpr Header(uint8_t cmd, uint8_t flags, uint32_t len)
        :cmd(cmd), flags(flags), version(0u), len(len)
    {}
};

template<typename Buf>
void to_wire(Buf& buf, const Header& H)
{
    if(!buf.ensure(8)) {
        buf.fault(__FILE__, __LINE__);

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

template<typename Buf>
void from_wire(Buf& buf, Header& H)
{
    if(!buf.ensure(8) || buf[0]!=0xca || buf[1]==0) {
        buf.fault(__FILE__, __LINE__);

    } else {
        H.cmd = buf[3];
        H.flags = buf[2];
        H.version = buf[1];
        // Set/change buffer endianness
        buf.be = H.flags&pva_flags::MSB;
        buf.skip(4u, __FILE__, __LINE__);
        from_wire(buf, H.len);
    }
}

// mapping between CMD_MESSAGE mtype and logging Level

inline
Level mtype2level(uint8_t mtype)
{
    switch(mtype) {
    case 0:  return Level::Info;
    case 1:  return Level::Warn;
    case 2:  return Level::Err;
    default: return Level::Crit;
    }
}

inline
uint8_t level2mtype(Level lvl)
{
    switch(lvl) {
    case Level::Debug:
    case Level::Info: return 0;
    case Level::Warn: return 1;
    case Level::Err:  return 2;
    case Level::Crit: return 3;
    }
    return 3;
}

}} // namespace pvxs::impl

#endif // PVAPROTO_H
