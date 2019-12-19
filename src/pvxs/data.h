/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_DATA_H
#define PVXS_DATA_H

#include <initializer_list>
#include <stdexcept>
#include <vector>
#include <ostream>
#include <memory>
#include <typeinfo>
#include <tuple>

#include <pvxs/version.h>
#include <pvxs/sharedArray.h>

namespace pvxs {
class Value;

//! selector for union FieldStorage::store
enum struct StoreType : uint8_t {
    Null,     //!< no associate storage
    UInteger, //!< uint64_t
    Integer,  //!< int64_t
    Real,     //!< double
    String,   //!< std::string
    Compound, //!< Value
    Array,    //!< shared_array<const void>
};

namespace impl {
struct FieldStorage;
struct FieldDesc;

//! maps T to one of the types which can be stored in the FieldStorage::store union
//! typename StorageMap<T>::store_t is, if existant, is one such type.
//! store_t shall be cast-able to/from T.
//! StorageMap<T>::code is the associated StoreType.
template<typename T, typename Enable=void>
struct StorageMap;

// map signed integers to int64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>{} && std::is_signed<T>{}>::type>
{ typedef int64_t store_t;  static constexpr StoreType code{StoreType::Integer}; };

// map unsigned integers, and bool, to uint64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>{} && !std::is_signed<T>{}>::type>
{ typedef uint64_t store_t; static constexpr StoreType code{StoreType::UInteger}; };

// map floating point to double.  (truncates long double, but then PVA doesn't >8 byte primatives anyway support anyway)
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_floating_point<T>{}>::type>
{ typedef double store_t;   static constexpr StoreType code{StoreType::Real}; };

template<>
struct StorageMap<std::string>
{ typedef std::string store_t;   static constexpr StoreType code{StoreType::String}; };

template<>
struct StorageMap<char*>
{ typedef std::string store_t;   static constexpr StoreType code{StoreType::String}; };

template<>
struct StorageMap<const char*>
{ typedef std::string store_t;   static constexpr StoreType code{StoreType::String}; };

template<>
struct StorageMap<shared_array<const void>>
{ typedef shared_array<const void> store_t;   static constexpr StoreType code{StoreType::Array}; };

template<>
struct StorageMap<Value>
{ typedef Value store_t;   static constexpr StoreType code{StoreType::Compound}; };

} // namespace impl

//! Groups of related types
enum struct Kind : uint8_t {
    Bool     = 0x00,
    Integer  = 0x20,
    Real     = 0x40,
    String   = 0x60,
    Compound = 0x80,
    Null     = 0xe0,
};

//! A particular type
struct TypeCode {
    //! actual complete (scalar) type code.
    enum code_t : uint8_t {
        Bool    = 0x00,
        BoolA   = 0x08,
        Int8    = 0x20,
        Int16   = 0x21,
        Int32   = 0x22,
        Int64   = 0x23,
        UInt8   = 0x24,
        UInt16  = 0x25,
        UInt32  = 0x26,
        UInt64  = 0x27,
        Int8A   = 0x28,
        Int16A  = 0x29,
        Int32A  = 0x2a,
        Int64A  = 0x2b,
        UInt8A  = 0x2c,
        UInt16A = 0x2d,
        UInt32A = 0x2e,
        UInt64A = 0x2f,
        Float32 = 0x42,
        Float64 = 0x43,
        Float32A= 0x4a,
        Float64A= 0x4b,
        String  = 0x60,
        StringA = 0x68,
        Struct  = 0x80,
        Union   = 0x81,
        Any     = 0x82,
        StructA = 0x88,
        UnionA  = 0x89,
        AnyA    = 0x8a,
        // 0xfd - cache update w/ full
        // 0xfe - cache fetch
        Null    = 0xff,
    };

    //! the actual type code.  eg. for switch()
    code_t code;

    bool valid() const;

    Kind    kind() const  { return Kind(code&0xe0); }
    //! size()==1<<order()
    uint8_t order() const { return code&3; }
    //! Size in bytes for simple kinds (Bool, Integer, Real)
    uint8_t size() const  { return 1u<<order(); }
    //! For Integer kind
    bool    isunsigned() const  { return code&0x04; }
    //! For all
    bool    isarray() const { return code&0x08; }

    constexpr TypeCode() :code(Null) {}
    constexpr explicit TypeCode(uint8_t c) :code(code_t(c)) {}
    constexpr TypeCode(code_t c) :code(c) {}

    //! associated array of type
    constexpr TypeCode arrayOf() const {return TypeCode{uint8_t(code|0x08)};}
    //! associated not array of type
    constexpr TypeCode scalarOf() const {return TypeCode{uint8_t(code&~0x08)};}

    //! name string.  eg. "bool" or "uint8_t"
    PVXS_API const char* name() const;
};

inline bool operator==(TypeCode lhs, TypeCode rhs) {
    return lhs.code==rhs.code;
}
inline bool operator!=(TypeCode lhs, TypeCode rhs) {
    return lhs.code!=rhs.code;
}
inline std::ostream& operator<<(std::ostream& strm, TypeCode c) {
    strm<<c.name();
    return strm;
}

struct Member {
    TypeCode code;
    std::string name;
    std::string id;
    std::vector<Member> children;

    Member(TypeCode code, const std::string& name, const std::string& id = std::string())
        :Member(code, name, id, {})
    {}
    PVXS_API
    Member(TypeCode code, const std::string& name, const std::string& id, std::initializer_list<Member> children);
    Member(TypeCode code, const std::string& name, std::initializer_list<Member> children)
        :Member(code, name , std::string(), children)
    {}
};

class PVXS_API TypeDef
{
public:
    struct Node;
private:
    std::shared_ptr<const Member> top;
public:
    TypeDef() = default;
    // moveable, copyable
    TypeDef(const TypeDef&) = default;
    TypeDef(TypeDef&&) = default;
    TypeDef& operator=(const TypeDef&) = default;
    TypeDef& operator=(TypeDef&&) = default;
    explicit TypeDef(const Value&);
    ~TypeDef();

    TypeDef(TypeCode code, const std::string& id, std::initializer_list<Member> children);
    TypeDef(TypeCode code, const std::string& id=std::string())
        :TypeDef(code, id, {})
    {}
    TypeDef(TypeCode code, std::initializer_list<Member> children)
        :TypeDef(code, std::string(), children)
    {}

    //TypeDef& operator+=(const Member& )

    Value create() const;

    friend
    std::ostream& operator<<(std::ostream& strm, const TypeDef&);
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const TypeDef&);

struct PVXS_API NoField : public std::runtime_error
{
    explicit NoField();
    virtual ~NoField();
};

struct PVXS_API NoConvert : public std::runtime_error
{
    explicit NoConvert();
    virtual ~NoConvert();
};

//! pointer-like reference to a single data field
class PVXS_API Value {
    friend class TypeDef;
    // (maybe) storage for this field.  alias of StructTop::members[]
    std::shared_ptr<impl::FieldStorage> store;
    // (maybe) owned thourgh StructTop (aliased as FieldStorage)
    const impl::FieldDesc* desc;
public:
    struct Helper;
    friend struct Helper;

    //! default empty Value
    constexpr Value() :desc(nullptr) {}
private:
    // Build new Value with the given type.  Used by TypeDef
    explicit Value(const std::shared_ptr<const impl::FieldDesc>& desc);
    Value(const std::shared_ptr<const impl::FieldDesc>& desc, Value& parent);
public:
    // movable and copyable
    Value(const Value&) = default;
    Value(Value&&) = default;
    Value& operator=(const Value&) = default;
    Value& operator=(Value&&) = default;
    ~Value();

    //! allocate new storage, with default values
    Value cloneEmpty() const;
    //! allocate new storage and copy in our values
    Value clone() const;
    //! copy values from other.  Must have matching types.
//    Value& assign(const Value&);

    Value allocMember();

    inline bool valid() const { return desc; }
    inline explicit operator bool() const { return desc; }

    bool isMarked(bool parents=true, bool children=false) const;
    void mark(bool v=true);
    void unmark(bool parents=false, bool children=true);

    TypeCode type() const;
    StoreType storageType() const;
    const std::string& id() const;
    bool idStartsWith(const std::string& prefix) const;

    //! test for instance equality.
    inline bool compareInst(const Value& o) { return store==o.store; }
//    int compareValue(const Value&);
//    int compareType(const Value&);

    // access to Value's ... value
    // not for Struct

    // use with caution
    void copyOut(void *ptr, StoreType type) const;
    //bool tryCopyOut(void *ptr, impl::StoreType type) const;
    void copyIn(const void *ptr, StoreType type);
    //bool tryCopyIn(const void *ptr, impl::StoreType type);

//    template<typename T>
//    inline bool tryAs(T& val) const {
//        return tryCopyOut(&val, std::type_index(typeid(std::decay<T>::type)));
//    }

    /** Extract value from field.
     */
    template<typename T>
    inline T as() const {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t ret;
        copyOut(&ret, map_t::code);
        return ret;
    }
//    template<typename T>
//    void as(T& val) const {
//        copyOut(&val, std::type_index(typeid(typename std::decay<T>::type)));
//    }

//    template<typename T>
//    inline bool tryFrom(const T& val) {
//        return tryCopyIn(&val, std::type_index(typeid(std::decay<T>::type)));
//    }

    template<typename T>
    void from(const T& val) {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t norm(val);
        copyIn(&norm, map_t::code);
    }

    // TODO T=Value is ambigious with previous assignment operator
    template<typename T>
    Value& operator=(const T& val) {
        from<T>(val);
        return *this;
    }

    // Struct/Union access
private:
    void traverse(const std::string& expr, bool modify);
public:

    //! attempt to decend into sub-structure
    Value operator[](const char *name);
    inline Value operator[](const std::string& name) { return (*this)[name.c_str()]; }
    const Value operator[](const char *name) const;
    inline const Value operator[](const std::string& name) const { return (*this)[name.c_str()]; }

private:
    template<typename V> friend class _iterator;
    // these cheat on const-ness
    void _step(const Value& child, bool next) const;
    void _first_child(const Value& child) const;

    template<typename V>
    class _iterator {
        V *parent;
        V child;
        friend class Value;
    public:
        _iterator() :parent(nullptr) {}
        explicit _iterator(V* parent) :parent(parent) {}

        V& operator*() { return child; }
        V* operator->() { return &child; }

        // ++(*this)
        inline _iterator& operator++() { parent->_step(child, true); return *this; }
        // (*this)++
        inline _iterator operator++(int) { _iterator ret(*this); parent->_step(child, true); return ret;}
        // --(*this)
        inline _iterator& operator--() { parent->_step(child, false); return *this; }
        // (*this)--
        inline _iterator operator--(int) { _iterator ret(*this); parent->_step(child, false); return ret;}

        inline bool operator==(const _iterator& o) const { return child.compareInst(o.child)==0; }
        inline bool operator!=(const _iterator& o) const { return !((*this)==o); }
    };
public:
    typedef _iterator<Value> iterator;
    typedef _iterator<const Value> const_iterator;

    inline iterator begin() { iterator ret(this); _first_child(ret.child); return ret;}
    inline const_iterator cbegin() const { const_iterator ret(this); _first_child(ret.child); return ret;}
    inline const_iterator begin() const { return cbegin(); }

    inline iterator end() { iterator ret(this); return ret;}
    inline const_iterator cend() const { const_iterator ret(this); return ret;}
    inline const_iterator end() const { return cend(); }
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Value& val);

} // namespace pvxs

#endif // PVXS_DATA_H
