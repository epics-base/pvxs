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
namespace impl {
class ValueBase;
}
class MValue;
class IValue;

//! selector for union FieldStorage::store
enum struct StoreType : uint8_t {
    Null,     //!< no associate storage
    Bool,     //!< bool
    UInteger, //!< uint64_t
    Integer,  //!< int64_t
    Real,     //!< double
    String,   //!< std::string
    Compound, //!< IValue
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

// map unsigned integers to uint64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>{} && !std::is_signed<T>{} && !std::is_same<T,bool>{}>::type>
{ typedef uint64_t store_t; static constexpr StoreType code{StoreType::UInteger}; };

// map floating point to double.  (truncates long double, but then PVA doesn't >8 byte primatives anyway support anyway)
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_floating_point<T>{}>::type>
{ typedef double store_t;   static constexpr StoreType code{StoreType::Real}; };

template<>
struct StorageMap<bool>
{ typedef bool store_t;   static constexpr StoreType code{StoreType::Bool}; };

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
struct StorageMap<IValue>
{ typedef IValue store_t;   static constexpr StoreType code{StoreType::Compound}; };

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

//! Definition of a member of a Struct/Union for use with TypeDef
struct Member {
    TypeCode code;
    std::string name;
    std::string id;
    std::vector<Member> children;

    //! Member for non-Compund
    //! @pre code.kind()!=Kind::Compound
    inline
    Member(TypeCode code, const std::string& name)
        :Member(code, name, {})
    {}
    //! Compound member with type ID
    PVXS_API
    Member(TypeCode code, const std::string& name, const std::string& id, std::initializer_list<Member> children);
    //! Compound member without type ID
    inline
    Member(TypeCode code, const std::string& name, std::initializer_list<Member> children)
        :Member(code, name , std::string(), children)
    {}

    PVXS_API
    void addChild(const Member& mem);
};

/** Helper functions for building TypeDef.
 *
 * Each of the TypeCode::code_t enums has an associated helper function of the same name
 * which is a shorthand notation for a Member().
 *
 * eg. @code members::UInt32("blah") @endcode is equivalent to @code Member(TypeCode::UInt32, "blah") @endcode
 */
namespace members {
#define CASE(TYPE) \
inline Member TYPE(const std::string& name) { return Member(TypeCode::TYPE, name); }
CASE(Bool)
CASE(UInt8)
CASE(UInt16)
CASE(UInt32)
CASE(UInt64)
CASE(Int8)
CASE(Int16)
CASE(Int32)
CASE(Int64)
CASE(Float32)
CASE(Float64)
CASE(String)
CASE(Any)
CASE(BoolA)
CASE(UInt8A)
CASE(UInt16A)
CASE(UInt32A)
CASE(UInt64A)
CASE(Int8A)
CASE(Int16A)
CASE(Int32A)
CASE(Int64A)
CASE(Float32A)
CASE(Float64A)
CASE(StringA)
CASE(AnyA)
#undef CASE

#define CASE(TYPE) \
inline Member TYPE(const std::string& name, std::initializer_list<Member> children) { return Member(TypeCode::TYPE, name, children); } \
inline Member TYPE(const std::string& name, const std::string& id, std::initializer_list<Member> children) { return Member(TypeCode::TYPE, name, id, children); }

CASE(Struct)
CASE(Union)
CASE(StructA)
CASE(UnionA)
#undef CASE
} // namespace members

/** Define a new type, either from scratch, or based on an existing Value
 *
 * @code
 * namespace M = pvxs::members;
 * auto def1 = TypeDef(TypeCode::Int32); // a single scalar field
 * auto def2 = TypeDef(TypeCode::Struct, {
 *     M::Int32("value"),
 *     M::Struct("alarm", "alarm_t", {
 *         M::Int32("severity"),
 *     }),
 *
 * auto val = def2.create(); // instanciate a Value
 * });
 * @endcode
 */
class PVXS_API TypeDef
{
public:
    struct Node;
private:
    std::shared_ptr<const Member> top;
    std::shared_ptr<const impl::FieldDesc> desc;
public:
    //! new, empty, definition
    TypeDef() = default;
    // moveable, copyable
    TypeDef(const TypeDef&) = default;
    TypeDef(TypeDef&&) = default;
    TypeDef& operator=(const TypeDef&) = default;
    TypeDef& operator=(TypeDef&&) = default;
    //! pre-populate definition based on provided Value
    explicit TypeDef(const impl::ValueBase&);
    ~TypeDef();

    //! new definition with id and children.  code must be TypeCode::Struct or TypeCode::Union
    TypeDef(TypeCode code, const std::string& id, std::initializer_list<Member> children);
    //! new definition for a single scalar field.  code must __not__ be TypeCode::Struct or TypeCode::Union
    TypeDef(TypeCode code)
        :TypeDef(code, std::string(), {})
    {}
    //! new definition without id.  code must be TypeCode::Struct or TypeCode::Union
    TypeDef(TypeCode code, std::initializer_list<Member> children)
        :TypeDef(code, std::string(), children)
    {}

    //! append additional children.  Only for TypeCode::Struct or TypeCode::Union
    TypeDef& operator+=(std::initializer_list<Member> children);

    //! Instanciate this definition
    MValue create() const;

    friend
    std::ostream& operator<<(std::ostream& strm, const TypeDef&);
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const TypeDef&);

//! Thrown when accessing a Null Value
struct PVXS_API NoField : public std::runtime_error
{
    explicit NoField();
    virtual ~NoField();
};

//! Thrown when a Value can not be converted to the requested type
struct PVXS_API NoConvert : public std::runtime_error
{
    explicit NoConvert();
    virtual ~NoConvert();
};

namespace impl {
class PVXS_API ValueBase
{
public:
    struct Helper;
protected:
    // (maybe) storage for this field.  alias of StructTop::members[]
    std::shared_ptr<impl::FieldStorage> store;
    // (maybe) owned thourgh StructTop (aliased as FieldStorage)
    const impl::FieldDesc* desc;

    friend class ::pvxs::MValue;
    friend class ::pvxs::IValue;
    friend class ::pvxs::TypeDef;

    constexpr ValueBase() :desc(nullptr) {}
    // Build new Value with the given type.  Used by TypeDef
    explicit ValueBase(const std::shared_ptr<const impl::FieldDesc>& desc);
    // movable and copyable
    ValueBase(const ValueBase&) = default;
    ValueBase(ValueBase&& o) noexcept
        :desc(o.desc)
    {
        store = std::move(o.store);
        o.desc = nullptr;
    }
    ValueBase& operator=(const ValueBase&) = default;
    ValueBase& operator=(ValueBase&& o) noexcept {
        store = std::move(o.store);
        desc = o.desc;
        o.desc = nullptr;
        return *this;
    }
    ~ValueBase();
public:

    //! allocate new storage, with default values
    MValue cloneEmpty() const;
    //! allocate new storage and copy in our values
    MValue clone() const;

    //! Does this Value actual reference some underlying storage
    inline bool valid() const { return desc; }
    inline explicit operator bool() const { return desc; }

    //! Test if this field is marked as valid/changed
    bool isMarked(bool parents=true, bool children=false) const;

    //! Type of the referenced field (or Null)
    TypeCode type() const;
    //! Type of value stored in referenced field
    StoreType storageType() const;
    //! Type ID string (Struct or Union only)
    const std::string& id() const;
    //! Test prefix of Type ID string (Struct or Union only)
    bool idStartsWith(const std::string& prefix) const;

    //! test for instance equality.
    inline bool compareInst(const ValueBase& o) const { return store==o.store; }
//    int compareValue(const Value&) const;
    inline int compareType(const ValueBase& o) const { return desc==o.desc; }

    /** Return our name for a decendent field.
     * @code
     *   Value v = ...;
     *   assert(v.nameOf(v["some.field"])=="some.field");
     * @endcode
     * @throws NoField unless both this and decendent are valid()
     * @throws std::logic_error if decendent is not actually a decendent
     */
    const std::string& nameOf(const ValueBase& decendent) const;

    // access to Value's ... value
    // not for Struct

    // use with caution
    void copyOut(void *ptr, StoreType type) const;
    bool tryCopyOut(void *ptr, StoreType type) const;

    /** Extract from field.
     *
     * Type 'T' may be one of:
     * - bool
     * - uint8_t, uint16_t, uint32_t, uint64_t
     * - int8_t, int16_t, int32_t, int64_t
     * - float, double
     * - std::string
     * - Value
     * - shared_array<const void>
     */
    template<typename T>
    inline T as() const {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t ret;
        copyOut(&ret, map_t::code);
        return ret;
    }

    //! Attempt to extract value from field.
    //! @returns false if as<T>() would throw NoField or NoConvert
    template<typename T>
    inline bool as(T& val) const {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t temp;
        auto ret = tryCopyOut(&temp, map_t::code);
        if(ret) {
            val = temp;
        }
        return ret;
    }

    //! Attempt to extract value from field.
    //! If possible, this value is cast to T and passed as the only argument
    //! of the provided function.
    template<typename T, typename FN>
    void as(FN&& fn) const {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t val;
        if(tryCopyOut(&val, map_t::code)) {
            fn(val);
        }
    }

    // Struct/Union access
protected:
    void traverse(const std::string& expr, bool modify);
public:

    template<typename V>
    class Iterable;
protected:
    struct IterInfo {
        // when Marked==true, index of next potentially unmarked field.
        // all [pos, nextcheck) are marked
        size_t pos;
        size_t nextcheck;
        bool marked;
        bool depth;
        constexpr IterInfo() :pos(0u), nextcheck(0u), marked(false), depth(false) {}
        constexpr IterInfo(size_t pos, bool marked, bool depth)
            :pos(pos), nextcheck(pos), marked(marked), depth(depth)
        {}
    };
    template<typename V>
    class Iter : private IterInfo {
        V *ref;
        constexpr Iter(V* ref, size_t pos, bool marked, bool depth)
            :IterInfo(pos, marked, depth), ref(ref)
        {}
        friend class Value;
        friend class Iterable<V>;
    public:
        Iter() {}

        V operator*() const { V ret; ref->_iter_deref(*this, ret); return ret; }
        Iter& operator++() {
            pos++;
            if(marked && pos >= nextcheck)
                ref->_iter_advance(*this);
            return *this;
        }
        Iter operator++(int) {
            Iter ret(*this);
            pos++;
            if(marked && pos >= nextcheck)
                ref->_iter_advance(*this);
            return ret;
        }
        bool operator==(const Iter& o) const { return pos == o.pos; }
        bool operator!=(const Iter& o) const { return !(o==*this); }
    };
    template<typename V>
    friend class Iter;

    void _iter_fl(IterInfo& info, bool first) const;
    void _iter_advance(IterInfo& info) const;
    void _iter_deref(const IterInfo& info, ValueBase& fld) const;
public:

    template<typename V>
    class Iterable {
        typedef Iter<V> iterator;
        V* owner;
        bool marked;
        bool depth;
    public:
        constexpr Iterable(V* owner, bool marked, bool depth) :owner(owner), marked(marked), depth(depth) {}
        iterator begin() const {
            iterator ret{owner, 0u, marked, depth};
            owner->_iter_fl(ret, true);
            return ret;
        }
        iterator end() const {
            iterator ret{owner, 0u, marked, depth};
            owner->_iter_fl(ret, false);
            return ret;
        }
    };
};
} // namespace impl

/** Mutable reference to a structure field
 */
class PVXS_API MValue : public impl::ValueBase{
public:
    constexpr MValue() = default;
protected:
    friend class impl::ValueBase;
    friend class TypeDef;
    friend struct impl::ValueBase::Helper;
    // Build new Value with the given type.  Used by TypeDef
    explicit MValue(const std::shared_ptr<const impl::FieldDesc>& desc) : impl::ValueBase(desc) {}
public:
    // movable and copyable
    MValue(const MValue&) = default;
    MValue(MValue&& o) = default;
    MValue& operator=(const MValue&) = default;
    MValue& operator=(MValue&& o) = default;
public:
    /** Exchange mutable MValue for an immutable IValue
     *
     * This MValue must be the only reference to the underlying structure.
     * If not, then an exception is thrown.
     * On success, this MValue is consumed and becomes invalid.
     *
     * @post !valid()
     * @throws std::runtime_error If this MValue is not the only reference
     */
    IValue freeze();

    //! copy values from other.  Must have matching types.
    MValue& assign(const impl::ValueBase&);

    //! Use to allocate members for an array of Struct and array of Union
    MValue allocMember() const;

    //! Mark this field as valid/changed
    void mark(bool v=true);
    //! Remove mark from this field
    void unmark(bool parents=false, bool children=true);

    void copyIn(const void *ptr, StoreType type);
    bool tryCopyIn(const void *ptr, StoreType type);

    //! Attempt to assign to field.
    //! @returns false if from<T>() would throw NoField or NoConvert
    template<typename T>
    inline bool tryFrom(const T& val) {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t norm(val);
        return copyIn(&norm, map_t::code);
    }

    /** Assign from field.
     *
     * Type 'T' may be one of:
     * - bool
     * - uint8_t, uint16_t, uint32_t, uint64_t
     * - int8_t, int16_t, int32_t, int64_t
     * - float, double
     * - std::string
     * - Value
     * - shared_array<const void>
     */
    template<typename T>
    MValue& from(const T& val) {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t norm(val);
        copyIn(&norm, map_t::code);
        return *this;
    }

    //! shorthand for from<T>(const T&)
    //! except for T=IValue to avoid ambiguity between this assignment of value and previous assignment of reference.
    template<typename T>
    typename std::enable_if<!std::is_same<T, IValue>{}, MValue&>::type
    operator=(const T& val) {
        return from<T>(val);
    }

    /** In-line assignment of sub-field value
     *
     *  Short-hand notation equivalent to
     *  @code
     *    (*this)[field].from(val);
     *  @endcode
     *
     *  Example usage
     *  @code
     *     IValue result = nt::NTScalar{TypeCode::Int32}
     *                  .create()
     *                  .update("value", 42)
     *                  .update("alarm.severity", 0);
     *                  .freeze();
     *  @endcode
     */
    template<typename T, typename K>
    MValue& update(const K& field, const T& val) {
        (*this)[field].from(val);
        return *this;
    }

    //! attempt to decend into sub-structure
    MValue operator[](const char *name) const {
        MValue ret(*this);
        ret.traverse(name, true);
        return ret;
    }
    inline MValue operator[](const std::string& name) const { return (*this)[name.c_str()]; }

    Iterable<MValue> iall()      { return Iterable<MValue>{this, false, true}; }
    Iterable<MValue> ichildren() { return Iterable<MValue>{this, false, false}; }
    Iterable<MValue> imarked()   { return Iterable<MValue>{this, true , true}; }

    Iterable<const MValue> iall() const      { return Iterable<const MValue>{this, false, true}; }
    Iterable<const MValue> ichildren() const { return Iterable<const MValue>{this, false, false}; }
    Iterable<const MValue> imarked() const   { return Iterable<const MValue>{this, true , true}; }
};

class PVXS_API IValue : public impl::ValueBase
{
public:
    constexpr IValue() = default;
    // movable and copyable
    IValue(const IValue&) = default;
    IValue(IValue&& o) = default;
    IValue& operator=(const IValue&) = default;
    IValue& operator=(IValue&& o) = default;

    MValue thaw();

    //! attempt to decend into sub-structure
    const IValue operator[](const char *name) const {
        IValue ret(*this);
        ret.traverse(name, false);
        return ret;
    }
    inline const IValue operator[](const std::string& name) const { return (*this)[name.c_str()]; }

    Iterable<IValue> iall()      { return Iterable<IValue>{this, false, true}; }
    Iterable<IValue> ichildren() { return Iterable<IValue>{this, false, false}; }
    Iterable<IValue> imarked()   { return Iterable<IValue>{this, true , true}; }

    Iterable<const IValue> iall() const      { return Iterable<const IValue>{this, false, true}; }
    Iterable<const IValue> ichildren() const { return Iterable<const IValue>{this, false, false}; }
    Iterable<const IValue> imarked() const   { return Iterable<const IValue>{this, true , true}; }
};


PVXS_API
std::ostream& operator<<(std::ostream& strm, const impl::ValueBase& val);

} // namespace pvxs

#endif // PVXS_DATA_H
