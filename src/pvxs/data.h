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
class TypeDef;
namespace client {
namespace detail {
class CommonBase;
}} // namespace client::detail

//! selector for union FieldStorage::store
enum struct StoreType : uint8_t {
    Null,     //!< no associate storage
    Bool,     //!< bool
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
//! typename StorageMap<T>::store_t is, if existant, one such type.
//! store_t shall be convertable-able to/from T through StoreTransform<T>::in() and out().
//! StorageMap<T>::code is the associated StoreType.
template<typename T, typename Enable=void>
struct StorageMap;

// map signed integers to int64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value>::type>
{ typedef int64_t store_t;  static constexpr StoreType code{StoreType::Integer}; };

// map unsigned integers to uint64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>::value && !std::is_signed<T>::value && !std::is_same<T,bool>::value>::type>
{ typedef uint64_t store_t; static constexpr StoreType code{StoreType::UInteger}; };

// map floating point to double.  (truncates long double, but then PVA doesn't have >8 byte primatives support anyway)
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_floating_point<T>::value>::type>
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

template<typename E>
struct StorageMap<shared_array<const E>>
{ typedef shared_array<const void> store_t;   static constexpr StoreType code{StoreType::Array}; };

template<>
struct StorageMap<Value>
{ typedef Value store_t;   static constexpr StoreType code{StoreType::Compound}; };

template<typename T>
using StoreAs = StorageMap<typename std::decay<T>::type>;

template<typename T>
struct StoreTransform {
    // pass through by default
    static inline const T& in (const T& v) { return v; }
    static inline const T& out(const T& v) { return v; }
};
template<typename E>
struct StoreTransform<shared_array<const E>> {
    // cast shared_array to void
    static inline
    shared_array<const void> in(const shared_array<const E>& v) {
        return v.template castTo<const void>();
    }
    static inline
    shared_array<const E> out(const shared_array<const void>& v) {
        return v.template convertTo<const E>();
    }
};

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

/** Possible Field types.
 *
 * eg. String is scalar string, StringA is array of strings.
 */
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

    PVXS_API StoreType storedAs() const;

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

namespace impl {
template<typename T>
struct ScalarMap;

#define CASE(TYPE, STORE, CODE) \
template<> struct ScalarMap<TYPE> { typedef STORE store_t; static constexpr TypeCode::code_t code{TypeCode::CODE}; }

CASE(bool    , uint64_t, Bool);
CASE(uint8_t , uint64_t, UInt8);
CASE(uint16_t, uint64_t, UInt16);
CASE(uint32_t, uint64_t, UInt32);
CASE(uint64_t, uint64_t, UInt64);
CASE(int8_t  , int64_t , Int8);
CASE(int16_t , int64_t , Int16);
CASE(int32_t , int64_t , Int32);
CASE(int64_t , int64_t , Int64);
CASE(float   , double  , Float32);
CASE(double  , double  , Float64);
CASE(std::string, std::string, String);

#undef CASE

} // namespace

//! Definition of a member of a Struct/Union for use with TypeDef
struct Member {
private:
    TypeCode code;
    std::string name;
    std::string id;
    std::vector<Member> children;
    friend class TypeDef;
    friend class client::detail::CommonBase;

    PVXS_API
    void _validate() const;
public:
    struct Helper;

    //! Empty/invalid Member
    inline
    Member() :code(TypeCode::Null) {}

    //! Member for non-Compund
    //! @pre code.kind()!=Kind::Compound
    inline
    Member(TypeCode code, const std::string& name)
        :Member(code, name, {})
    {}
    //! Compound member with type ID
    Member(TypeCode code, const std::string& name, const std::string& id, std::initializer_list<Member> children)
        :code(code)
        ,name(name)
        ,id(id)
        ,children(children.begin(), children.end())
    {_validate();}
    template<typename Iterable>
    Member(TypeCode code, const std::string& name, const std::string& id, const Iterable& children)
        :code(code)
        ,name(name)
        ,id(id)
        ,children(children.begin(), children.end())
    {_validate();}
    //! Compound member without type ID
    inline
    Member(TypeCode code, const std::string& name, std::initializer_list<Member> children)
        :Member(code, name , std::string(), children)
    {}
    template<typename Iterable>
    inline
    Member(TypeCode code, const std::string& name, const Iterable& children)
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
template <typename Iterable> \
inline Member TYPE(const std::string& name, const Iterable& children) { return Member(TypeCode::TYPE, name, children); } \
inline Member TYPE(const std::string& name, const std::string& id, std::initializer_list<Member> children) { return Member(TypeCode::TYPE, name, id, children); } \
template <typename Iterable> \
inline Member TYPE(const std::string& name, const std::string& id, const Iterable& children) { return Member(TypeCode::TYPE, name, id, children); }

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
 *     def1.as("special"), // compose definitions
 * });
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
    explicit TypeDef(const Value&);
    ~TypeDef();

    //! new definition with id and children.  code must be TypeCode::Struct or TypeCode::Union
    template<typename Iterable>
    TypeDef(TypeCode code, const std::string& id, const Iterable& children)
        :TypeDef(std::make_shared<Member>(code, "", id, children))
    {}
    TypeDef(TypeCode code, const std::string& id, std::initializer_list<Member> children)
        :TypeDef(std::make_shared<Member>(code, "", id, children))
    {}
private:
    TypeDef(std::shared_ptr<const Member>&&);
public:
    //! new definition for a single scalar field.  code must __not__ be TypeCode::Struct or TypeCode::Union
    TypeDef(TypeCode code)
        :TypeDef(code, std::string(), {})
    {}
    //! new definition without id.  code must be TypeCode::Struct or TypeCode::Union
    TypeDef(TypeCode code, std::initializer_list<Member> children)
        :TypeDef(code, std::string(), children)
    {}

    //! Use this definition as a member (eg. sub-structure) in another definition.
    Member as(const std::string& name) const;

private:
    std::shared_ptr<Member> _append_start();
    static
    void _append(Member& edit, const Member& mem);
    void _append_finish(std::shared_ptr<Member>&& edit);
public:

    //! append additional children.  Only for TypeCode::Struct or TypeCode::Union
    template<typename Iterable>
    TypeDef& operator+=(const Iterable& children) {
        auto edit = _append_start();
        for(auto& child : children) {
            _append(*edit, child);
        }
        _append_finish(std::move(edit));
        return *this;
    }
    TypeDef& operator+=(std::initializer_list<Member> children) {
        auto edit = _append_start();
        for(auto& child : children) {
            _append(*edit, child);
        }
        _append_finish(std::move(edit));
        return *this;
    }

    //! Instanciate this definition
    Value create() const;

    friend
    PVXS_API
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

/** Generic data container
 *
 * References a single data field, which may be free-standing (eg. "int x = 5;")
 * or a member of an enclosing Struct, or an element in an array of Struct.
 *
 * - Use valid() (or operator bool() ) to determine if pointed to a valid field.
 * - Use operator[] to traverse within a Kind::Compound field.
 *
 * @code
 * Value val = nt::NTScalar{TypeCode::Int32}.create();
 * val["value"] = 42;
 * Value alias = val;
 * assert(alias["value"].as<int32_t>()==42); // 'alias' is a second reference to the same Struct
 * @endcode
 */
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
    Value(Value&& o) noexcept
        :desc(o.desc)
    {
        store = std::move(o.store);
        o.desc = nullptr;
    }
    Value& operator=(const Value&) = default;
    Value& operator=(Value&& o) noexcept {
        store = std::move(o.store);
        desc = o.desc;
        o.desc = nullptr;
        return *this;
    }
    ~Value();

    //! allocate new storage, with default values
    Value cloneEmpty() const;
    //! allocate new storage and copy in our values
    Value clone() const;
    //! copy value(s) from other.
    //! Acts like from(o) for kind==Kind::Compound .
    //! Acts like from(o.as<T>()) for kind!=Kind::Compound
    Value& assign(const Value& o);

    //! Use to allocate members for an array of Struct and array of Union
    Value allocMember();

    //! Does this Value actual reference some underlying storage
    inline bool valid() const { return desc; }
    inline explicit operator bool() const { return desc; }

    //! Test if this field is marked as valid/changed
    bool isMarked(bool parents=true, bool children=false) const;
    //! return *this if isMarked()==true, or a !valid() ref. if false.
    Value ifMarked(bool parents=true, bool children=false) const;
    //! Mark this field as valid/changed
    void mark(bool v=true);
    //! Remove mark from this field
    void unmark(bool parents=false, bool children=true);

    //! Type of the referenced field (or Null)
    TypeCode type() const;
    //! Type of value stored in referenced field
    StoreType storageType() const;
    //! Type ID string (Struct or Union only)
    const std::string& id() const;
    //! Test prefix of Type ID string (Struct or Union only)
    bool idStartsWith(const std::string& prefix) const;

    //! test for instance equality.
    inline bool compareInst(const Value& o) const { return store==o.store; }
//    int compareValue(const Value&) const;
    inline int compareType(const Value& o) const { return desc==o.desc; }

    /** Return our name for a decendent field.
     * @code
     *   Value v = ...;
     *   assert(v.nameOf(v["some.field"])=="some.field");
     * @endcode
     * @throws NoField unless both this and decendent are valid()
     * @throws std::logic_error if decendent is not actually a decendent
     */
    const std::string& nameOf(const Value& decendent) const;

    // access to Value's ... value
    // not for Struct

    // use with caution
    void copyOut(void *ptr, StoreType type) const;
    bool tryCopyOut(void *ptr, StoreType type) const;
    void copyIn(const void *ptr, StoreType type);
    bool tryCopyIn(const void *ptr, StoreType type);

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
        typename impl::StoreAs<T>::store_t ret;
        copyOut(&ret, impl::StoreAs<T>::code);
        return impl::StoreTransform<T>::out(ret);
    }

    //! Attempt to extract value from field.
    //! @returns false if as<T>() would throw NoField or NoConvert
    template<typename T>
    inline bool as(T& val) const {
        typename impl::StoreAs<T>::store_t temp;
        auto ret = tryCopyOut(&temp, impl::StoreAs<T>::code);
        if(ret) {
            val = impl::StoreTransform<T>::out(temp);
        }
        return ret;
    }

    //! Attempt to extract value from field.
    //! If possible, this value is cast to T and passed as the only argument
    //! of the provided function.
    template<typename T, typename FN>
    void as(FN&& fn) const {
        typename impl::StoreAs<T>::store_t val;
        if(tryCopyOut(&val, impl::StoreAs<T>::code)) {
            fn(impl::StoreTransform<T>::out(val));
        }
    }

    //! Attempt to assign to field.
    //! @returns false if from<T>() would throw NoField or NoConvert
    template<typename T>
    inline bool tryFrom(const T& val) {
        const typename impl::StoreAs<T>::store_t& norm(impl::StoreTransform<T>::in(val));
        return copyIn(&norm, impl::StoreAs<T>::code);
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
    void from(const T& val) {
        const typename impl::StoreAs<T>::store_t& norm(impl::StoreTransform<T>::in(val));
        copyIn(&norm, impl::StoreAs<T>::code);
    }

    //! Inline assignment of sub-field.
    //! Shorthand for @code (*this)[key].from(val) @endcode
    template<typename T, typename K>
    Value& update(K key, const T& val) {
        (*this)[key].from(val);
        return *this;
    }

    //! shorthand for from<T>(const T&) except for T=Value (would be ambigious with ref. assignment)
    template<typename T>
#ifdef _DOXYGEN_
    Value&
#else
    typename std::enable_if<!std::is_same<T,Value>::value, Value&>::type
#endif
    operator=(const T& val) {
        from<T>(val);
        return *this;
    }

    // Struct/Union access
private:
    void traverse(const std::string& expr, bool modify);
public:

    /** Attempt to access a decendant field.
     *
     * Argument may be:
     * * name of a child field.  eg. "value"
     * * name of a decendant field.  eg "alarm.severity"
     * * element of an array of structures.  eg "dimension[0]"
     * * name of a union field.  eg. "booleanValue"
     *
     * These may be composed.  eg.
     *
     * * "dimension[0]size"
     * * "value->booleanValue"
     *
     * @returns A valid() Value if the decendant field exists, otherwise an invalid Value.
     */
    Value operator[](const char *name);
    inline Value operator[](const std::string& name) { return (*this)[name.c_str()]; }
    const Value operator[](const char *name) const;
    inline const Value operator[](const std::string& name) const { return (*this)[name.c_str()]; }

    template<typename V>
    class Iterable;
private:
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
    class Iter;
    template<typename V>
    friend class Iter;

    void _iter_fl(IterInfo& info, bool first) const;
    void _iter_advance(IterInfo& info) const;
    Value _iter_deref(const IterInfo& info) const;
public:

    template<typename V>
    class Iterable;

    /** Depth-first iteration of all decendent fields
     *
     * @code
     * Value top(...);
     * for(auto fld : top.iall()) {
     *     std::cout<<top.nameOf(fld)<<" = "<<fld<<"\n";
     * }
     * @endcode
     */
    inline
    Iterable<Value> iall();
    //! iteration of all child fields
    inline
    Iterable<Value> ichildren();
    //! Depth-first iteration of all marked decendent fields
    inline
    Iterable<Value> imarked();

    inline
    Iterable<const Value> iall() const;
    inline
    Iterable<const Value> ichildren() const;
    inline
    Iterable<const Value> imarked() const;

    struct Fmt {
        const Value* top = nullptr;
        size_t _limit=0u;
        enum format_t {
            Tree,
            Delta,
        } _format = Tree;
        bool _showValue = true;

        Fmt(const Value* top) :top(top) {}
        Fmt& tree() { _format = Tree; return *this; }
        Fmt& delta()  { _format = Delta ; return *this; }
        Fmt& format(format_t f) { _format = f ; return *this; }
        Fmt& showValue(bool v) { _showValue = v; return *this; }
        Fmt& arrayLimit(size_t cnt) { _limit = cnt; return *this; }
    };
    inline Fmt format() const { return Fmt(this); }
};

template<typename V>
class Value::Iter : private Value::IterInfo {
    const Value ref;
    constexpr Iter(const Value& ref, size_t pos, bool marked, bool depth)
        :IterInfo(pos, marked, depth), ref(ref)
    {}
    friend class Value;
    friend class Iterable<V>;
public:
    Iter() :ref(nullptr) {}

    V operator*() const { return ref._iter_deref(*this); }
    Iter& operator++() {
        pos++;
        if(marked && pos >= nextcheck)
            ref._iter_advance(*this);
        return *this;
    }
    Iter operator++(int) {
        Iter ret(*this);
        pos++;
        if(marked && pos >= nextcheck)
            ref._iter_advance(*this);
        return ret;
    }
    bool operator==(const Iter& o) const { return pos == o.pos; }
    bool operator!=(const Iter& o) const { return !(o==*this); }
};

template<typename V>
class Value::Iterable {
    typedef Iter<V> iterator;
    const Value owner;
    bool marked;
    bool depth;
public:
    constexpr Iterable(const Value& owner, bool marked, bool depth) :owner(owner), marked(marked), depth(depth) {}
    iterator begin() const {
        iterator ret{owner, 0u, marked, depth};
        owner._iter_fl(ret, true);
        return ret;
    }
    iterator end() const {
        iterator ret{owner, 0u, marked, depth};
        owner._iter_fl(ret, false);
        return ret;
    }
};

Value::Iterable<Value> Value::iall()      { return Iterable<Value>{*this, false, true}; }
Value::Iterable<Value> Value::ichildren() { return Iterable<Value>{*this, false, false}; }
Value::Iterable<Value> Value::imarked()   { return Iterable<Value>{*this, true , true}; }

Value::Iterable<const Value> Value::iall() const      { return Iterable<const Value>{*this, false, true}; }
Value::Iterable<const Value> Value::ichildren() const { return Iterable<const Value>{*this, false, false}; }
Value::Iterable<const Value> Value::imarked() const   { return Iterable<const Value>{*this, true , true}; }

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Value::Fmt& fmt);

inline
std::ostream& operator<<(std::ostream& strm, const Value& val)
{
    return strm<<val.format();
}

} // namespace pvxs

#endif // PVXS_DATA_H
