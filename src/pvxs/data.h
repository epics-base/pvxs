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
#include <iosfwd>
#include <string>
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

PVXS_API
std::ostream& operator<<(std::ostream& strm, StoreType c);

constexpr struct unselect_t {} unselect;

namespace impl {
struct FieldStorage;
struct FieldDesc;

//! maps T to one of the types which can be stored in the FieldStorage::store union
//! typename StorageMap<T>::store_t is, if existent, one such type.
//! store_t shall be convertible to/from T through StoreTransform<T>::in() and out().
//! StorageMap<T>::code is the associated StoreType.
template<typename T, typename Enable=void>
struct StorageMap {
    typedef void not_storable;
};

// map signed integers to int64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value>::type>
{ typedef int64_t store_t;  static constexpr StoreType code{StoreType::Integer}; };

// map unsigned integers to uint64_t
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_integral<T>::value && !std::is_signed<T>::value && !std::is_same<T,bool>::value>::type>
{ typedef uint64_t store_t; static constexpr StoreType code{StoreType::UInteger}; };

// map floating point to double.  (truncates long double, but then PVA doesn't have >8 byte primitives support anyway)
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

template<>
struct StorageMap<unselect_t>
{ typedef unselect_t store_t; static constexpr StoreType code{StoreType::Null}; };

// drill through enum{} to handle as underlying integer type
template<typename T>
struct StorageMap<T, typename std::enable_if<std::is_enum<T>::value>::type>
        :StorageMap<typename std::underlying_type<T>::type>
{};

template<typename T>
using StoreAs = StorageMap<typename std::decay<T>::type>;

template<typename T, typename Enable=void>
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
template<typename T>
struct StoreTransform<T, typename std::enable_if<std::is_enum<T>::value>::type> {
    typedef typename std::underlying_type<T>::type itype_t;
    static inline
    itype_t in(const T& v) { return v; }
    static inline
    T out(const itype_t& v) { return static_cast<T>(v); }
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

enum class ArrayType : uint8_t;

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
    PVXS_API ArrayType arrayType() const;

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
PVXS_API
std::ostream& operator<<(std::ostream& strm, TypeCode c);

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

} // namespace impl

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

    //! Member for non-Compound
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
 * auto val = def2.create(); // instantiate a Value
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

    /** Use this definition as a member (eg. sub-structure) in another definition
     *  with a (limited) type change.
     *
     *  A ``Kind::Compound`` type (eg. ``Struct``) may be changed to another
     *  Compound type (eg. ``StructA``).  However. changes between Compound
     *  and non-Compound are not allowed.
     *
     *  @since 1.1.0
     */
    Member as(TypeCode code, const std::string& name) const;

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

    //! Instantiate this definition
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
    NoConvert(const std::string& msg) : std::runtime_error(msg) {}
    virtual ~NoConvert();
};

struct PVXS_API LookupError : public std::runtime_error
{
    explicit LookupError(const std::string& msg);
    virtual ~LookupError();
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
    // (maybe) owned through StructTop (aliased as FieldStorage)
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

    /** Restore to newly allocated state.
     *
     * Free any allocation for array or string values, zero numeric values.
     * unmark() all fields.
     *
     * @since 1.1.0
     */
    void clear();

    //! Does this Value actually reference some underlying storage
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

private:
    static
    bool _equal(const impl::FieldDesc* A, const impl::FieldDesc* B);
public:
    //! Test for instance equality.  aka. this==this
    inline bool equalInst(const Value& o) const { return store==o.store; }
    //! Test for equality of type only (including field names)
    inline bool equalType(const Value& o) const { return _equal(desc, o.desc); }

    /** Return our name for a descendant field.
     * @code
     *   Value v = ...;
     *   assert(v.nameOf(v["some.field"])=="some.field");
     * @endcode
     * @throws NoField unless both this and descendant are valid()
     * @throws std::logic_error if descendant is not actually a descendant
     */
    const std::string& nameOf(const Value& descendant) const;

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
     * - An enum where the underlying type is one of the preceding (since 0.2.0).
     *
     * @throws NoField !this->valid()
     * @throws NoConvert if the field value can not be coerced to type T
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
            try {
                val = impl::StoreTransform<T>::out(temp);
            }catch(std::exception&){
                ret = false;
            }
        }
        return ret;
    }

    //! Attempt to extract value from field.
    //! If possible, this value is cast to T and passed as the only argument
    //! of the provided function.
    template<typename T, typename FN>
    typename impl::StorageMap<typename std::decay<FN>::type>::not_storable as(FN&& fn) const {
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
        return tryCopyIn(&norm, impl::StoreAs<T>::code);
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
     * - An enum where the underlying type is one of the preceding (since 0.2.0).
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

    //! shorthand for from<T>(const T&) except for T=Value (would be ambiguous with ref. assignment)
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
    void traverse(const std::string& expr, bool modify, bool dothrow);
public:

    /** Attempt to access a descendant field.
     *
     * Argument may be:
     * * name of a child field.  eg. "value"
     * * name of a descendant field.  eg "alarm.severity"
     * * element of an array of structures.  eg "dimension[0]"
     * * name of a union field.  eg. "->booleanValue"
     *
     * These may be composed.  eg.
     *
     * * "dimension[0]size"
     * * "value->booleanValue"
     *
     * @returns A valid() Value if the descendant field exists, otherwise an invalid Value.
     */
    Value operator[](const std::string& name);
    const Value operator[](const std::string& name) const;

    /** Attempt to access a descendant field, or throw exception.
     *
     * Acts like operator[] on success, but throws a (hopefully descriptive)
     * exception instead of returning an invalid Value.
     *
     * @throws LookupError If the lookup can not be satisfied
     * @throws NoField If this Value is empty
     * @since 1.1.2 An empty Value correctly throws NoField instead of returning an empty Value
     */
    Value lookup(const std::string& name);
    const Value lookup(const std::string& name) const;

    //! Number of child fields.
    //! only Struct, StructA, Union, UnionA return non-zero
    size_t nmembers() const;

    struct _IAll {};
    struct _IChildren {};
    struct _IMarked {
        size_t nextcheck=0u;
    };
private:
    template<typename T>
    struct _Iterator;
    template<typename T>
    friend struct _Iterator;
public:
    template<typename T>
    struct Iterable;
    template<typename T>
    friend struct Iterable;

    typedef Iterable<_IAll> IAll;
    typedef Iterable<_IChildren> IChildren;
    typedef Iterable<_IMarked> IMarked;

    /** Depth-first iteration of all descendant fields
     *
     * @code
     * Value top(...);
     * for(auto fld : top.iall()) {
     *     std::cout<<top.nameOf(fld)<<" = "<<fld<<"\n";
     * }
     * @endcode
     */
    inline
    IAll iall() const noexcept;
    //! iteration of all child fields
    inline
    IChildren ichildren() const noexcept;
    //! Depth-first iteration of all marked descendant fields
    inline
    IMarked imarked() const noexcept;

    //! Provides options to control printing of a Value via std::ostream.
    struct Fmt {
        const Value* top = nullptr;
        size_t _limit=0u;
        enum format_t {
            Tree,
            Delta,
        } _format = Tree;
        bool _showValue = true;

        Fmt(const Value* top) :top(top) {}
        //! Show Value in tree/struct format
        Fmt& tree() { _format = Tree; return *this; }
        //! Show Value in delta format
        Fmt& delta()  { _format = Delta ; return *this; }
        //! Explicitly select format_t
        Fmt& format(format_t f) { _format = f ; return *this; }
        //! Whether to show field values, or only type information
        Fmt& showValue(bool v) { _showValue = v; return *this; }
        //! When non-zero, arrays output will be truncated with "..." after cnt elements.
        Fmt& arrayLimit(size_t cnt) { _limit = cnt; return *this; }
    };
    /** Configurable printing via std::ostream
     *
     * @code
     * Value val;
     * std::cout<<val.format().arrayLimit(10);
     * @endcode
     */
    inline Fmt format() const { return Fmt(this); }
};

template<typename T>
struct Value::_Iterator : private T
{
private:
    Value val;
    size_t pos = 0u;
    friend class Value;
    friend struct Iterable<T>;
    constexpr _Iterator(const Value& val, size_t pos) : val(val), pos(pos) {}
public:
    _Iterator() = default;
    Value operator*() const noexcept; // specialized per- _IterKind
    _Iterator& operator++() noexcept; // specialized per- _IterKind
    _Iterator operator++(int) noexcept {
        _Iterator ret(*this);
        ++(*this);
        return ret;
    }
    inline bool operator==(const _Iterator& o) const noexcept { return pos==o.pos; }
    inline bool operator!=(const _Iterator& o) const noexcept { return pos!=o.pos; }
};

template<typename T>
struct Value::Iterable
{
private:
    Value val;
    friend class Value;
public:
    Iterable() = default;
    explicit Iterable(const Value* val) :val(*val) {}
    typedef _Iterator<T> iterator;
    iterator begin() const noexcept; // specialized per- _IterKind
    iterator end() const noexcept; // specialized per- _IterKind
};

template<>
inline
Value::Iterable<Value::_IAll>::iterator
Value::Iterable<Value::_IAll>::begin() const noexcept {
    return iterator(val, 0u); // always start pos==0
}

template<>
PVXS_API
Value::Iterable<Value::_IAll>::iterator
Value::Iterable<Value::_IAll>::end() const noexcept;

template<>
PVXS_API
Value
Value::_Iterator<Value::_IAll>::operator*() const noexcept;

template<>
inline
Value::_Iterator<Value::_IAll>&
Value::_Iterator<Value::_IAll>::operator++() noexcept {
    pos++;
    return *this;
}

template<>
inline
Value::Iterable<Value::_IChildren>::iterator
Value::Iterable<Value::_IChildren>::begin() const noexcept {
    return iterator(val, 0u); // always start pos==0
}

template<>
PVXS_API
Value::Iterable<Value::_IChildren>::iterator
Value::Iterable<Value::_IChildren>::end() const noexcept;

template<>
PVXS_API
Value
Value::_Iterator<Value::_IChildren>::operator*() const noexcept;

template<>
inline
Value::_Iterator<Value::_IChildren>&
Value::_Iterator<Value::_IChildren>::operator++() noexcept {
    pos++;
    return *this;
}

template<>
PVXS_API
Value::Iterable<Value::_IMarked>::iterator
Value::Iterable<Value::_IMarked>::begin() const noexcept;

template<>
PVXS_API
Value::Iterable<Value::_IMarked>::iterator
Value::Iterable<Value::_IMarked>::end() const noexcept;

template<>
PVXS_API
Value
Value::_Iterator<Value::_IMarked>::operator*() const noexcept;

template<>
PVXS_API
Value::_Iterator<Value::_IMarked>&
Value::_Iterator<Value::_IMarked>::operator++() noexcept;

Value::Iterable<Value::_IAll>
Value::iall() const noexcept {
    return Iterable<Value::_IAll>{this};
}

Value::Iterable<Value::_IChildren>
Value::ichildren() const noexcept {
    return Iterable<Value::_IChildren>{this};
}

Value::Iterable<Value::_IMarked>
Value::imarked() const noexcept {
    return Iterable<Value::_IMarked>{this};
}

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Value::Fmt& fmt);

inline
std::ostream& operator<<(std::ostream& strm, const Value& val)
{
    return strm<<val.format();
}

} // namespace pvxs

#endif // PVXS_DATA_H
