/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef DATAIMPL_H
#define DATAIMPL_H

#include <string>
#include <map>

#include <pvxs/data.h>
#include <pvxs/sharedArray.h>
#include "bitmask.h"
#include "utilpvt.h"

namespace pvxs {

struct Value::Helper {
    // internal access to private operations
    static inline Value build(const std::shared_ptr<const impl::FieldDesc>& desc) {
        return Value(desc);
    }
    static inline Value build(const std::shared_ptr<const impl::FieldDesc>& desc, Value& parent) {
        return Value(desc, parent);
    }
    static inline Value build(const std::shared_ptr<const impl::FieldDesc>& desc,
                              const std::shared_ptr<impl::FieldStorage>& pstore, const impl::FieldDesc* pdesc);


    static Value build(const void* ptr, StoreType type);

    static inline       std::shared_ptr<impl::FieldStorage>& store(      Value& v) { return v.store; }
    static inline std::shared_ptr<const impl::FieldStorage>  store(const Value& v) { return v.store; }
    static constexpr const FieldDesc*                        desc(const Value& v) { return v.desc; }
    static inline void set_desc(Value& v, const FieldDesc* desc) { v.desc = desc; }

    static inline                       impl::FieldStorage*  store_ptr(      Value& v) { return v.store.get(); }
    static inline                 const impl::FieldStorage*  store_ptr(const Value& v) { return v.store.get(); }

    static std::shared_ptr<const impl::FieldDesc> type(const Value& v);
};

namespace impl {
struct Buffer;

/** Describes a single field, leaf or otherwise, in a nested structure.
 *
 * FieldDesc are always stored depth first as a contiguous array,
 * with offset to descendant fields given as positive integers relative
 * to the current field.  (not possible to jump _back_)
 *
 * We deal with indices in this FieldDesc array.  found in FieldDesc::mlookup
 * and FieldDesc::miter Relative to current position in FieldDesc array.  (aka this+n)
 */
struct FieldDesc {
    // type ID string (Struct/Union)
    std::string id;

    // Lookup of all descendant fields of this Structure or Union.
    // "fld.sub.leaf" -> rel index
    // For Struct, relative to this (always >=1)
    // For Union, offset in members array (one entry will always be zero)
    std::map<std::string, size_t> mlookup;

    // child iteration.  child# -> ("sub", rel index in enclosing vector<FieldDesc>)
    std::vector<std::pair<std::string, size_t>> miter;

    // number of FieldDesc nodes between this node and it's a parent Struct (or 0 if no parent).
    // This value also appears in the parent's miter and mlookup mappings.
    // Only usable when a StructTop is accessible and this!=StructTop::desc
    size_t parent_index=0;

    // For Union, UnionA, StructA
    // For Union, the choices concatenated together (members.size() !+ #choices)
    // For UnionA/StructA containing a single Union/Struct
    std::vector<FieldDesc> members;

    const TypeCode code{TypeCode::Null};

    explicit FieldDesc(TypeCode code) :code{code} {}

    // number of FieldDesc nodes which describe this node.  Inclusive.  always size()>=1
    inline size_t size() const { return 1u + (members.empty() ? mlookup.size() : 0u); }
};

PVXS_API
void to_wire(Buffer& buf, const FieldDesc* cur);

typedef std::map<uint16_t, std::vector<FieldDesc>> TypeStore;

PVXS_API
void from_wire(Buffer& buf, std::vector<FieldDesc>& descs, TypeStore& cache, unsigned depth=0);

struct StructTop;

struct FieldStorage {
    /* Storage for field value.  depends on StoreType.
     *
     * All array types stored as shared_array<const void> which includes full type info
     * Integers promoted to either int64_t or uint64_t.
     * Bool promoted to uint64_t
     * Reals promoted to double.
     * String stored as std::string
     * Compound (Struct, Union, Any) stored as Value
     */
    aligned_union<8,
                       double, // Real
                       uint64_t, // Bool, Integer
                       std::string, // String
                       Value, // Union, Any
                       shared_array<const void> // array of POD, std::string, or std::shared_ptr<Value>
    >::type store;
    // index of this field in StructTop::members
    StructTop *top;
    bool valid=false;
    StoreType code=StoreType::Null;

    void init(StoreType code);
    void deinit();
    ~FieldStorage();

    size_t index() const;

    template<typename T>
    T& as() { return *reinterpret_cast<T*>(&store); }
    template<typename T>
    const T& as() const { return *reinterpret_cast<const T*>(&store); }

    inline uint8_t* buffer() { return reinterpret_cast<uint8_t*>(&store); }
    inline const uint8_t* buffer() const { return reinterpret_cast<const uint8_t*>(&store); }
};

// hidden (publicly) management of an allocated Struct
struct StructTop {
    // type of first top level struct.  always !NULL.
    // Actually the first element of a vector<const FieldDesc>
    std::shared_ptr<const FieldDesc> desc;
    // our members (inclusive).  always size()>=1
    std::vector<FieldStorage> members;

    // empty, or the field of a structure which encloses this.
    std::weak_ptr<FieldStorage> enclosing;

    INST_COUNTER(StructTop);
};

using Type = std::shared_ptr<const FieldDesc>;


//! serialize all Value fields
PVXS_API
void to_wire_full(Buffer& buf, const Value& val);

//! serialize BitMask and marked valid Value fields
PVXS_API
void to_wire_valid(Buffer& buf, const Value& val, const BitMask* mask=nullptr);

//! deserialize type description
PVXS_API
void from_wire_type(Buffer& buf, TypeStore& ctxt, Value& val);

//! deserialize full Value
PVXS_API
void from_wire_full(Buffer& buf, TypeStore& ctxt, Value& val);

//! deserialize BitMask and partial Value
PVXS_API
void from_wire_valid(Buffer& buf, TypeStore& ctxt, Value& val);

//! deserialize type description and full value (a la. pvRequest)
PVXS_API
void from_wire_type_value(Buffer& buf, TypeStore& ctxt, Value& val);

PVXS_API
std::ostream& operator<<(std::ostream& strm, const FieldDesc* desc);

} // namespace impl


Value Value::Helper::build(const std::shared_ptr<const impl::FieldDesc>& desc,
                           const std::shared_ptr<impl::FieldStorage>& pstore, const impl::FieldDesc* pdesc)
{
    Value ret(desc);
    auto& enc = ret.store->top->enclosing;
    enc = pstore;
    return ret;
}

} // namespace pvxs

#endif // DATAIMPL_H
