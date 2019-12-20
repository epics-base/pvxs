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
#include <pvxs/bitmask.h>
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

    static inline       std::shared_ptr<impl::FieldStorage>& store(      Value& v) { return v.store; }
    static inline std::shared_ptr<const impl::FieldStorage>  store(const Value& v) { return v.store; }
    static inline const FieldDesc*                           desc(const Value& v) { return v.desc; }

    static inline                       impl::FieldStorage*  store_ptr(      Value& v) { return v.store.get(); }
    static inline                 const impl::FieldStorage*  store_ptr(const Value& v) { return v.store.get(); }

    static std::shared_ptr<const impl::FieldDesc> type(const Value& v);
};

namespace impl {
struct Buffer;

/** Describes a single field, leaf or otherwise, in a nested structure.
 *
 * FieldDesc are always stored depth first as a contigious array,
 * with offset to decendent fields given as positive integers relative
 * to the current field.  (not possible to jump _back_)
 *
 * We deal with two different numeric values:
 * 1. indicies in this FieldDesc array.  found in FieldDesc::mlookup and FieldDesc::miter
 *    Relative to current position in FieldDesc array.  (aka this+n)
 * 2. offsets in associated FieldStorage array.  found in FieldDesc::index
 *    Relative to current FieldDesc*.
 */
struct FieldDesc {
    // type ID string (struct/union)
    std::string id;
    // Lookup of all decendent fields of this Structure or Union.
    // "fld.sub.leaf" -> rel index in enclosing vector<FieldDesc>
    std::map<std::string, size_t> mlookup;
    // child iteration.  child# -> ("sub", rel index in enclosing vector<FieldDesc>)
    std::vector<std::pair<std::string, size_t>> miter;
    // hash of this type (aggragating from children)
    // created using the code ^ id ^ (child_name ^ child_hash)*N
    size_t hash;
    // abs. offset in enclosing StructTop::members.  (not abs. offset of FieldDesc array)
    // used to navigate vector<FieldStorage>
    size_t offset=0, next_offset=0;
    // number of FieldDesc nodes which describe this node and decendents.  Inclusive.  always >=1
    // eg. num_index+(FieldDesc*)this jumps to next sibling
    size_t num_index=0;
    // number of FieldDesc nodes between this node and it's a parent node (if any).
    // This value also appears in the parent's miter and mlookup mappings.
    // Only usable when a StructTop is accessible and this!=StructTop::desc
    size_t parent_index=0;
    TypeCode code{TypeCode::Null};

    // number of FieldDesc nodes which describe this node.  Inclusive.  always size()>=1
    inline size_t size() const { return num_index; }
};

PVXS_API
void to_wire(Buffer& buf, const FieldDesc* cur);

typedef std::map<uint16_t, std::vector<FieldDesc>> TypeStore;

struct TypeDeserContext {
    std::vector<FieldDesc>& descs;
    TypeStore& cache;
};

PVXS_API
void from_wire(Buffer& buf, TypeDeserContext& ctxt, unsigned depth=0);

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
    StoreType code=StoreType::Null; // duplicates associated FieldDesc::code

    void init(const FieldDesc* desc);
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
    // which members have been assigned/updated (use to track "changes")
    BitMask valid;
    // type of first top level struct.  always !NULL.
    // Actually the first element of a vector<const FieldDesc>
    std::shared_ptr<const FieldDesc> desc;
    // map from FieldStorage offsets to FieldDesc offsets.  inverse of FieldDesc::offset
    std::vector<size_t> member_indicies;
    // our members (inclusive).  always size()>=1
    std::vector<FieldStorage> members;

    // empty, or the field of a structure which encloses this.
    Value enclosing;
};

using Type = std::shared_ptr<const FieldDesc>;


PVXS_API
void to_wire_full(Buffer& buf, const Value& val);

PVXS_API
void to_wire_valid(Buffer& buf, const Value& val);

PVXS_API
void from_wire_full(Buffer& buf, TypeStore& ctxt, Value& val);

PVXS_API
void from_wire_valid(Buffer& buf, TypeStore& ctxt, Value& val);

PVXS_API
void from_wire_type_value(Buffer& buf, TypeStore& ctxt, Value& val);

PVXS_API
void FieldDesc_calculate_offset(FieldDesc* top);

PVXS_API
std::ostream& operator<<(std::ostream& strm, const FieldDesc* desc);

} // namespace impl


Value Value::Helper::build(const std::shared_ptr<const impl::FieldDesc>& desc,
                           const std::shared_ptr<impl::FieldStorage>& pstore, const impl::FieldDesc* pdesc)
{
    Value ret(desc);
    auto& enc = ret.store->top->enclosing;
    enc.store = pstore;
    enc.desc = pdesc;
    return ret;
}

} // namespace pvxs

#endif // DATAIMPL_H
