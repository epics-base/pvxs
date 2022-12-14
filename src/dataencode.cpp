/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef DATAENCODE_H
#define DATAENCODE_H

#include <cassert>

#include <stdexcept>
#include <functional>
#include <ostream>
#include <list>
#include <map>
#include <utility>
#include <type_traits>
#include <memory>

#include <pvxs/data.h>
#include <pvxs/sharedArray.h>
#include "pvaproto.h"
#include "utilpvt.h"
#include "dataimpl.h"

namespace pvxs {
namespace impl {

void to_wire(Buffer& buf, const FieldDesc* cur)
{
    if(!cur) {
        to_wire(buf, uint8_t(0xff));
        return;
    }

    // we assume FieldDesc* is valid (checked on creation)
    to_wire(buf, cur->code.code);

    // other than (array of) struct and union, encoding is simple
    switch(cur->code.code) {
    case TypeCode::StructA:
    case TypeCode::UnionA:
        to_wire(buf, &cur->members[0]);
        break;

    case TypeCode::Struct:
        to_wire(buf, cur->id);
        to_wire(buf, Size{cur->miter.size()});
        for(auto& pair : cur->miter) {
            to_wire(buf, pair.first);
            to_wire(buf, cur+pair.second); // jump forward in FieldDesc array and recurse!
        }
        break;

    case TypeCode::Union:
        to_wire(buf, cur->id);
        to_wire(buf, Size{cur->miter.size()});
        for(auto& pair : cur->miter) {
            to_wire(buf, pair.first);
            to_wire(buf, &cur->members[pair.second]); // jump forward in FieldDesc array and recurse!
        }
        break;
    default:
        break;
    }
}

void from_wire(Buffer& buf, std::vector<FieldDesc>& descs, TypeStore& cache, unsigned depth)
{
    if(!buf.good() || depth>20) {
        buf.fault(__FILE__, __LINE__);
        return;
    }

    TypeCode code;
    from_wire(buf, code.code);
    const size_t index = descs.size(); // index of first node we add to descs[]

    if(code == TypeCode::Null) {
        return;

    } else if(code.code==0xfd) {
        // update cache
        uint16_t key=0;
        from_wire(buf, key);
        from_wire(buf, descs, cache, depth+1u);
        if(!buf.good() || index==descs.size()) {
            buf.fault(__FILE__, __LINE__);
            return;

        } else {
            cache.emplace(std::piecewise_construct,
                          std::make_tuple(key),
                          std::make_tuple(descs.begin()+index, descs.end()));

            descs[index].parent_index = 0u; // our caller will set if actually is a parent.
        }

    } else if(code.code==0xfe) {
        // fetch cache
        uint16_t key=0;
        from_wire(buf, key);
        auto it = cache.find(key);
        if(it==cache.end()) {
            buf.fault(__FILE__, __LINE__);
        }

        if(!buf.good() || it->second.empty()) {
            buf.fault(__FILE__, __LINE__);
            return;

        } else {
            // copy from cache
            descs.reserve(index+it->second.size());
            for(const auto& d : it->second)
                descs.emplace_back(d);
        }

    } else if(code.code!=0xff && code.code&0x10) {
        // fixed length is deprecated
        buf.fault(__FILE__, __LINE__);

    } else {
        // actual field

        descs.emplace_back(code);

        switch(code.code) {
        case TypeCode::StructA:
        case TypeCode::UnionA:
            from_wire(buf, descs.back().members, cache, depth+1);
            if(!buf.good() || descs.back().members.empty() || descs.back().members[0].code!=code.scalarOf()) {
                buf.fault(__FILE__, __LINE__);
                return;
            }
            break;

        case TypeCode::Struct:
        case TypeCode::Union: {
            from_wire(buf, descs.back().id);

            Size nfld{0};
            std::string name;
            from_wire(buf, nfld); // number of children
            {
                auto& fld = descs.back();

                fld.miter.reserve(nfld.size);
            }

            auto& cdescs = code.code==TypeCode::Struct ? descs : descs.back().members;
            auto cref = code.code==TypeCode::Struct ? index : 0u;

            for(auto i: range(nfld.size)) {
                (void)i;
                const size_t cindex = cdescs.size(); // index of this child

                from_wire(buf, name);
                from_wire(buf, cdescs, cache, depth+1);
                if(!buf.good() || cindex>=cdescs.size()) {
                    buf.fault(__FILE__, __LINE__);
                    return;
                }

                // descs may be re-allocated (invalidating previous refs.)
                auto& fld = descs[index];
                auto& cfld = cdescs[cindex];
                if(code.code==TypeCode::Struct)
                    cfld.parent_index = cindex-cref;

                // update field refs.
                fld.miter.emplace_back(name, cindex-cref);
                fld.mlookup[name] = cindex-cref;
                name+='.';

                if(code.code==TypeCode::Struct && code==cfld.code) {
                    // copy descendant indices for sub-struct
                    for(auto& pair : cfld.mlookup) {
                        fld.mlookup[name+pair.first] = cindex - cref + pair.second;
                    }
                }
            }
        }
            break;
        default:
            // not handling fixed/bounded
            // other types have simple/single node description
            switch(code.scalarOf().code) {
            case TypeCode::Bool:
            case TypeCode::Int8:
            case TypeCode::Int16:
            case TypeCode::Int32:
            case TypeCode::Int64:
            case TypeCode::UInt8:
            case TypeCode::UInt16:
            case TypeCode::UInt32:
            case TypeCode::UInt64:
            case TypeCode::Float32:
            case TypeCode::Float64:
            case TypeCode::String:
            case TypeCode::Any:
                break;
            default:
                buf.fault(__FILE__, __LINE__);
                break;
            }
        }
    }
}

// serialize a field and all children (if Compound)
static
void to_wire_field(Buffer& buf, const FieldDesc* desc, const std::shared_ptr<const FieldStorage>& store)
{
    switch(store->code) {
    case StoreType::Null:
        switch(desc->code.code) {
        case TypeCode::Struct: {
            // serialize entire sub-structure
            for(auto off : range(desc->size())) {
                auto cdesc = desc + off;
                if(cdesc->code==TypeCode::Struct) // skip sub-struct nodes.  Would be redundant
                    continue;
                std::shared_ptr<const FieldStorage> cstore(store, store.get()+off); // TODO avoid shared_ptr/aliasing here
                to_wire_field(buf, cdesc, cstore);
            }
        }
            return;
        default: break;
        }
        break;
    case StoreType::Real: {
        auto& fld = store->as<double>();
        switch(desc->code.code) {
        case TypeCode::Float32: to_wire(buf, float(fld)); return;
        case TypeCode::Float64: to_wire(buf, double(fld)); return;
        default: break;
        }
    }
        break;
    case StoreType::Integer: {
        auto& fld = store->as<int64_t>();
        switch(desc->code.code) {
        case TypeCode::Int8:  to_wire(buf, int8_t (fld)); return;
        case TypeCode::Int16: to_wire(buf, int16_t(fld)); return;
        case TypeCode::Int32: to_wire(buf, int32_t(fld)); return;
        case TypeCode::Int64: to_wire(buf, int64_t(fld)); return;
        default: break;
        }
    }
        break;
    case StoreType::UInteger: {
        auto& fld = store->as<uint64_t>();
        switch(desc->code.code) {
        case TypeCode::UInt8:  to_wire(buf, uint8_t (fld)); return;
        case TypeCode::UInt16: to_wire(buf, uint16_t(fld)); return;
        case TypeCode::UInt32: to_wire(buf, uint32_t(fld)); return;
        case TypeCode::UInt64: to_wire(buf, uint64_t(fld)); return;
        default: break;
        }
    }
        break;
    case StoreType::Bool: {
        auto& fld = store->as<bool>();
        switch(desc->code.code) {
        case TypeCode::Bool:   to_wire(buf, uint8_t (fld)); return;
        default: break;
        }
    }
        break;
    case StoreType::String: {
        auto& fld = store->as<std::string>();
        switch(desc->code.code) {
        case TypeCode::String: to_wire(buf, fld); return;
        default: break;
        }
    }
        break;
    case StoreType::Compound: {
        auto& fld = store->as<Value>();
        switch (desc->code.code) {
        case TypeCode::Union:
            if(!fld) {
                // implied NULL Union member
                to_wire(buf, Size{size_t(-1)});

            } else {
                size_t index = 0u;
                for(auto& pair : desc->miter) {
                    if(Value::Helper::desc(fld)== &desc->members[pair.second])
                        break;
                    index++;
                }
                if(index>=desc->miter.size())
                    throw std::logic_error("Union contains non-member type");
                to_wire(buf, Size{index});
                to_wire_full(buf, fld);
            }
            return;

        case TypeCode::Any:
            if(!fld) {
                to_wire(buf, uint8_t(0xff));

            } else {
                to_wire(buf, Value::Helper::desc(fld));
                to_wire_full(buf, fld);
            }
            return;
        default: break;
        }
    }
        break;
    case StoreType::Array: {
        auto& fld = store->as<shared_array<const void>>();
        switch (desc->code.code) {
        case TypeCode::BoolA:
            to_wire<bool, uint8_t>(buf, fld);
            return;
        case TypeCode::Int8A:
            to_wire<int8_t>(buf, fld);
            return;
        case TypeCode::UInt8A:
            to_wire<uint8_t>(buf, fld);
            return;
        case TypeCode::Int16A:
            to_wire<int16_t>(buf, fld);
            return;
        case TypeCode::UInt16A:
            to_wire<uint16_t>(buf, fld);
            return;
        case TypeCode::Int32A:
            to_wire<int32_t>(buf, fld);
            return;
        case TypeCode::UInt32A:
            to_wire<uint32_t>(buf, fld);
            return;
        case TypeCode::Float32A:
            to_wire<float>(buf, fld);
            return;
        case TypeCode::Int64A:
            to_wire<int64_t>(buf, fld);
            return;
        case TypeCode::UInt64A:
            to_wire<uint64_t>(buf, fld);
            return;
        case TypeCode::Float64A:
            to_wire<double>(buf, fld);
            return;
        case TypeCode::StringA:
            to_wire<std::string, const std::string&>(buf, fld);
            return;
        case TypeCode::StructA:{
            auto arr = fld.castTo<const Value>();
            to_wire(buf, Size{arr.size()});
            for(auto& elem : arr) {
                if(!elem) {
                    to_wire(buf, uint8_t(0u));
                } else {
                    to_wire(buf, uint8_t(1u));
                    assert(Value::Helper::desc(elem)==&desc->members[0]);
                    to_wire_full(buf, elem);
                }
            }
        }
            return;
        case TypeCode::UnionA: {
            auto arr = fld.castTo<const Value>();
            to_wire(buf, Size{arr.size()});
            for(auto& elem : arr) {
                if(!elem) {
                    to_wire(buf, uint8_t(0u));
                } else {
                    to_wire(buf, uint8_t(1u));

                    to_wire_full(buf, elem);
                }
            }
        }
            return;
        case TypeCode::AnyA:{
            auto arr = fld.castTo<const Value>();
            to_wire(buf, Size{arr.size()});
            for(auto& elem : arr) {
                if(!elem) {
                    to_wire(buf, uint8_t(0u));
                } else {
                    to_wire(buf, uint8_t(1u));

                    to_wire(buf, Value::Helper::desc(elem));
                    to_wire_full(buf, elem);
                }
            }
        }
            return;
        default: break;
        }
        break;
    }
    } // end case

    assert(false);
    buf.fault(__FILE__, __LINE__);
}

void to_wire_full(Buffer& buf, const Value& val)
{
    assert(!!val);

    to_wire_field(buf, Value::Helper::desc(val), Value::Helper::store(val));
}

void to_wire_valid(Buffer& buf, const Value& val, const BitMask* mask)
{
    auto desc = Value::Helper::desc(val);
    auto store = Value::Helper::store(val);
    assert(desc && desc->code==TypeCode::Struct);
    assert(!mask || mask->size()==desc->size());

    BitMask valid(desc->size());

    for(size_t bit=0u, N=desc->size(); bit<N;) {
        if(store.get()[bit].valid && (!mask || (*mask)[bit])) {
            valid[bit] = true;
            bit += desc[bit].size(); // maybe skip past entire sub-struct
        } else {
            bit++;
        }
    }

    to_wire(buf, valid);

    for(auto bit : valid.onlySet()) {
        std::shared_ptr<const FieldStorage> cstore(store, store.get()+bit);
        to_wire_field(buf, desc+bit, cstore);
    }
}

namespace {
template<typename T>
T from_wire_as(Buffer& buf)
{
    T ret{};
    from_wire(buf, ret);
    return ret;
}
}

static
void from_wire_field(Buffer& buf, TypeStore& ctxt,  const FieldDesc* desc, const std::shared_ptr<FieldStorage>& store)
{
    switch(store->code) {
    case StoreType::Null:
        switch(desc->code.code) {
        case TypeCode::Struct: {
            // serialize entire sub-structure
            for(auto off : range(desc->size())) {
                auto cdesc = desc + off;
                std::shared_ptr<FieldStorage> cstore(store, store.get()+off); // TODO avoid shared_ptr/aliasing here
                if(cdesc->code!=TypeCode::Struct) {
                    from_wire_field(buf, ctxt, cdesc, cstore);
                    cstore->valid = true;
                }
            }
        }
            return;
        default: break;
        }
        break;
    case StoreType::Real: {
        auto& fld = store->as<double>();
        switch(desc->code.code) {
        case TypeCode::Float32: fld = from_wire_as<float>(buf); return;
        case TypeCode::Float64: fld = from_wire_as<double>(buf); return;
        default: break;
        }
    }
        break;
    case StoreType::Integer: {
        auto& fld = store->as<int64_t>();
        switch(desc->code.code) {
        case TypeCode::Int8:  fld = from_wire_as<int8_t>(buf); return;
        case TypeCode::Int16: fld = from_wire_as<int16_t>(buf); return;
        case TypeCode::Int32: fld = from_wire_as<int32_t>(buf); return;
        case TypeCode::Int64: fld = from_wire_as<int64_t>(buf); return;
        default: break;
        }
    }
        break;
    case StoreType::UInteger: {
        auto& fld = store->as<uint64_t>();
        switch(desc->code.code) {
        case TypeCode::UInt8:  fld = from_wire_as<int8_t>(buf); return;
        case TypeCode::UInt16: fld = from_wire_as<int16_t>(buf); return;
        case TypeCode::UInt32: fld = from_wire_as<int32_t>(buf); return;
        case TypeCode::UInt64: fld = from_wire_as<int64_t>(buf); return;
        default: break;
        }
    }
        break;
    case StoreType::Bool: {
        auto& fld = store->as<bool>();
        switch(desc->code.code) {
        case TypeCode::Bool:   fld = 0!=from_wire_as<uint8_t>(buf); return;
        default: break;
        }
    }
        break;
    case StoreType::String: {
        auto& fld = store->as<std::string>();
        switch(desc->code.code) {
        case TypeCode::String: from_wire(buf, fld); return;
        default: break;
        }
    }
        break;
    case StoreType::Compound: {
        auto& fld = store->as<Value>();
        switch (desc->code.code) {
        case TypeCode::Union: {
            Size select{};
            from_wire(buf, select);
            if(select.size==size_t(-1)) {
                fld = Value();
                return;

            } else if(select.size < desc->miter.size()) {
                std::shared_ptr<const FieldDesc> stype(store->top->desc,
                                                       &desc->members[desc->miter[select.size].second]); // alias
                fld = Value::Helper::build(stype, store, desc);

                from_wire_full(buf, ctxt, fld);
                return;
            }
        }
            break;

        case TypeCode::Any: {
            auto descs(std::make_shared<std::vector<FieldDesc>>());

            from_wire(buf, *descs, ctxt);
            if(!buf.good())
                return;

            if(descs->empty()) {
                fld = Value();
                return;

            } else {
                std::shared_ptr<const FieldDesc> stype(descs, descs->data()); // alias
                fld = Value::Helper::build(stype);

                from_wire_full(buf, ctxt, fld);
                return;

            }
        }
            break;

        default: break;
        }
    }
        break;
    case StoreType::Array: {
        auto& fld = store->as<shared_array<const void>>();
        switch (desc->code.code) {
        case TypeCode::BoolA:
            from_wire<bool, uint8_t>(buf, fld);
            return;
        case TypeCode::Int8A:
            from_wire<int8_t>(buf, fld);
            return;
        case TypeCode::UInt8A:
            from_wire<uint8_t>(buf, fld);
            return;
        case TypeCode::Int16A:
            from_wire<int16_t>(buf, fld);
            return;
        case TypeCode::UInt16A:
            from_wire<uint16_t>(buf, fld);
            return;
        case TypeCode::Int32A:
            from_wire<int32_t>(buf, fld);
            return;
        case TypeCode::UInt32A:
            from_wire<uint32_t>(buf, fld);
            return;
        case TypeCode::Float32A:
            from_wire<float>(buf, fld);
            return;
        case TypeCode::Int64A:
            from_wire<int64_t>(buf, fld);
            return;
        case TypeCode::UInt64A:
            from_wire<uint64_t>(buf, fld);
            return;
        case TypeCode::Float64A:
            from_wire<double>(buf, fld);
            return;
        case TypeCode::StringA:
            from_wire<std::string>(buf, fld);
            return;
        case TypeCode::StructA:{
            Size alen{};
            from_wire(buf, alen);
            shared_array<Value> arr(alen.size);
            std::shared_ptr<const FieldDesc> etype(store->top->desc,
                                                   &desc->members[0]); // alias
            for(auto& elem : arr) {
                if(from_wire_as<uint8_t>(buf)!=0) { // strictly 1 or 0
                    elem = Value::Helper::build(etype, store, desc);

                    from_wire_full(buf, ctxt, elem);
                }
            }

            fld = arr.freeze().castTo<const void>();
        }
            return;
        case TypeCode::UnionA: {
            Size alen{};
            from_wire(buf, alen);
            shared_array<Value> arr(alen.size);
            auto cdesc = &desc->members[0];

            for(auto& elem : arr) {
                if(from_wire_as<uint8_t>(buf)!=0) { // strictly 1 or 0
                    Size select{};
                    from_wire(buf, select);

                    if(select.size==size_t(-1)) {
                        // null element.  treated the same as 0 case (which is what actually happens)

                    } else if(select.size < cdesc->miter.size()) {
                        std::shared_ptr<const FieldDesc> stype(store->top->desc,
                                                               &cdesc->members[cdesc->miter[select.size].second]); // alias
                        elem = Value::Helper::build(stype, store, desc);

                        from_wire_full(buf, ctxt, elem);

                    } else {
                        // invalid selector
                        buf.fault(__FILE__, __LINE__);
                        return;
                    }
                }
            }

            fld = arr.freeze().castTo<const void>();
        }
            return;
        case TypeCode::AnyA:{
            Size alen{};
            from_wire(buf, alen);
            shared_array<Value> arr(alen.size);

            for(auto& elem : arr) {
                if(from_wire_as<uint8_t>(buf)!=0) { // strictly 1 or 0
                    auto descs(std::make_shared<std::vector<FieldDesc>>());

                    from_wire(buf, *descs, ctxt);
                    if(!buf.good())
                        return;

                    if(!descs->empty()) {

                        std::shared_ptr<const FieldDesc> stype(descs, descs->data()); // alias
                        elem = Value::Helper::build(stype, store, desc);

                        from_wire_full(buf, ctxt, elem);
                    }
                }
            }

            fld = arr.freeze().castTo<const void>();
        }
            return;
        default: break;
        }
        break;

    }
    } // end case

    buf.fault(__FILE__, __LINE__);
}

void from_wire_full(Buffer& buf, TypeStore& ctxt, Value& val)
{
    assert(!!val);

    from_wire_field(buf, ctxt, Value::Helper::desc(val), Value::Helper::store(val));
}

void from_wire_valid(Buffer& buf, TypeStore& ctxt, Value& val)
{
    auto desc = Value::Helper::desc(val);
    auto store = Value::Helper::store(val);

    if(!desc || !store) {
        buf.fault(__FILE__, __LINE__);
        return;
    }

    auto top = store->top;

    BitMask valid;
    from_wire(buf, valid);
    // encoding rounds # of bits to whole bytes, so we may trim
    valid.resize(top->members.size());
    if(!buf.good())
        return;

    for(auto bit = valid.findSet(0u);
        bit<desc->size();)
    {
        std::shared_ptr<FieldStorage> cstore(store, store.get()+bit);
        auto cdesc = desc + bit;
        from_wire_field(buf, ctxt, cdesc, cstore);
        cstore->valid = true;
        bit = valid.findSet(bit + cdesc->size());
    }
}

void from_wire_type(Buffer& buf, TypeStore& ctxt, Value& val)
{
    auto descs(std::make_shared<std::vector<FieldDesc>>());

    from_wire(buf, *descs, ctxt);
    if(!buf.good())
        return;

    if(!descs->empty()) {

        std::shared_ptr<const FieldDesc> stype(descs, descs->data()); // alias
        val = Value::Helper::build(stype);

    } else {
        val = Value();
    }
}

void from_wire_type_value(Buffer& buf, TypeStore& ctxt, Value& val)
{
    from_wire_type(buf, ctxt, val);

    if(buf.good() && val)
        from_wire_full(buf, ctxt, val);
}

}} // namespace pvxs::impl

#endif // DATAENCODE_H
