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
    // we assume FieldDesc* is valid (checked on creation)
    to_wire(buf, cur->code.code);

    // other than (array of) struct and union, encoding is simple
    switch(cur->code.code) {
    case TypeCode::StructA:
    case TypeCode::UnionA:
        to_wire(buf, cur+1);
        break;

    case TypeCode::Struct:
    case TypeCode::Union:
        to_wire(buf, cur->id);
        to_wire(buf, Size{cur->miter.size()});
        for(auto& pair : cur->miter) {
            to_wire(buf, pair.first);
            to_wire(buf, cur+pair.second); // jump forward in FieldDesc array and recurse!
        }
        break;
    default:
        break;
    }
}

void from_wire(Buffer& buf, TypeDeserContext& ctxt, unsigned depth)
{
    if(!buf.good() || depth>20) {
        buf.fault();
        return;
    }

    TypeCode code;
    from_wire(buf, code.code);
    const size_t index = ctxt.descs.size(); // index of first node we add to ctxt.descs[]

    if(code == TypeCode::Null) {
        return;

    } else if(code.code==0xfd) {
        // update cache
        uint16_t key=0;
        from_wire(buf, key);
        from_wire(buf, ctxt, depth+1u);
        if(!buf.good() || index==ctxt.descs.size()) {
            buf.fault();
            return;

        } else {
            auto& entry = ctxt.cache[key];
            // copy new node, and any decendents into cache
            entry.resize(ctxt.descs.size()-index);
            std::copy(ctxt.descs.begin()+index,
                      ctxt.descs.end(),
                      entry.begin());
        }

    } else if(code.code==0xfe) {
        // fetch cache
        uint16_t key=0;
        from_wire(buf, key);
        auto it = ctxt.cache.find(key);
        if(it==ctxt.cache.end()) {
            buf.fault();
        }

        if(!buf.good() || it->second.empty()) {
            buf.fault();
            return;

        } else {
            // copy from cache
            ctxt.descs.resize(index+it->second.size());
            std::copy(it->second.begin(),
                      it->second.end(),
                      ctxt.descs.begin()+index);
        }

    } else if(code.code!=0xff && code.code&0x10) {
        // fixed length is deprecated
        buf.fault();

    } else {
        // actual field

        ctxt.descs.emplace_back();
        {
            auto& fld = ctxt.descs.back();

            fld.code = code;
            fld.hash = code.code;
        }

        switch(code.code) {
        case TypeCode::StructA:
        case TypeCode::UnionA:
            from_wire(buf, ctxt, depth+1);
            if(!buf.good() || ctxt.descs.size()==index || ctxt.descs[index+1].code!=code.scalarOf()) {
                buf.fault();
                return;
            }
            break;

        case TypeCode::Struct:
        case TypeCode::Union: {
            from_wire(buf, ctxt.descs.back().id);

            Size nfld{0};
            std::string name;
            from_wire(buf, nfld); // number of children
            {
                auto& fld = ctxt.descs.back();

                fld.miter.reserve(nfld.size);
                fld.hash ^= std::hash<std::string>{}(fld.id);
            }

            for(auto i: range(nfld.size)) {
                (void)i;
                const size_t cindex = ctxt.descs.size(); // index of this child
                from_wire(buf, name);
                from_wire(buf, ctxt, depth+1);
                if(!buf.good() || cindex>=ctxt.descs.size()) {
                    buf.fault();
                    return;
                }

                // descs may be re-allocated (invalidating previous refs.)
                auto& fld = ctxt.descs[index];
                auto& cfld = ctxt.descs[cindex];

                // update hash
                // TODO investigate better ways to combine hashes
                fld.hash ^= std::hash<std::string>{}(name) ^ cfld.hash;

                // update field refs.
                fld.miter.emplace_back(name, cindex-index);
                fld.mlookup[name] = cindex-index;
                name+='.';

                if(code.code==TypeCode::Struct && code==cfld.code) {
                    // copy decendent indicies for sub-struct
                    for(auto& pair : cfld.mlookup) {
                        fld.mlookup[name+pair.first] = cindex + pair.second;
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
                buf.fault();
                break;
            }
        }

        ctxt.descs[index].num_index = ctxt.descs.size()-index;
    }
}

namespace {
template<typename E, typename C = E>
void to_wire(Buffer& buf, const shared_array<const void>& varr)
{
    auto arr = shared_array_static_cast<const E>(varr);
    to_wire(buf, Size{arr.size()});
    for(auto i : range(arr.size())) {
        to_wire(buf, C(arr[i]));
    }
}

template<typename E, typename C = E>
void from_wire(Buffer& buf, shared_array<const void>& varr)
{
    Size slen;
    from_wire(buf, slen);
    shared_array<E> arr(slen.size);
    for(auto i : range(arr.size())) {
        C temp{};
        from_wire(buf, temp);
        arr[i] = temp;
    }
}
}

// serialize a field and all children (if Compound)
static
void to_wire_field(Buffer& buf, const FieldDesc* desc, const FieldStorage* store)
{
    switch(store->code) {
    case StoreType::Null:
        switch(desc->code.code) {
        case TypeCode::Struct: {
            auto& top = *store->top;
            // serialize entire sub-structure
            for(auto off : range(desc->offset+1u, desc->next_offset)) {
                auto cdesc = desc + top.member_indicies[off];
                auto cstore = store + off;
                if(cdesc->code!=TypeCode::Struct)
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
        case TypeCode::Bool:   to_wire(buf, uint8_t (fld!=0)); return;
        case TypeCode::UInt8:  to_wire(buf, uint8_t (fld)); return;
        case TypeCode::UInt16: to_wire(buf, uint16_t(fld)); return;
        case TypeCode::UInt32: to_wire(buf, uint32_t(fld)); return;
        case TypeCode::UInt64: to_wire(buf, uint64_t(fld)); return;
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
                    if(fld._desc()== desc+pair.second)
                        break;
                    index++;
                }
                if(index>=desc->miter.size())
                    throw std::logic_error("Union contains non-member type");
                to_wire(buf, Size{index});
                to_wire_field(buf, fld._desc(), fld._store());
            }
            return;

        case TypeCode::Any:
            if(!fld) {
                to_wire(buf, uint8_t(0xff));

            } else {
                to_wire(buf, fld._desc());
                to_wire_field(buf, fld._desc(), fld._store());
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
        case TypeCode::Int8:
        case TypeCode::UInt8:
            to_wire<uint8_t>(buf, fld);
            return;
        case TypeCode::Int16:
        case TypeCode::UInt16:
            to_wire<uint16_t>(buf, fld);
            return;
        case TypeCode::Int32:
        case TypeCode::UInt32:
        case TypeCode::Float32:
            to_wire<uint32_t>(buf, fld);
            return;
        case TypeCode::Int64:
        case TypeCode::UInt64:
        case TypeCode::Float64:
            to_wire<uint64_t>(buf, fld);
            return;
        case TypeCode::StringA:
            to_wire<std::string, const std::string&>(buf, fld);
            return;
        case TypeCode::StructA:{
            auto arr = shared_array_static_cast<const Value>(fld);
            to_wire(buf, Size{arr.size()});
            for(auto& elem : arr) {
                if(!elem) {
                    to_wire(buf, uint8_t(0u));
                } else {
                    to_wire(buf, uint8_t(1u));
                    assert(elem._desc()==desc+1);
                    to_wire_field(buf, elem._desc(), elem._store());
                }
            }
        }
            return;
        case TypeCode::UnionA: {
            auto arr = shared_array_static_cast<const Value>(fld);
            to_wire(buf, Size{arr.size()});
            for(auto& elem : arr) {
                if(!elem) {
                    to_wire(buf, uint8_t(0u));
                } else {
                    to_wire(buf, uint8_t(1u));

                    to_wire_field(buf, elem._desc(), elem._store());
                }
            }
        }
            return;
        case TypeCode::AnyA:{
            auto arr = shared_array_static_cast<const Value>(fld);
            to_wire(buf, Size{arr.size()});
            for(auto& elem : arr) {
                if(!elem) {
                    to_wire(buf, uint8_t(0u));
                } else {
                    to_wire(buf, uint8_t(1u));

                    to_wire(buf, elem._desc());
                    to_wire_field(buf, elem._desc(), elem._store());
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
    buf.fault();
}

void to_wire_full(Buffer& buf, const Value& val)
{
    assert(!!val);

    to_wire_field(buf, val._desc(), val._store());
}

void to_wire_valid(Buffer& buf, const Value& val)
{
    auto desc = val._desc();
    assert(!!desc);
    auto top = val._store()->top;

    to_wire(buf, top->valid);
    top->valid.resize(top->members.size());

    // iterate marked fields
    for(auto bit = top->valid.findSet(desc->offset);
        bit<desc->next_offset;
        bit = top->valid.findSet(bit+1))
    {
        to_wire_field(buf, desc + top->member_indicies[bit], val._store()+bit);
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
void from_wire_field(Buffer& buf, TypeStore& ctxt,  const FieldDesc* desc, FieldStorage* store)
{
    switch(store->code) {
    case StoreType::Null:
        switch(desc->code.code) {
        case TypeCode::Struct: {
            auto& top = *store->top;
            // serialize entire sub-structure
            for(auto off : range(desc->offset+1u, desc->next_offset)) {
                auto cdesc = desc + top.member_indicies[off];
                auto cstore = store + off;
                if(cdesc->code!=TypeCode::Struct)
                    from_wire_field(buf, ctxt, cdesc, cstore);
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
        case TypeCode::Bool:   fld = 0!=from_wire_as<uint8_t>(buf); return;
        case TypeCode::UInt8:  fld = from_wire_as<int8_t>(buf); return;
        case TypeCode::UInt16: fld = from_wire_as<int16_t>(buf); return;
        case TypeCode::UInt32: fld = from_wire_as<int32_t>(buf); return;
        case TypeCode::UInt64: fld = from_wire_as<int64_t>(buf); return;
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
                                                       desc + desc->miter[select.size].second); // alias
                fld = Value(stype);

                from_wire_field(buf, ctxt, fld._desc(), fld._store());
                return;
            }
        }
            break;

        case TypeCode::Any: {
            std::shared_ptr<std::vector<FieldDesc>> descs(new std::vector<FieldDesc>);
            TypeDeserContext dc{*descs, ctxt};

            from_wire(buf, dc);

            if(descs->empty()) {
                fld = Value();
                return;

            } else {
                std::shared_ptr<const FieldDesc> stype(descs, descs->data()); // alias
                fld = Value(stype);

                from_wire_field(buf, ctxt, fld._desc(), fld._store());
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
        case TypeCode::Int8:
        case TypeCode::UInt8:
            from_wire<uint8_t>(buf, fld);
            return;
        case TypeCode::Int16:
        case TypeCode::UInt16:
            from_wire<uint16_t>(buf, fld);
            return;
        case TypeCode::Int32:
        case TypeCode::UInt32:
        case TypeCode::Float32:
            from_wire<uint32_t>(buf, fld);
            return;
        case TypeCode::Int64:
        case TypeCode::UInt64:
        case TypeCode::Float64:
            from_wire<uint64_t>(buf, fld);
            return;
        case TypeCode::StringA:
            from_wire<std::string>(buf, fld);
            return;
        case TypeCode::StructA:{
            Size alen{};
            from_wire(buf, alen);
            shared_array<Value> arr(alen.size);
            std::shared_ptr<const FieldDesc> etype(store->top->desc,
                                                   desc + 1); // alias
            for(auto& elem : arr) {
                if(from_wire_as<uint8_t>(buf)!=0) { // strictly 1 or 0
                    elem = Value(etype);

                    from_wire_field(buf, ctxt, elem._desc(), elem._store());
                }
            }

            fld = shared_array_static_cast<const void>(freeze(std::move(arr)));
        }
            return;
        case TypeCode::UnionA: {
            Size alen{};
            from_wire(buf, alen);
            shared_array<Value> arr(alen.size);
            auto cdesc = desc+1;

            for(auto& elem : arr) {
                if(from_wire_as<uint8_t>(buf)!=0) { // strictly 1 or 0
                    Size select{};
                    from_wire(buf, select);

                    if(select.size==size_t(-1)) {
                        // null element.  treated the same as 0 case (which is what actually happens)

                    } else if(select.size < cdesc->miter.size()) {
                        std::shared_ptr<const FieldDesc> stype(store->top->desc,
                                                               cdesc + cdesc->miter[select.size].second); // alias
                        elem = Value(stype);

                        from_wire_field(buf, ctxt, elem._desc(), elem._store());
                        return;

                    } else {
                        // invalid selector
                        buf.fault();
                        break;
                    }
                }
            }

            fld = shared_array_static_cast<const void>(freeze(std::move(arr)));
        }
            return;
        case TypeCode::AnyA:{
            Size alen{};
            from_wire(buf, alen);
            shared_array<Value> arr(alen.size);

            for(auto& elem : arr) {
                if(from_wire_as<uint8_t>(buf)!=0) { // strictly 1 or 0
                    std::shared_ptr<std::vector<FieldDesc>> descs(new std::vector<FieldDesc>);
                    TypeDeserContext dc{*descs, ctxt};

                    from_wire(buf, dc);
                    if(!descs->empty()) {
                        std::shared_ptr<const FieldDesc> stype(descs, descs->data()); // alias
                        elem = Value(stype);

                        from_wire_field(buf, ctxt, elem._desc(), elem._store());
                    }
                }
            }

            fld = shared_array_static_cast<const void>(freeze(std::move(arr)));
        }
            return;
        default: break;
        }
        break;

    }
    } // end case

    assert(false);
    buf.fault();
}

void from_wire_full(Buffer& buf, TypeStore& ctxt, Value& val)
{
    assert(!!val);

    from_wire_field(buf, ctxt, val._desc(), val._store());
}

void from_wire_valid(Buffer& buf, TypeStore& ctxt, Value& val)
{
    auto desc = val._desc();
    assert(!!desc);
    auto top = val._store()->top;

    from_wire(buf, top->valid);
    // encoding rounds # of bits to whole bytes, so we may trim
    top->valid.resize(top->members.size());
    if(!buf.good())
        return;

    for(auto bit = top->valid.findSet(desc->offset);
        bit<desc->next_offset;
        bit = top->valid.findSet(bit+1))
    {
        from_wire_field(buf, ctxt, desc + top->member_indicies[bit], val._store()+bit);
    }
}

}} // namespace pvxs::impl

#endif // DATAENCODE_H
