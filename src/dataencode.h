/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef DATAENCODE_H
#define DATAENCODE_H

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

template<typename Buf>
void to_wire(Buf& buf, const FieldDesc* cur)
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

typedef std::map<uint16_t, std::vector<FieldDesc>> TypeStore;

struct TypeDeserContext {
    std::vector<FieldDesc>& descs;
    TypeStore& cache;
};

template<typename Buf>
void from_wire(Buf& buf, TypeDeserContext& ctxt, unsigned depth=0)
{
    if(!buf.good() || depth>20) {
        buf.fault();
        return;
    }

    TypeCode code;
    from_wire(buf, code.code);
    const size_t index = ctxt.descs.size(); // index of first node we add to ctxt.descs[]

    if(code.code==0xfd) {
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
            switch(code.code&~0x08) {
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

}} // namespace pvxs::impl

#endif // DATAENCODE_H
