/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "pvrequest.h"
#include "dataimpl.h"

namespace pvxs {
namespace impl {

BitMask request2mask(const FieldDesc* desc, const Value& pvRequest)
{
    auto fields = pvRequest["field"];
    // pre-select top wildcard bit, which will always be permitted
    BitMask ret({0u}, desc->size());
    // have we found at least one requested field?
    bool foundrequested = false;

    if(fields.type()==TypeCode::Struct) {
        auto rdesc = Value::Helper::desc(fields);

        if(rdesc->mlookup.empty())
            foundrequested = true; // empty is wildcard

        // iterate pvRequest fields
        for(auto& pair : rdesc->mlookup) {
            auto crdesc = rdesc + pair.second;

            if(crdesc->code==TypeCode::Struct) {
                // attempt to match up with actual structure
                auto it = desc->mlookup.find(pair.first);
                if(it!=desc->mlookup.end()) {
                    // match found
                    auto cdesc = desc + it->second;

                    ret[it->second] = true;
                    foundrequested = true;

                    if(crdesc->mlookup.empty() && cdesc->code==TypeCode::Struct) {
                        // implicit select of all fields sub-struct

                        for(auto& pair2 : cdesc->mlookup)
                            ret[it->second + pair2.second] = true;
                    }

                } else {
                    // request of non-existent field
                }
            }
        }

    } else if(!fields.valid()) {
        foundrequested = true;

    } else {
        // .fields isn't a sub-struct
    }

    if(!foundrequested)
        throw std::runtime_error("Empty field selection");

    if(ret.findSet(1)==ret.size()) {
        // empty mask is wildcard
        for(auto bit : range(desc->size()))
            ret[bit] = true;

    }

    return ret;
}

bool testmask(const Value& update, const BitMask& mask)
{
    auto desc = Value::Helper::desc(update);
    auto store = Value::Helper::store_ptr(update);

    if(!desc)
        return false;

    if(store->valid && mask[0])
        return true;

    if(desc->code==TypeCode::Struct) {
        for(auto idx : range(size_t(1u), desc->size())) {
            if(store[idx].valid && mask[idx])
                return true;
        }
    }

    return false;
}

}} // namespace pvxs::impl
