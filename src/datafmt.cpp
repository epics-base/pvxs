/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "dataimpl.h"

namespace pvxs {

static
void show_Value(std::ostream& strm,
                const std::string& member,
                const Value& val,
                unsigned level=0);

static
void show_Value(std::ostream& strm,
                const std::string& member,
                const FieldDesc *desc,
                const FieldStorage* store,
                unsigned level=0)
{
    indent(strm, level);
    if(!desc) {
        strm<<"null\n";
        return;
    }

    strm<<desc->code;
    if(!desc->id.empty())
        strm<<" \""<<desc->id<<"\"";
    if(!member.empty() && desc->code!=TypeCode::Struct)
        strm<<" "<<member;

    switch(store->code) {
    case StoreType::Null:
        if(desc->code==TypeCode::Struct) {
            strm<<" {\n";
            for(auto& pair : desc->miter) {
                auto cdesc = desc + pair.second;
                show_Value(strm, pair.first, cdesc, store + pair.second, level+1);
            }
            indent(strm, level);
            strm<<"}";
            if(!member.empty())
                strm<<" "<<member;
            strm<<"\n";
        } else {
            strm<<"\n";
        }
        break;
    case StoreType::Real:     strm<<" = "<<store->as<double>()<<"\n"; break;
    case StoreType::Integer:  strm<<" = "<<store->as<int64_t>()<<"\n"; break;
    case StoreType::UInteger: strm<<" = "<<store->as<uint64_t>()<<"\n"; break;
    case StoreType::Bool: strm<<" = "<<(store->as<bool>() ? "true" : "false")<<"\n"; break;
    case StoreType::String:   strm<<" = \""<<escape(store->as<std::string>())<<"\"\n"; break;
    case StoreType::Compound: {
        auto& fld = store->as<Value>();
        if(fld.valid() && desc->code==TypeCode::Union) {
            for(auto& pair : desc->miter) {
                if(&desc->members[pair.second] == Value::Helper::desc(fld)) {
                    strm<<"."<<pair.first;
                    break;
                }
            }
        }
        show_Value(strm, std::string(), fld, level+1);
    }
        break;
    case StoreType::Array: {
        auto& varr = store->as<shared_array<const void>>();
        if(varr.original_type()!=ArrayType::Value) {
            strm<<" = "<<varr<<"\n";
        } else {
            auto arr = varr.castTo<const Value>();
            strm<<" [\n";
            for(auto& val : arr) {
                show_Value(strm, std::string(), val, level+1);
            }
            indent(strm, level);
            strm<<"]\n";
        }
    }
        break;
    default:
        strm<<"!!Invalid StoreType!! "<<int(store->code)<<"\n";
        break;
    }
}

static
void show_Value(std::ostream& strm,
                const std::string& member,
                const Value& val,
                unsigned level)
{
    show_Value(strm, member,
               Value::Helper::desc(val),
               Value::Helper::store_ptr(val),
               level);
}

std::ostream& operator<<(std::ostream& strm, const Value& val)
{
    show_Value(strm, std::string(), val);
    return strm;
}

}
