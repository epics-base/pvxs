/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "dataimpl.h"

namespace pvxs {

namespace {

struct FmtDelta {
    std::ostream& strm;
    const Value::Fmt& fmt;

    void field(const std::string& prefix, const Value& val, bool verytop)
    {
        if(verytop && !val.isMarked(false))
            return;

        strm<<indent{}<<prefix;
        if(!verytop)
            strm<<" ";
        strm<<val.type().name();
        if(val.type()==TypeCode::Struct && !val.id().empty()) {
            strm<<" \""<<escape(val.id())<<'"';
        }

        if(fmt._showValue) {
            auto store = Value::Helper::store_ptr(val);

            switch(val.storageType()) {
            case StoreType::Real:     strm<<" = "<<store->as<double>(); break;
            case StoreType::Integer:  strm<<" = "<<store->as<int64_t>(); break;
            case StoreType::UInteger: strm<<" = "<<store->as<uint64_t>(); break;
            case StoreType::Bool:     strm<<" = "<<(store->as<bool>() ? "true" : "false"); break;
            case StoreType::String:   strm<<" = \""<<escape(store->as<std::string>())<<"\""; break;
            case StoreType::Array: {
                auto& varr = store->as<shared_array<const void>>();
                if(varr.original_type()!=ArrayType::Value) {
                    strm<<" = "<<varr.format().limit(fmt._limit);
                }
            }
                break;
            default:
                break;
            }
        }

        strm<<"\n";

        switch(val.type().code) {
        case TypeCode::Union:
        case TypeCode::Any: {
            auto uval = val.as<Value>();
            std::string cprefix(prefix);
            cprefix+="->";

            if(val.type()==TypeCode::Union) {
                auto desc = Value::Helper::desc(val);
                auto udesc = Value::Helper::desc(uval);
                for(auto idx : range(desc->members.size())) {
                    if(udesc == &desc->members[idx]) {
                        cprefix+=desc->miter[idx].first;
                        break;
                    }
                }
            }

            top(cprefix, uval, false);
        }
            break;
        case TypeCode::StructA:
        case TypeCode::UnionA:
        case TypeCode::AnyA: {
            auto rawval = val.as<const shared_array<const void>>();
            if(rawval.original_type()==ArrayType::Null) {

            } else if(rawval.original_type()==ArrayType::Value) {
                auto aval = rawval.castTo<const Value>();

                for(auto idx : range(aval.size())) {
                    std::ostringstream strm;
                    strm<<indent{}<<prefix<<'['<<idx<<']';

                    top(strm.str(), aval[idx], false);
                }

            } else {
                throw std::logic_error("Value[] is not");
            }
        }
            break;
        default:
            break;
        }
    }

    void top(const std::string& prefix, const Value& val, bool verytop)
    {
        if(!val) {
            strm<<indent{}<<prefix;
            if(!verytop)
                strm<<' ';
            strm<<"null\n";
            return;
        }

        field(prefix, val, verytop);

        if(val.type()==TypeCode::Struct) {
            for(auto fld : val.imarked()) {
                std::string cprefix(prefix);
                if(!verytop)
                    cprefix += '.';
                cprefix += val.nameOf(fld);
                field(cprefix, fld, false);
            }
        }
    }
};

struct FmtTree {
    std::ostream& strm;
    const Value::Fmt& fmt;

    void top(const std::string& member,
             const FieldDesc *desc,
             const FieldStorage* store)
    {
        strm<<indent{};
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
                    Indented I(strm);
                    top(pair.first, cdesc, store + pair.second);
                }
                strm<<indent{}<<"}";
                if(!member.empty())
                    strm<<" "<<member;
                strm<<"\n";
            } else {
                strm<<"\n";
            }
            break;
        case StoreType::Real:     if(fmt._showValue) { strm<<" = "<<store->as<double>(); } strm<<"\n"; break;
        case StoreType::Integer:  if(fmt._showValue) { strm<<" = "<<store->as<int64_t>(); } strm<<"\n"; break;
        case StoreType::UInteger: if(fmt._showValue) { strm<<" = "<<store->as<uint64_t>(); } strm<<"\n"; break;
        case StoreType::Bool:     if(fmt._showValue) { strm<<" = "<<(store->as<bool>() ? "true" : "false"); } strm<<"\n"; break;
        case StoreType::String:   if(fmt._showValue) { strm<<" = \""<<escape(store->as<std::string>())<<"\""; } strm<<"\n"; break;
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
            Indented I(strm);
            top(std::string(),
                Value::Helper::desc(fld),
                Value::Helper::store_ptr(fld));
        }
            break;
        case StoreType::Array: {
            auto& varr = store->as<shared_array<const void>>();
            if(!fmt._showValue) {
                strm<<"\n";
            } else if(varr.original_type()!=ArrayType::Value) {
                strm<<" = "<<varr.format().limit(fmt._limit)<<"\n";
            } else {
                auto arr = varr.castTo<const Value>();
                strm<<" [\n";
                for(auto& val : arr) {
                    Indented I(strm);
                    top(std::string(),
                        Value::Helper::desc(val),
                        Value::Helper::store_ptr(val));
                }
                strm<<indent{}<<"]\n";
            }
        }
            break;
        default:
            strm<<"!!Invalid StoreType!! "<<int(store->code)<<"\n";
            break;
        }
    }
};

} // namespace

std::ostream& operator<<(std::ostream& strm, const Value::Fmt& fmt)
{
    switch (fmt._format) {
    case Value::Fmt::Tree:
        FmtTree{strm, fmt}.top("",
                                 Value::Helper::desc(*fmt.top),
                                 Value::Helper::store_ptr(*fmt.top));
        break;
    case Value::Fmt::Delta:
        FmtDelta{strm, fmt}.top("", *fmt.top, true);
        break;
    default:
        strm<<"<Unknown Value format()>\n";
    }
    return strm;
}

}
