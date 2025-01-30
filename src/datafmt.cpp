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
            for(const auto& fld : val.imarked()) {
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

    void show_value(const Value& fld) {
        const auto type(fld.type());
        assert(type.kind()!=Kind::Compound);

        switch(type.code) {
        case TypeCode::Bool:
            strm<<(fld.as<bool>() ? "true" : "false");
            return;
        case TypeCode::Int8:
        case TypeCode::Int16:
        case TypeCode::Int32:
        case TypeCode::Int64:
            strm<<fld.as<int64_t>();
            return;
        case TypeCode::UInt8:
        case TypeCode::UInt16:
        case TypeCode::UInt32:
        case TypeCode::UInt64:
            strm<<fld.as<uint64_t>();
            return;
        case TypeCode::Float32:
        case TypeCode::Float64:
            strm<<fld.as<double>();
            return;
        case TypeCode::String:
            strm<<"\""<<escape(fld.as<std::string>())<<"\"";
            return;
        case TypeCode::BoolA:
        case TypeCode::Int8A:
        case TypeCode::Int16A:
        case TypeCode::Int32A:
        case TypeCode::Int64A:
        case TypeCode::UInt8A:
        case TypeCode::UInt16A:
        case TypeCode::UInt32A:
        case TypeCode::UInt64A:
        case TypeCode::Float32A:
        case TypeCode::Float64A:
        case TypeCode::StringA:
        {
            auto varr = fld.as<shared_array<const void>>();
            strm<<varr.format().limit(fmt._limit);
        }
            return;
        case TypeCode::Any:
        case TypeCode::Struct:
        case TypeCode::Union:
        case TypeCode::StructA:
        case TypeCode::UnionA:
        case TypeCode::AnyA:
            assert(false);
            break;
        default:
            strm<<"!!Invalid TypeCode!! "<<int(type.code)<<"\n";
            return;
        }
    }

    // each invocation emits at least one complete line
    void show(const Value& fld, const std::string& member) {
        // caller should indent{}
        if(!fld) {
            strm<<"null\n";
            return;
        }

        const auto type(fld.type());

        strm<<type;
        {
            auto id(fld.id());
            if(!id.empty())
                strm<<" \""<<id<<"\"";
        }

        if(type.kind()!=Kind::Compound) {
            if(!member.empty())
                strm<<' '<<member;
            if(fmt._showValue) {
                strm<<" = ";
                show_value(fld);
            }
            strm<<"\n";
            return;
        }

        if(type==TypeCode::Any
                || (!fmt._showValue && type==TypeCode::AnyA)
                || (fmt._showValue && type==TypeCode::Union)) {
            // any NAME = VAL
            // union NAME.MEM TYPE = VAL

            Value val;
            if(fmt._showValue)
                val = fld.as<Value>();

            if(!member.empty())
                strm<<' '<<member;

            if(type==TypeCode::Union && val) { // implied _showValue
                auto mem(fld.nameOf(val));
                strm<<'.'<<mem;
            }
            if(fmt._showValue) {
                strm<<" ";
                show(val, std::string());
            } else {
                strm<<"\n";
            }
            return;

        } else if(type==TypeCode::Struct
                  || type==TypeCode::Union // && !_showValue
                  || (!fmt._showValue && type==TypeCode::StructA)
                  || (!fmt._showValue && type==TypeCode::UnionA))
        {
            // struct "id" { ... } NAME

            Value def;
            if(!type.isarray()) {
                def = fld;
            } else { // StructA, UnionA
                //def = fld.allocMember(); // can't call directly due to const
                auto desc(Value::Helper::desc(fld));
                auto store(Value::Helper::store(fld));
                decltype (store->top->desc) fld(store->top->desc, desc->members.data());
                def = Value::Helper::build(fld); // not connection to fld (not parent)
            }

            strm<<" {";
            bool first = true;
            {
                Indented I(strm);
                for(auto mem : def.ichildren()) {
                    auto mname(def.nameOf(mem));
                    if(first)
                        strm<<'\n';
                    strm<<indent{};
                    show(mem, mname);
                    first = false;
                }
            }
            if(!first)
                strm<<indent{};
            strm<<'}';

            if(!member.empty())
                strm<<' '<<member;
            strm<<"\n";

        } else {
            // struct[] NAME = [ ... ]

            if(!member.empty())
                strm<<' '<<member;

            auto arr(fld.as<shared_array<const Value>>());
            strm<<" = {"<<arr.size()<<"}[";
            size_t shown = 0u;
            {
                Indented I(strm);

                for(auto& elem : arr) {
                    if(!shown)
                        strm<<'\n';
                    strm<<indent{};
                    if(fmt._limit && shown>=fmt._limit) {
                        strm<<"...\n";
                        break;
                    }
                    show(elem, std::string());
                    shown++;
                }
            }

            if(shown)
                strm<<indent{};
            strm<<"]\n";
        }
    }
};

} // namespace

std::ostream& operator<<(std::ostream& strm, const Value::Fmt& fmt)
{
    switch (fmt._format) {
    case Value::Fmt::Tree:
        strm<<indent{};
        FmtTree{strm, fmt}.show(*fmt.top, std::string());
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
