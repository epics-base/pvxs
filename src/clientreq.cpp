/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <map>
#include <string>

#include <pvxs/version.h>
#include <pvxs/client.h>
#include "utilpvt.h"

namespace pvxs {
namespace client {
namespace detail {

struct CommonBase::Req {
    Value pvRequest;

    Member fields;

    std::map<std::string, Value> options;
    Member record;

    Req()
        :fields(TypeCode::Struct, "fields")
        ,record(TypeCode::Struct, "record", {
                Member(TypeCode::Struct, "_options")
        })
    {}
};

CommonBase::~CommonBase() {}

void CommonBase::_rawRequest(Value&& raw)
{
    if(!req)
        req = std::make_shared<Req>();
    req->pvRequest = std::move(raw);
}
void CommonBase::_field(const std::string& s)
{
    if(!req)
        req = std::make_shared<Req>();

    size_t idx=0u;

    decltype (req->fields) *cur = &req->fields;

    while(idx<s.size()) {
        auto sep = s.find_first_of('.', idx);

        if(sep==idx) {
            idx++;
            continue;

        }
        std::string child;

        if(sep==std::string::npos) {
            child = s.substr(idx);
            idx = sep;

        } else {
            child = s.substr(idx, sep-idx);
            idx = sep+1;
        }

        size_t idx = cur->children.size();
        for(auto x : range(cur->children.size())) {
            auto& c = cur->children[x];
            if(c.name==child) {
                idx = x;
                break;
            }
        }

        if(idx==cur->children.size()) {
            cur->addChild(Member(TypeCode::Struct, child));
        }
    }
}

void CommonBase::_record(const std::string& key, const void* value, StoreType vtype)
{
    if(!req)
        req = std::make_shared<Req>();

    TypeCode base;
    switch (vtype) {
    case StoreType::Bool:     base = TypeCode::Bool; break;
    case StoreType::Integer:  base = TypeCode::Int64; break;
    case StoreType::UInteger: base = TypeCode::UInt64; break;
    case StoreType::Real:     base = TypeCode::Float64; break;
    case StoreType::String:   base = TypeCode::String; break;
    default:
        throw std::logic_error("record() only support scalar values");
    }

    Value v = TypeDef(base).create();
    v.copyIn(value, vtype);

    if(req->options.find(key)==req->options.end()) {
        req->record.children[0].addChild(Member(base, key));
    }

    req->options[key] = std::move(v);
}

void CommonBase::_parse(const std::string& req)
{
    throw std::logic_error("Not implemented");
}

Value CommonBase::_build()
{
    if(!req) {
        using namespace pvxs::members;
        return TypeDef(TypeCode::Struct, {
                           Struct("field", {}),
                       }).create();

    } else if(req->pvRequest) {
        return req->pvRequest;

    } else {
        auto inst = TypeDef(TypeCode::Struct, {
                                req->fields,
                                req->record,
                            }).create();

        auto opt = inst["record._options"];
        for(auto& pair : req->options) {
            opt[pair.first].assign(pair.second);
        }

        return inst;
    }
}

} // namespace detail
} // namespace client
} // namespace pvxs
