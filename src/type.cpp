/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstring>
#include <epicsAssert.h>

#include "dataimpl.h"
#include "utilpvt.h"

namespace pvxs {

std::ostream& operator<<(std::ostream& strm, StoreType c)
{
    const char* name = "<\?\?\?>";
    switch(c) {
#define CASE(CODE) case StoreType::CODE: name = #CODE; break
    CASE(Null);
    CASE(Bool);
    CASE(Real);
    CASE(Integer);
    CASE(UInteger);
    CASE(String);
    CASE(Compound);
    CASE(Array);
#undef CASE
    }
    return strm<<name;
}

struct Member::Helper {
    static
    void node_validate(const Member* parent, const std::string& id, TypeCode code);
    static
    void build_tree(std::vector<FieldDesc>& desc, const Member& node);
    static
    void copy_tree(const FieldDesc* desc, Member& node);
    static
    void show_Node(std::ostream& strm, const std::string& name, const Member* node);
};

bool TypeCode::valid() const
{
    if((code&0x10) && code!=Null)
        return false; // fixed size not supported
    switch(scalarOf().code) {
#define CASE(CASE, LBL) case CASE:
    CASE(Bool,   "bool");
    CASE(Int8,   "int8_t");
    CASE(Int16,  "int16_t");
    CASE(Int32,  "int32_t");
    CASE(Int64,  "int64_t");
    CASE(UInt8,  "uint8_t");
    CASE(UInt16, "uint16_t");
    CASE(UInt32, "uint32_t");
    CASE(UInt64, "uint64_t");
    CASE(Float32,"float");
    CASE(Float64,"double");
    CASE(String, "string");
    CASE(Any,    "any");
    CASE(Union,  "union");
    CASE(Struct, "struct");
    CASE(Null,   "null");
#undef CASE
        return true;
    default:
        return false;
    }
}

StoreType TypeCode::storedAs() const
{
    if(isarray()) {
        return StoreType::Array;

    } else if(code==Struct) {
        return StoreType::Null;

    } else if(code==String) {
        return StoreType::String;

    } else if(code==Bool) {
        return StoreType::Bool;

    } else if(kind()==Kind::Real) {
        return StoreType::Real;

    } else if(kind()==Kind::Integer) {
        return isunsigned() ? StoreType::UInteger : StoreType::Integer;

    } else if(kind()==Kind::Compound) {
        return StoreType::Compound;

    } else {
        throw std::logic_error(SB()<<"TypeCode::storedAs("<<(*this)<<") not map");
    }
}

ArrayType TypeCode::arrayType() const
{
    switch(code) {
#define CASE(ATYPE, TYPE) case TypeCode::TYPE: return ArrayType::ATYPE
    CASE(Bool, BoolA);
    CASE(Int8, Int8A);
    CASE(Int16, Int16A);
    CASE(Int32, Int32A);
    CASE(Int64, Int64A);
    CASE(UInt8, UInt8A);
    CASE(UInt16, UInt16A);
    CASE(UInt32, UInt32A);
    CASE(UInt64, UInt64A);
    CASE(Float32, Float32A);
    CASE(Float64, Float64A);
    CASE(String, StringA);
    CASE(Value, StructA);
    CASE(Value, UnionA);
    CASE(Value, AnyA);
#undef CASE
    default:
        throw std::logic_error("TypeCode can not be mapped to ArrayType");
    }
}

const char* TypeCode::name() const
{
    switch(code) {
#define CASE(CASE, LBL) case TypeCode::CASE: return LBL
    CASE(Bool,   "bool");
    CASE(Int8,   "int8_t");
    CASE(Int16,  "int16_t");
    CASE(Int32,  "int32_t");
    CASE(Int64,  "int64_t");
    CASE(UInt8,  "uint8_t");
    CASE(UInt16, "uint16_t");
    CASE(UInt32, "uint32_t");
    CASE(UInt64, "uint64_t");
    CASE(Float32,"float");
    CASE(Float64,"double");
    CASE(String, "string");
    CASE(Any,    "any");
    CASE(Union,  "union");
    CASE(Struct, "struct");
    CASE(Null,   "null");
#undef CASE
#define CASE(CASE, LBL) case TypeCode::CASE##A: return LBL "[]"
    CASE(Bool,   "bool");
    CASE(Int8,   "int8_t");
    CASE(Int16,  "int16_t");
    CASE(Int32,  "int32_t");
    CASE(Int64,  "int64_t");
    CASE(UInt8,  "uint8_t");
    CASE(UInt16, "uint16_t");
    CASE(UInt32, "uint32_t");
    CASE(UInt64, "uint64_t");
    CASE(Float32,"float");
    CASE(Float64,"double");
    CASE(String, "string");
    CASE(Any,    "any");
    CASE(Union,  "union");
    CASE(Struct, "struct");
#undef CASE
    }
    return "\?\?\?_t";
}

std::ostream& operator<<(std::ostream& strm, TypeCode c)
{
    auto name = c.name();
    if(name[0]!='?') {
        strm<<name;
    } else {
        Restore R(strm);
        strm<<"TypeCode(0x"<<std::hex<<(unsigned)c.code<<")";
    }
    return strm;
}

void Member::Helper::node_validate(const Member* parent, const std::string& id, TypeCode code)
{
    if(!id.empty() && code.scalarOf()!=TypeCode::Struct && code.scalarOf()!=TypeCode::Union)
        throw std::logic_error("Only Struct or Union may have an ID");
    else if(!code.valid())
        throw std::logic_error("Invalid TypeCode");
    if(parent) {
        auto c = parent->code.scalarOf();
        if(c!=TypeCode::Struct && c!=TypeCode::Union)
            throw std::logic_error("Only (array of) Struct or Union may have members");
    }
}

static
void name_validate(const char *name)
{
    // [a-zA-Z_][a-zA-Z0-9_]*

    if(!name || name[0]=='\0')
        throw std::runtime_error("empty field name not allowed");
    for(size_t i=0; name[i]; i++) {
        char c = name[i];
        if(c>='0' && c<='9' && i>0) {
            // number ok after first
        } else if((c>='a' && c<='z') || (c>='A' && c<='Z')) {
            // alphas ok
        } else {
            switch(c) {
            case '_':
                break;
            default:
                throw std::runtime_error(SB()<<"invalid field name \""<<escape(name)<<"\"");
            }
        }
    }
}

void Member::_validate() const
{
    if(!name.empty())
        name_validate(name.c_str());
    Helper::node_validate(nullptr, id, code);
    for(auto& child : children) {
        Helper::node_validate(this, child.id, child.code);
    }
}

void Member::addChild(const Member& mem)
{
    Helper::node_validate(this, mem.id, mem.code);
    children.push_back(mem);
}

void Member::Helper::build_tree(std::vector<FieldDesc>& desc, const Member& node)
{
    auto code = node.code;
    if(node.code==TypeCode::StructA || node.code==TypeCode::UnionA) {

        desc.emplace_back(node.code);
        // struct/union array have no ID

        Member next{code.scalarOf(), node.name};
        next.id = node.id;
        next.children = node.children; // TODO ick copy

        build_tree(desc.back().members, next);
        return;
    }

    const auto index = desc.size();
    desc.emplace_back(code);

    {
        auto& fld = desc.back();
        fld.id = node.id;
    }

    auto& cdescs = code.code==TypeCode::Struct ? desc : desc.back().members;
    auto cref = code.code==TypeCode::Struct ? index : 0u;

    for(auto& cnode : node.children) {
        const auto cindex = cdescs.size();

        build_tree(cdescs, cnode); // recurse.  may realloc desc

        auto& fld = desc[index];
        auto& child = cdescs[cindex];
        if(code.code==TypeCode::Struct)
            child.parent_index = cindex-cref;

        fld.mlookup[cnode.name] = cindex-cref;
        fld.miter.emplace_back(cnode.name, cindex-cref);

        std::string cname = cnode.name+".";
        if(fld.code.code==TypeCode::Struct && fld.code==child.code) {
            // propagate names from sub-struct
            for(auto& cpair : child.mlookup) {
                fld.mlookup[cname+cpair.first] = cindex-cref+cpair.second;
            }
        }
    }

    assert(desc.size()==index+desc[index].size());
}

TypeDef::TypeDef(std::shared_ptr<const Member>&& temp)
{
    auto tempdesc = std::make_shared<std::vector<FieldDesc>>();
    Member::Helper::build_tree(*tempdesc, *temp);

    std::shared_ptr<const FieldDesc> type(tempdesc, tempdesc->data()); // alias

    top = std::move(temp);
    desc = std::move(type);
}

void Member::Helper::copy_tree(const FieldDesc* desc, Member& node)
{
    node.code = desc->code;
    node.id = desc->id;
    node.children.reserve(desc->miter.size());
    for(auto& pair : desc->miter) {
        auto cdesc = desc+pair.second;
        node.children.emplace_back(cdesc->code, pair.first);
        node.children.back().id = cdesc->id;
        copy_tree(cdesc, node.children.back());
    }
}

TypeDef::TypeDef(const Value& val)
{
    if(val.desc) {
        auto root(std::make_shared<Member>(val.desc->code, ""));
        root->id = val.desc->id;

        Member::Helper::copy_tree(val.desc, *root);

        auto temp = std::make_shared<std::vector<FieldDesc>>();
        Member::Helper::build_tree(*temp, *root);

        std::shared_ptr<const FieldDesc> type(temp, temp->data()); // alias

        top = std::move(root);
        desc = std::move(type);
    }
}

TypeDef::~TypeDef() {}

Member TypeDef::as(const std::string& name) const
{
    if(!top)
        throw std::logic_error("Can't append empty TypeDef");

    Member ret(*top);
    ret.name = name;
    return ret;
}

Member TypeDef::as(TypeCode code, const std::string& name) const
{
    Member ret(as(name));

    if((code.kind()==Kind::Compound) ^ (ret.code.kind()==Kind::Compound))
        throw std::logic_error("as() may change between Compound and non-Compound");

    ret.code = code;
    return ret;
}

std::shared_ptr<Member> TypeDef::_append_start()
{
    if(!top || (top->code.scalarOf()!=TypeCode::Struct && top->code.scalarOf()!=TypeCode::Union))
        throw std::logic_error("May only append to Struct, Union, StructA, or UnionA");

    std::shared_ptr<Member> edit;
    if(top.use_count()==1u) {
        edit = std::const_pointer_cast<Member>(top);
        top.reset(); // so we don't leave partial tree on error.
    } else {
        edit = std::make_shared<Member>(*top); // copy
    }

    return edit;
}

void TypeDef::_append(Member& node, const Member& adopt)
{
    for(auto& child : node.children) {
        if(child.name==adopt.name) {
            // update of existing.

            if((child.code.kind()==Kind::Compound) != (adopt.code.kind()==Kind::Compound)) {
                throw std::logic_error(SB()<<"May not change member '"<<adopt.name<<"' kind to/from Compound");
            }

            child.code = adopt.code;
            if(!adopt.id.empty())
                child.id = adopt.id;

            for(auto& grandchild : adopt.children) {
                _append(child, grandchild);
            }
            return;
        }
    }

    // new node, just append
    node.children.push_back(adopt);
}

void TypeDef::_append_finish(std::shared_ptr<Member>&& edit)
{
    auto temp = std::make_shared<std::vector<FieldDesc>>();
    Member::Helper::build_tree(*temp, *edit);

    std::shared_ptr<const FieldDesc> type(temp, temp->data()); // alias

    top = std::move(edit);
    desc = std::move(type);
}

Value TypeDef::create() const
{
    if(!desc)
        throw std::logic_error("Empty TypeDef");

    return Value(desc);
}

void Member::Helper::show_Node(std::ostream& strm, const std::string& name, const Member* node)
{
    strm<<node->code;
    if(!node->id.empty())
        strm<<" \""<<node->id<<"\"";
    if(!node->children.empty()) {
        strm<<" {\n";
        for(auto& cnode : node->children) {
            Indented I(strm);
            strm<<indent{};
            show_Node(strm, cnode.name, &cnode);
        }
        strm<<indent{};
        strm.put('}');
        if(!name.empty())
            strm<<" "<<name;
        strm.put('\n');
    } else {
        if(!name.empty())
            strm<<" "<<name;
        strm<<"\n";
    }
}

std::ostream& operator<<(std::ostream& strm, const TypeDef& def)
{
    if(!def.top) {
        strm<<"<Empty>\n";
    } else {
        Member::Helper::show_Node(strm, std::string(), def.top.get());
    }
    return strm;
}

namespace impl {

void show_FieldDesc(std::ostream& strm, const FieldDesc* desc)
{
    for(auto idx : range(desc->size())) {
        auto& fld = desc[idx];
        strm<<indent{}<<"["<<idx<<"] "<<fld.code<<' '<<fld.id
            <<" parent=["<<(idx-fld.parent_index)   <<"]"
              "  ["<<idx<<":"<<idx+fld.size()<<")\n";

        switch(fld.code.code) {
        case TypeCode::Struct:
            // note: need to ensure stable lexical iteration order if fld.mlookup ever becomes unordered_map
            for(auto& pair : fld.mlookup) {
                strm<<indent{}<<"    "<<pair.first<<" -> "<<pair.second<<" ["<<(idx+pair.second)<<"]\n";
            }
            for(auto& pair : fld.miter) {
                strm<<indent{}<<"    "<<pair.first<<" :  "<<pair.second<<" ["<<(idx+pair.second)<<"]\n";
            }
            break;

        case TypeCode::Union:
            for(auto& pair : fld.mlookup) {
                strm<<indent{}<<"    "<<pair.first<<" -> "<<pair.second<<" ["<<(pair.second)<<"]\n";
            }
            for(auto& pair : fld.miter) {
                strm<<indent{}<<"    "<<pair.first<<" :  "<<pair.second<<" ["<<(pair.second)<<"]\n";
                Indented I(strm);
                show_FieldDesc(strm, fld.members.data()+pair.second);
            }
            break;

        case TypeCode::StructA:
        case TypeCode::UnionA: {
            Indented I(strm);
            show_FieldDesc(strm, fld.members.data());
            break;
        }
        default:
            break;
        }
    }
}

std::ostream& operator<<(std::ostream& strm, const FieldDesc* desc)
{
    show_FieldDesc(strm, desc);
    return strm;
}

} // namespace impl

} // namespace pvxs
