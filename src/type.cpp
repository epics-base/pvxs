/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstring>
#include <epicsAssert.h>

#include <epicsStdlib.h>

#include "dataimpl.h"
#include "utilpvt.h"

namespace pvxs {

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

static
void node_validate(const Member* parent, const std::string& id, TypeCode code)
{
    if(!id.empty() && code!=TypeCode::Struct && code!=TypeCode::Union)
        throw std::logic_error("Only Struct or Union may have an ID");
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

Member::Member(TypeCode code, const std::string& name, const std::string& id, std::initializer_list<Member> children)
    :code(code), name(name), id(id)
{
    if(!name.empty())
        name_validate(name.c_str());
    for(auto& child : children) {
        node_validate(this, child.id, child.code);
        this->children.push_back(child);
    }
}

TypeDef::TypeDef(TypeCode code, const std::string& id, std::initializer_list<Member> children)
{
    auto temp(std::make_shared<Member>(code, "", id, children));
    top = std::move(temp);
}

static
void copy_tree(const FieldDesc* desc, Member& node)
{
    node.code = desc->code;
    node.id = desc->id;
    node.children.reserve(desc->miter.size());
    for(auto& pair : desc->miter) {
        auto cdesc = desc+pair.second;
        node.children.emplace_back(cdesc->code, cdesc->id, pair.first);
        copy_tree(cdesc, node.children.back());
    }
}

TypeDef::TypeDef(const Value& o)
{
    if(o.desc) {
        auto root(std::make_shared<Member>(o.desc->code, o.desc->id));

        copy_tree(o.desc, *root);
        top = std::move(root);
    }
}

TypeDef::~TypeDef() {}

static
void build_tree(std::vector<FieldDesc>& desc, const Member& node)
{
    auto code = node.code;
    if(node.code==TypeCode::StructA || node.code==TypeCode::UnionA) {

        desc.emplace_back();
        auto& fld = desc.back();
        fld.code = node.code;
        // struct/union array have no ID
        fld.hash = node.code.code;
        code = code.scalarOf();
    }

    const auto index = desc.size();
    desc.emplace_back();

    {
        auto& fld = desc.back();
        fld.code = code;
        fld.id = node.id;
        fld.hash = code.code ^ std::hash<std::string>{}(fld.id);
    }


    for(auto& cnode : node.children) {
        const auto cindex = desc.size();

        build_tree(desc, cnode); // recurse.  may realloc desc

        auto& fld = desc[index];
        auto& child = desc[cindex];

        fld.hash ^= std::hash<std::string>{}(cnode.name) ^ child.hash;

        fld.mlookup[cnode.name] = cindex-index;
        fld.miter.emplace_back(cnode.name, cindex-index);

        std::string cname = cnode.name+".";
        if(fld.code.code==TypeCode::Struct && fld.code==child.code) {
            // propagate names from sub-struct
            for(auto& cpair : child.mlookup) {
                fld.mlookup[cname+cpair.first] = cindex-index+cpair.second;
            }
        }
    }

    desc[index].num_index = desc.size()-index;

    if(node.code==TypeCode::StructA || node.code==TypeCode::UnionA)
    {
        desc[index-1].num_index = desc.size()-index+1;
    }
}

static
void append_tree(Member& node, const Member& adopt)
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
                append_tree(child, grandchild);
            }
            return;
        }
    }

    // new node, just append
    node.children.push_back(adopt);
}

TypeDef& TypeDef::operator+=(std::initializer_list<Member> children)
{
    if(!top || (top->code!=TypeCode::Struct && top->code!=TypeCode::Union))
        throw std::logic_error("May only append to Struct or Union");

    std::shared_ptr<Member> edit;
    if(top.use_count()==1u)
        edit = std::const_pointer_cast<Member>(top);
    else
        edit = std::make_shared<Member>(*top); // copy

    for(auto& child : children) {
        append_tree(*edit, child);
    }

    top = std::move(edit);

    return *this;
}

Value TypeDef::create() const
{
    if(!top)
        throw std::logic_error("Empty TypeDef");

    auto desc = std::make_shared<std::vector<FieldDesc>>();
    build_tree(*desc, *top);
    FieldDesc_calculate_offset(desc->data());

    std::shared_ptr<const FieldDesc> type(desc, desc->data()); // alias
    return Value(type);
}

static
void show_Node(std::ostream& strm, const std::string& name, const Member* node, unsigned level=0)
{
    strm<<node->code;
    if(!node->id.empty())
        strm<<" \""<<node->id<<"\"";
    if(!node->children.empty()) {
        strm<<" {\n";
        for(auto& cnode : node->children) {
            indent(strm, level+1);
            show_Node(strm, cnode.name, &cnode, level+1);
        }
        indent(strm, level);
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
        show_Node(strm, std::string(), def.top.get());
    }
    return strm;
}

namespace impl {


void FieldDesc_calculate_offset(FieldDesc* const top)
{
    top->offset = 0;
    uint16_t offset = 1;
    size_t index = 1;
    while(index < top->size()) {
        auto& fld = top[index];

        switch (fld.code.code) {
        case TypeCode::Struct:
            if(top->code==fld.code) {
                // sub-structure
                fld.offset = offset++;
                index++;
            } else {
                // structure inside union or array of struct
                // new offset zero
                FieldDesc_calculate_offset(top);
                index+=top->size();
            }
            break;
        case TypeCode::Union:
            // number in parent structure/union
            fld.offset = offset++;
            // new offset zero for each child
            for(auto& pair : fld.miter) {
                FieldDesc_calculate_offset(top+index+pair.second);
            }
            index += fld.size();
            break;
        case TypeCode::StructA:
        case TypeCode::UnionA:
            // number in parent structure/union
            fld.offset = offset++;
            index++;
            // new offset zero for child
            FieldDesc_calculate_offset(top+index);
            index += top[index].size();
            break;
        default:
            fld.offset = offset++;
            index++;
            break;
        }
        fld.next_offset = offset;
    }
    top->next_offset = offset;
}

std::ostream& operator<<(std::ostream& strm, const FieldDesc* desc)
{
    for(auto idx : range(desc->size())) {
        auto& fld = desc[idx];
        strm<<"["<<idx<<"] "<<fld.code<<' '<<fld.id
            <<" <"<<fld.offset<<":"<<fld.next_offset<<">"
              "  ["<<idx<<":"<<idx+fld.num_index<<")\n";

        switch(fld.code.code) {
        case TypeCode::Struct:
        case TypeCode::Union: {
            // note: need to ensure stable lexical iteration order if fld.mlookup ever becomes unordered_map
            for(auto& pair : fld.mlookup) {
                strm<<"  "<<pair.first<<" -> "<<pair.second<<" ["<<(idx+pair.second)<<"]\n";
            }
            for(auto& pair : fld.miter) {
                strm<<"  "<<pair.first<<" :  "<<pair.second<<" ["<<(idx+pair.second)<<"]\n";
            }
            break;
        }
        default:
            break;
        }
    }
    return strm;
}

} // namespace impl

} // namespace pvxs
