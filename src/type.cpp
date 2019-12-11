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

struct TypeDef::Node {
    Node * const parent;
    std::string id;
    TypeCode code;
    std::vector<std::pair<std::string, decltype (TypeDef::root)>> children;
    explicit Node(Node *parent) :parent(parent) {}
    Node(Node* parent, const char *id, TypeCode code) :parent(parent), id(id?id:""), code(code) {}

    decltype (TypeDef::root) clone(Node *new_parent) const {
        decltype (TypeDef::root) ret{new Node(new_parent, id.c_str(), code)};
        ret->children.reserve(children.size());
        for(auto& pair : children) {
            ret->children.emplace_back(pair.first, pair.second->clone(ret.get()));
        }
        return ret;
    }
};

void TypeDef::NodeDeletor::operator()(Node *p)
{
    delete p;
}

static
void node_validate(const TypeDef::Node* parent, const char  *id, TypeCode code)
{
    if(id && code!=TypeCode::Struct && code!=TypeCode::Union)
        throw std::runtime_error("Only Struct or Union may have an ID");
    if(parent) {
        auto c = parent->code.scalarOf();
        if(c!=TypeCode::Struct && c!=TypeCode::Union)
            throw std::runtime_error("Only (array of) Struct or Union may have members");
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

TypeDef::TypeDef(TypeCode code, const char *id)
    :root{new Node(nullptr, id, code)}
{
    node_validate(nullptr, id, code);
}

static
void copy_tree(const FieldDesc* desc, TypeDef::Node& node)
{
    node.code = desc->code;
    node.id = desc->id;
    node.children.reserve(desc->miter.size());
    for(auto& pair : desc->miter) {
        node.children.emplace_back(pair.first,
                                   decltype (node.children)::value_type::second_type{new TypeDef::Node(&node)});
        copy_tree(desc+pair.second, *node.children.back().second);
    }
}

TypeDef::TypeDef(const Value& o)
{
    if(o.desc) {
        root.reset(new Node(nullptr));
        copy_tree(o.desc, *root);
    }
}

TypeDef::~TypeDef() {}

TypeDef TypeDef::clone() const
{
    TypeDef ret;
    if(root) {
        ret.root = root->clone(nullptr);
    }
    return ret;
}

TypeDef::Cursor TypeDef::begin()
{
    if(!root)
        throw std::runtime_error("Can't edit empty TypeDef");
    Cursor ret;
    ret.owner = this;
    ret.reset();
    return ret;
}

static
void build_tree(std::vector<FieldDesc>& desc, const TypeDef::Node& node)
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


    for(auto& pair : node.children) {
        const auto cindex = desc.size();

        build_tree(desc, *pair.second); // recurse.  may realloc desc

        auto& fld = desc[index];
        auto& child = desc[cindex];

        fld.hash ^= std::hash<std::string>{}(pair.first) ^ child.hash;

        fld.mlookup[pair.first] = cindex-index;
        fld.miter.emplace_back(pair.first, cindex-index);

        std::string cname = pair.first+".";
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

Value TypeDef::create() const
{
    if(!root)
        throw std::logic_error("Empty TypeDef");

    auto desc = std::make_shared<std::vector<FieldDesc>>();
    build_tree(*desc, *root);
    FieldDesc_calculate_offset(desc->data());

    std::shared_ptr<const FieldDesc> type(desc, desc->data()); // alias
    return Value(type);
}

TypeDef::Cursor& TypeDef::Cursor::seek(const char *name)
{
    while(name && name[0]) {
        auto sep = strchr(name, '.');
        std::string fname;
        if(sep) {
            fname = std::string(name, sep-name);
            name = sep+1;
        } else {
            fname = name;
            name = nullptr;
        }

        for(auto i : range(parent->children.size())) {
            auto& pair = parent->children[i];
            if(pair.first==fname) {
                auto code = pair.second->code.scalarOf();
                if(code==TypeCode::Union || code==TypeCode::Struct) {
                    parent = pair.second.get();
                    index = parent->children.size();

                } else if(sep) {
                    throw std::runtime_error("Can only seek through Struct/Union");

                } else {
                    index = i;
                }
            }
        }
    }

    return *this;
}

TypeDef::Cursor& TypeDef::Cursor::change(const char *id, TypeCode code)
{
    node_validate(parent, id, code);

    if(index>=parent->children.size()) {
        throw std::runtime_error("Cursor does not select a field");
    } else {
        auto& fld = parent->children[index];
        if(code.kind()!=Kind::Compound && !fld.second->children.empty())
            throw std::runtime_error("May not change type of Compound field w/ sub-fields");
        fld.second->id = id;
        fld.second->code = code;
    }
    return *this;
}

TypeDef::Cursor& TypeDef::Cursor::insert(const char *name, const char *id, TypeCode code)
{
    node_validate(parent, id, code);
    name_validate(name);

    decltype (owner->root) node{new Node(parent, id, code)};

    parent->children.emplace(parent->children.begin()+index,
                             name, std::move(node));
    index++;
    return *this;
}

TypeDef::Cursor& TypeDef::Cursor::add(const char *name, const TypeDef& def)
{
    name_validate(name);

    if(!def.root)
        throw std::runtime_error("Empty TypeDef");

    node_validate(parent, def.root->id.c_str(), def.root->code);

    parent->children.emplace(parent->children.begin()+index,
                            name, std::move(def.root->clone(parent)));

    return *this;
}

TypeDef::Cursor& TypeDef::Cursor::up()
{
    if(parent!=owner->root.get()) {
        parent = parent->parent;
        index = parent->children.size();
    } else {
        throw std::logic_error("Can't go up() from root");
    }
    return *this;
}

TypeDef::Cursor& TypeDef::Cursor::reset()
{
    parent = owner->root.get();
    index = parent->children.size();
    return *this;
}

static
void show_Node(std::ostream& strm, const std::string& name, const TypeDef::Node* node, unsigned level=0)
{
    strm<<node->code;
    if(!node->id.empty())
        strm<<" \""<<node->id<<"\"";
    if(!node->children.empty()) {
        strm<<" {\n";
        for(auto& pair : node->children) {
            indent(strm, level+1);
            show_Node(strm, pair.first, pair.second.get(), level+1);
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
    if(!def.root) {
        strm<<"<Empty>\n";
    } else {
        show_Node(strm, std::string(), def.root.get());
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
