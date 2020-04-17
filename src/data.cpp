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

NoField::NoField()
    :std::runtime_error ("No such field")
{}

NoField::~NoField() {}

NoConvert::NoConvert()
    :std::runtime_error ("No conversion defined")
{}

NoConvert::~NoConvert() {}

std::shared_ptr<const impl::FieldDesc>
Value::Helper::type(const Value& v)
{
    if(v) {
        return std::shared_ptr<const impl::FieldDesc>(v.store->top->desc, v.desc);
    } else {
        return nullptr;
    }
}

Value Value::Helper::build(const void* ptr, StoreType type)
{
    TypeCode base{TypeCode::Null};
    switch (type) {
    case StoreType::Bool:     base = TypeCode::Bool; break;
    case StoreType::Integer:  base = TypeCode::Int64; break;
    case StoreType::UInteger: base = TypeCode::UInt64; break;
    case StoreType::Real:     base = TypeCode::Float64; break;
    case StoreType::String:   base = TypeCode::String; break;
    case StoreType::Array: {
        auto& arr = *static_cast<const shared_array<const void>*>(ptr);
        switch(arr.original_type()) {
#define CASE(TYPE) case ArrayType::TYPE: base = TypeCode::TYPE ## A; break
        CASE(Bool);
        CASE(Int8);
        CASE(Int16);
        CASE(Int32);
        CASE(Int64);
        CASE(UInt8);
        CASE(UInt16);
        CASE(UInt32);
        CASE(UInt64);
        CASE(Float32);
        CASE(Float64);
        CASE(String);
#undef CASE
        case ArrayType::Value:
            base = TypeCode::AnyA;
            break;
        case ArrayType::Null:
            throw std::logic_error("Unable to infer ArrayType::Null");
        }
    }
        break;
    case StoreType::Compound: {
        auto src = *reinterpret_cast<const Value*>(ptr);
        if(src) {
            auto dst = TypeDef(src).create();
            dst.assign(src);
            return dst;
        }
    }
        base = TypeCode::Any;
        break;
    case StoreType::Null:
        throw std::logic_error("Unable to infer ArrayType::Null");
    }

    Value ret(TypeDef(base).create());
    ret.copyIn(ptr, type);

    return ret;
}

Value::Value(const std::shared_ptr<const impl::FieldDesc>& desc)
    :desc(nullptr)
{
    if(!desc)
        return;

    auto top = std::make_shared<StructTop>();

    top->desc = desc;
    top->members.resize(desc->size());
    {
        auto& root = top->members[0];
        root.init(desc->code.storedAs());
        root.top = top.get();
    }

    if(desc->code==TypeCode::Struct) {
        for(auto& pair : desc->mlookup) {
            auto cfld = desc.get() + pair.second;
            auto& mem = top->members.at(pair.second);
            mem.top = top.get();
            mem.init(cfld->code.storedAs());
        }
    }

    this->desc = desc.get();
    decltype (store) val(top, top->members.data()); // alias
    this->store = std::move(val);
}

Value::Value(const std::shared_ptr<const impl::FieldDesc>& desc, Value& parent)
    :Value(desc)
{
    store->top->enclosing = parent.store;
}

Value::~Value() {}

Value Value::cloneEmpty() const
{
    Value ret;
    if(desc) {
        decltype (store->top->desc) fld(store->top->desc, desc);
        ret = Value(fld);
    }
    return ret;
}

Value Value::clone() const
{
    Value ret;
    if(desc) {
        decltype (store->top->desc) fld(store->top->desc, desc);
        ret = Value(fld);
        ret.assign(*this);
    }
    return ret;
}

Value& Value::assign(const Value& o)
{
    if(!store || !o.store)
        throw std::logic_error("Can't assign() to/from empty Value");

    if(type().kind()==Kind::Compound) {
        // pass through Struct and others w/ type
        copyIn(&o, StoreType::Compound);
    } else {
        // unpack other field types
        copyIn(o.store.get(), o.store->code);
    }
    return *this;
}

Value Value::allocMember()
{
    // allocate member type for Struct[] or Union[]
    if(!desc || (desc->code!=TypeCode::UnionA && desc->code!=TypeCode::StructA))
        throw std::runtime_error("allocMember() only meaningful for Struct[] or Union[]");

    decltype (store->top->desc) fld(store->top->desc, desc->members.data());
    return Value::Helper::build(fld, *this);
}

bool Value::isMarked(bool parents, bool children) const
{
    if(!desc)
        return false;

    if(store->valid)
        return true;

    auto top = store->top;

    if(children && desc->size()>1u) {
        // TODO more efficient
        for(auto bit : range(desc->size()))
        {
            auto cstore = store.get() + bit;
            if(cstore->valid)
                return true;
        }
    }

    if(parents) {
        auto pdesc = desc;
        auto pstore = store.get();
        while(pdesc!=top->desc.get()) {
            pstore -= pdesc->parent_index;
            pdesc -= pdesc->parent_index;

            if(pstore->valid)
                return true;
        }
    }

    return false;
}

Value Value::ifMarked(bool parents, bool children) const
{
    Value ret;
    if(isMarked(parents, children))
        ret = *this;
    return ret;
}

void Value::mark(bool v)
{
    if(!desc)
        return;

    store->valid = v;
    if(!v)
        return;

    auto top = store->top;
    std::shared_ptr<FieldStorage> enc;
    while(top && (enc=top->enclosing.lock())) {
        enc->valid = true;
        top = enc->top;
    }
}

void Value::unmark(bool parents, bool children)
{
    if(!desc)
        return;

    store->valid = false;

    auto top = store->top;

    if(children && desc->size()>1u) {
        // TODO more efficient
        for(auto bit : range(desc->size()))
        {
            (store.get() + bit)->valid = false;
        }
    }

    if(parents) {
        auto pdesc = desc;
        auto pstore = store.get();
        while(pdesc!=top->desc.get()) {
            pdesc -= pdesc->parent_index;
            pstore -= pdesc->parent_index;

            pstore->valid = false;
        }
    }
}

TypeCode Value::type() const
{
    return desc ? desc->code : TypeCode::Null;
}

StoreType Value::storageType() const
{
    return store ? store->code : StoreType::Null;
}

const std::string& Value::id() const
{
    if(!desc)
        throw std::runtime_error("Null Value");
    return desc->id;
}

bool Value::idStartsWith(const std::string& prefix) const
{
    auto ID = this->id();
    return ID.size()>=prefix.size() && prefix==ID.substr(0u, prefix.size());
}

const std::string &Value::nameOf(const Value& decendent) const
{
    if(!store || !decendent.store)
        throw NoField();
    auto pidx = store->index();
    auto didx = decendent.store->index();
    if(pidx >= didx || didx >= store->top->members.size())
        throw std::logic_error("not a decendent");

    // inefficient, but we don't keep a reverse mapping
    for(auto& it : desc->mlookup) {
        if(it.second == didx-pidx)
            return it.first;
    }

    throw std::logic_error("missing decendent");
}

namespace {
// C-style cast between scalar storage types, and print to string (base 10)
template<typename Src>
bool copyOutScalar(const Src& src, void *ptr, StoreType type)
{
    switch(type) {
    case StoreType::Real:     *reinterpret_cast<double*>(ptr) = double(src); return true;
    case StoreType::Integer:  *reinterpret_cast<int64_t*>(ptr) = int64_t(src); return true;
    case StoreType::UInteger: *reinterpret_cast<uint64_t*>(ptr) = uint64_t(src); return true;
    case StoreType::Bool:     *reinterpret_cast<bool*>(ptr) = bool(src); return true;
    case StoreType::String:   *reinterpret_cast<std::string*>(ptr) = SB()<<src; return true;
    case StoreType::Null:
    case StoreType::Compound:
    case StoreType::Array:
        break;
    }
    return false;
}
}

void Value::copyOut(void *ptr, StoreType type) const
{
    if(!desc)
        throw NoField();

    switch(store->code) {
    case StoreType::Real:     if(copyOutScalar(store->as<double>(), ptr, type)) return; else break;
    case StoreType::Integer:  if(copyOutScalar(store->as<int64_t>(), ptr, type)) return; else break;
    case StoreType::UInteger: if(copyOutScalar(store->as<uint64_t>(), ptr, type)) return; else break;
    case StoreType::Bool: {
        auto& src = store->as<bool>();

        switch(type) {
        case StoreType::Bool:     *reinterpret_cast<bool*>(ptr) = src; return;
        case StoreType::Integer:
        case StoreType::UInteger: *reinterpret_cast<uint64_t*>(ptr) = src; return;
        case StoreType::Real:     *reinterpret_cast<double*>(ptr) = src; return;
        case StoreType::String:   *reinterpret_cast<std::string*>(ptr) = src ? "true" : "false"; return;
        default:
            break;
        }
        break;
    }
    case StoreType::String: {
        auto& src = store->as<std::string>();

        switch(type) {
        case StoreType::String: *reinterpret_cast<std::string*>(ptr) = src; return;
        case StoreType::Integer: {
            *reinterpret_cast<int64_t*>(ptr) = parseTo<int64_t>(src);
            return;
        }
        case StoreType::UInteger: {
            *reinterpret_cast<uint64_t*>(ptr) = parseTo<uint64_t>(src);
            return;
        }
        case StoreType::Real: {
            *reinterpret_cast<double*>(ptr) = parseTo<double>(src);
            return;
        }
        case StoreType::Bool: {
            if(src=="true") { *reinterpret_cast<bool*>(ptr) = true; return; }
            else if(src=="false") { *reinterpret_cast<bool*>(ptr) = false; return; }
        }
        default:
            break;
        }
        break;
    }
    case StoreType::Array: {
        auto& src = store->as<shared_array<const void>>();
        switch (type) {
        case StoreType::Array: *reinterpret_cast<shared_array<const void>*>(ptr) = src; return;
            // TODO: print array
            //       extract [0] as scalar?
        default:
            break;
        }
        break;
    }
    case StoreType::Compound: {
        auto& src = store->as<Value>();
        if(type==StoreType::Compound) {
            // extract Value
            *reinterpret_cast<Value*>(ptr) = src;
            return;

        } else if(src) {
            // automagic deref and delegate assign
            src.copyOut(ptr, type);
            return;

        } else {
            throw NoConvert();
        }

        break;
    }
    case StoreType::Null:
        break;
    }

    throw NoConvert();
}

bool Value::tryCopyOut(void *ptr, StoreType type) const
{
    try {
        copyOut(ptr, type);
        return true;
    }catch(NoField&){
        return false;
    }catch(NoConvert&){
        return false;
    }
}

namespace {

// C-style cast between scalar storage types, and print to string (base 10)
template<typename Dest>
bool copyInScalar(Dest& dest, const void *ptr, StoreType type)
{
    switch(type) {
    case StoreType::Real:     dest = Dest(*reinterpret_cast<const double*>(ptr)); return true;
    case StoreType::Integer:  dest = Dest(*reinterpret_cast<const int64_t*>(ptr)); return true;
    case StoreType::UInteger: dest = Dest(*reinterpret_cast<const uint64_t*>(ptr)); return true;
    case StoreType::Bool:     dest = Dest(*reinterpret_cast<const bool*>(ptr)); return true;
    case StoreType::String:   dest = parseTo<Dest>(*reinterpret_cast<const std::string*>(ptr)); return true;
    case StoreType::Null:
    case StoreType::Compound:
    case StoreType::Array:
        break;
    }
    return false;
}
}

void Value::copyIn(const void *ptr, StoreType type)
{
    // control flow should either throw NoField or NoConvert, or update 'store' and
    // reach the mark() at the end.

    if(!desc)
        throw NoField();

    switch(store->code) {
    case StoreType::Real:     if(!copyInScalar(store->as<double>(), ptr, type)) throw NoConvert(); break;
    case StoreType::Integer:  if(!copyInScalar(store->as<int64_t>(), ptr, type)) throw NoConvert(); break;
    case StoreType::UInteger: if(!copyInScalar(store->as<uint64_t>(), ptr, type)) throw NoConvert(); break;
    case StoreType::Bool: {
        auto& dest = store->as<bool>();
        switch(type) {
        case StoreType::Bool:     dest = *reinterpret_cast<const bool*>(ptr); break;
        case StoreType::Integer:
        case StoreType::UInteger: dest = 0!=*reinterpret_cast<const uint64_t*>(ptr); break;
        //case StoreType::Real:  // TODO pick condition.  strict non-zero?  fabs()<0.5 ?
        case StoreType::String:
            if("true"==*reinterpret_cast<const std::string*>(ptr)) { dest = true; break; }
            else if("false"==*reinterpret_cast<const std::string*>(ptr)) { dest = false; break; }
            // fall through
        default:
            throw NoConvert();
        }
        break;
    }
    case StoreType::String: {
        auto& dest = store->as<std::string>();

        switch(type) {
        case StoreType::String:   dest = *reinterpret_cast<const std::string*>(ptr); break;
        case StoreType::Integer:  dest = SB()<<*reinterpret_cast<const int64_t*>(ptr); break;
        case StoreType::UInteger: dest = SB()<<*reinterpret_cast<const uint64_t*>(ptr); break;
        case StoreType::Real:     dest = SB()<<*reinterpret_cast<const double*>(ptr); break;
        case StoreType::Bool:     dest = (*reinterpret_cast<const bool*>(ptr)) ? "true" : "false"; break;
        default:
            throw NoConvert();
        }
        break;
    }
    case StoreType::Array: {
        auto& dest = store->as<shared_array<const void>>();
        switch (type) {
        case StoreType::Array: {
            auto& src = *reinterpret_cast<const shared_array<const void>*>(ptr);
            if(src.original_type()==ArrayType::Null || src.empty()) {
                // assignment from untyped or empty
                dest.clear();

            } else if(src.original_type()==ArrayType::Value && desc->code.kind()==Kind::Compound) {
                // assign array of Struct/Union/Any
                auto tsrc  = src.castTo<const Value>();

                if(desc->code!=TypeCode::AnyA) {
                    // enforce member type for Struct[] and Union[]
                    for(auto& val : tsrc) {
                        if(val.desc && val.desc!=desc->members.data()) {
                            throw NoConvert();
                        }
                    }
                }
                dest = src;

            } else if(src.original_type()!=ArrayType::Value && uint8_t(desc->code.code)==uint8_t(src.original_type())) {
                // assign array of scalar w/o convert
                dest = src;

            } else {
                // TODO: alloc and convert
                throw NoConvert();
            }
            break;
        }
        default:
            throw NoConvert();
        }
        break;
    }
    case StoreType::Compound:
        if(desc->code==TypeCode::Any) {
            // assigning variant union.
            auto& val = store->as<Value>();
            if(type==StoreType::Compound) {
                val = *reinterpret_cast<const Value*>(ptr);
                break;
            } else {
                val = Value::Helper::build(ptr, type);
                break;
            }
        }
        throw NoConvert();
    case StoreType::Null:
        if(type==StoreType::Compound) {
            auto& src = *reinterpret_cast<const Value*>(ptr);
            if(src.type()==TypeCode::Struct) {
                // copy struct to struct
                // all marked source field may be mapped to destination fields

                for(auto& sfld : src.imarked()) {
                    if(sfld.type()==TypeCode::Struct) {
                        // entire sub-struct marked.

                        if(auto dfld = (*this)[src.nameOf(sfld)]) {
                            dfld.mark();
                        }

                    } else {
                        if(auto dfld = (*this)[src.nameOf(sfld)]) {
                            dfld.copyIn(&sfld.store->store, sfld.store->code);
                        } else {
                            throw NoField();
                        }
                    }
                }
                if(src.isMarked())
                    mark();

                return;
            }
        }
        throw NoConvert();
    }

    mark();
}

bool Value::tryCopyIn(const void *ptr, StoreType type)
{
    try {
        copyIn(ptr, type);
        return true;
    }catch(NoField&){
        return false;
    }catch(NoConvert&){
        return false;
    }
}

void Value::traverse(const std::string &expr, bool modify)
{
    size_t pos=0;
    bool maybedot = false;

    while(desc && pos<expr.size()) {
        if(expr[pos]=='<') {
            // attempt traverse to parent
            if(desc!=store->top->desc.get())
            {
                auto pdesc = desc - desc->parent_index;
                std::shared_ptr<FieldStorage> pstore(store, store.get() - desc->parent_index);
                store = std::move(pstore);
                desc = pdesc;
                pos++;
                continue;
            } else {
                // at top
                store.reset();
                desc = nullptr;
                break;
            }

        }

        if(desc->code.code==TypeCode::Struct) {
            // attempt traverse to member.
            // expect: [0-9a-zA-Z_.]+[\[-$]

            // skip a leading dot
            if(maybedot) {
                if(expr[pos]!='.') {
                    store.reset();
                    desc = nullptr;
                    break;
                }
                maybedot = false;
                pos++;
            }

            size_t sep = expr.find_first_of("<[-", pos);

            decltype (desc->mlookup)::const_iterator it;

            if(sep>0 && (it=desc->mlookup.find(expr.substr(pos, sep-pos)))!=desc->mlookup.end()) {
                // found it
                auto next = desc+it->second;
                decltype(store) value(store, store.get()+it->second);
                store = std::move(value);
                desc = next;
                pos = sep;

            } else {
                // no such member
                store.reset();
                desc = nullptr;
            }

        } else if(desc->code.code==TypeCode::Union || desc->code.code==TypeCode::Any) {
            // attempt to traverse to (and maybe select) member
            // expect: ->[0-9a-zA-Z_]+[.\[-$]

            maybedot = false;

            if(expr.size()-pos >= 3 && expr[pos]=='-' && expr[pos+1]=='>') {
                pos += 2; // skip past "->"

                if(desc->code.code==TypeCode::Any) {
                    // select member of Any (may be Null)
                    *this = store->as<Value>();

                } else {
                    // select member of Union
                    size_t sep = expr.find_first_of("<[-.", pos);

                    decltype (desc->mlookup)::const_iterator it;

                    if(sep>0 && (it=desc->mlookup.find(expr.substr(pos, sep-pos)))!=desc->mlookup.end()) {
                        // found it.
                        auto& fld = store->as<Value>();

                        if(modify || fld.desc==&desc->members[it->second]) {
                            // will select, or already selected
                            if(fld.desc!=&desc->members[it->second]) {
                                // select
                                std::shared_ptr<const FieldDesc> mtype(store->top->desc, &desc->members[it->second]);
                                fld = Value(mtype, *this);
                            }
                            pos = sep;
                            *this = fld;
                            maybedot = true;

                        } else {
                            // traversing const Value, can't select Union
                            store.reset();
                            desc = nullptr;
                        }
                    }
                }
            } else {
                // expected "->"
                store.reset();
                desc = nullptr;
            }

        } else if(desc->code.isarray() && desc->code.kind()==Kind::Compound) {
            // attempt to traverse into array of Struct, Union, or Any
            // expect: \[[0-9]+\]

            maybedot = false;

            size_t sep = expr.find_first_of(']', pos);

            if(expr[pos]=='['
                    && sep!=std::string::npos && sep-pos>=2)
            {
                auto index = parseTo<uint64_t>(expr.substr(pos+1, sep-1-pos));
                auto& varr = store->as<shared_array<const void>>();
                shared_array<const Value> arr;
                if((varr.original_type()==ArrayType::Value)
                        && index < (arr = varr.castTo<const Value>()).size())
                {
                    *this = arr[index];
                    pos = sep+1;
                    maybedot = true;

                } else {
                    // wrong element type or out of range
                    store.reset();
                    desc = nullptr;
                }

            } else {
                // syntax error
                store.reset();
                desc = nullptr;
            }

        } else {
            // syntax error or wrong field type (can't index scalar array)
            store.reset();
            desc = nullptr;
        }
    }
}

Value Value::operator[](const char *name)
{
    Value ret(*this);
    ret.traverse(name, true);
    return ret;
}

const Value Value::operator[](const char *name) const
{
    Value ret(*this);
    ret.traverse(name, false);
    return ret;
}

void Value::_iter_fl(Value::IterInfo &info, bool first) const
{
    if(!store)
        throw NoField();

    if(desc->code!=TypeCode::Struct) {
        // TODO implement iteration of Union, or Struct[]/Union[]
        info.pos = info.nextcheck = 0;

    } else if(info.depth) {
        info.pos = info.nextcheck = first ? 1u : desc->size();

        if(info.marked)
            _iter_advance(info);

    } else {
        info.pos = info.nextcheck = first ? 0u : desc->miter.size();
    }
}

void Value::_iter_advance(IterInfo& info) const
{
    assert(info.depth);

    // scan forward to find next non-marked
    for(auto idx : range(info.pos, desc->size())) {
        auto S = store.get() + idx;
        if(S->valid) {
            auto D = desc + idx;
            info.pos = idx;
            info.nextcheck = idx + D->size();
            return;
        }
    }

    info.pos = info.nextcheck = desc->size();
}

Value Value::_iter_deref(const IterInfo& info) const
{
    auto idx = info.pos;
    if(!info.depth)
        idx = desc->miter[idx].second;

    decltype (store) store2(store, store.get()+idx);
    Value ret;
    ret.store = std::move(store2);
    ret.desc = desc + idx;
    return ret;
}

namespace impl {

void FieldStorage::init(StoreType code)
{
    this->code = code;
    switch(code) {
    case StoreType::Null:
        return;
    case StoreType::Bool:
        as<bool>() = false;
        return;
    case StoreType::Integer:
    case StoreType::UInteger:
    case StoreType::Real:
        // just zero 8 bytes
        as<uint64_t>() = 0u;
        return;
    case StoreType::String:
        new(&store) std::string();
        return;
    case StoreType::Compound:
        new(&store) std::shared_ptr<FieldStorage>();
        return;
    case StoreType::Array:
        new(&store) shared_array<void>();
        return;
    }
    throw std::logic_error("FieldStore::init()");
}

void FieldStorage::deinit()
{
    switch(code) {
    case StoreType::Null:
    case StoreType::Integer:
    case StoreType::UInteger:
    case StoreType::Real:
    case StoreType::Bool:
             break;
    case StoreType::Array:
        as<shared_array<void>>().~shared_array();
        break;
    case StoreType::String:
        as<std::string>().~basic_string();
        break;
    case StoreType::Compound:
        as<Value>().~Value();
        break;
    default:
        throw std::logic_error("FieldStore::deinit()");
    }
    code = StoreType::Null;
}

FieldStorage::~FieldStorage()
{
    deinit();
}

size_t FieldStorage::index() const
{
    const size_t ret = this-top->members.data();
    return ret;
}

}} // namespace pvxs::impl
