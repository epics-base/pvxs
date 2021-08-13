/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <string>

#include <string.h>

#include <epicsTypes.h>

#include <pvxs/sharedArray.h>
#include <pvxs/data.h>
#include "utilpvt.h"

namespace pvxs {

std::ostream& operator<<(std::ostream& strm, ArrayType code)
{
    switch(code) {
#define CASE(CODE) case ArrayType::CODE : strm<<#CODE; break
    CASE(Null);
    CASE(Bool);
    CASE(UInt8);
    CASE(UInt16);
    CASE(UInt32);
    CASE(UInt64);
    CASE(Int8);
    CASE(Int16);
    CASE(Int32);
    CASE(Int64);
    CASE(Float32);
    CASE(Float64);
    CASE(Value);
#undef CASE
    default:
        strm<<"<\?\?\?>";
    }
    return strm;
}

size_t elementSize(ArrayType type)
{
    switch(type) {
#define CASE(CODE, Type) case ArrayType::CODE: return sizeof(Type)
    CASE(Bool, bool);
    CASE(UInt8, uint8_t);
    CASE(UInt16, uint16_t);
    CASE(UInt32, uint32_t);
    CASE(UInt64, uint64_t);
    CASE(Int8, int8_t);
    CASE(Int16, int16_t);
    CASE(Int32, int32_t);
    CASE(Int64, int64_t);
    CASE(Float32, float);
    CASE(Float64, double);
    CASE(String, std::string);
    CASE(Value, Value);
#undef CASE
    case ArrayType::Null:
        break;
    }
    throw std::logic_error("Invalid ArrayType");
}

shared_array<void> allocArray(ArrayType type, size_t count)
{
    switch(type) {
#define CASE(CODE, TYPE) case ArrayType::CODE: return shared_array<TYPE>(count).castTo<void>()
    CASE(Bool, bool);
    CASE(UInt8, uint8_t);
    CASE(UInt16, uint16_t);
    CASE(UInt32, uint32_t);
    CASE(UInt64, uint64_t);
    CASE(Int8, int8_t);
    CASE(Int16, int16_t);
    CASE(Int32, int32_t);
    CASE(Int64, int64_t);
    CASE(Float32, float);
    CASE(Float64, double);
    CASE(String, std::string);
    CASE(Value, Value);
#undef CASE
    case ArrayType::Null:
        break;
    }

    throw std::logic_error("Invalid ArrayType");
}

namespace detail {

namespace {

template<typename E>
struct Print { static inline void as(std::ostream& strm,const E& val) { strm<<val; } };
template<>
struct Print<int8_t> { static inline void as(std::ostream& strm,int8_t val) { strm<<int(val); } };
template<>
struct Print<uint8_t> { static inline void as(std::ostream& strm,uint8_t val) { strm<<unsigned(val); } };
template<>
struct Print<std::string> { static inline void as(std::ostream& strm,const std::string& val) { strm<<"\""<<escape(val)<<"\"";} };

template<typename E>
void showArr(std::ostream& strm, const void* raw, size_t count, size_t limit)
{
    auto base = reinterpret_cast<const E*>(raw);

    if(limit==0)
        limit=size_t(-1);

    strm<<"{"<<count<<"}[";
    for(auto i : range(count)) {
        if(i!=0)
            strm<<", ";
        if(i>limit) {
            strm<<"...";
            break;
        }
        Print<E>::as(strm, base[i]);
    }
    strm<<']';
}
} // namespace

std::ostream& operator<<(std::ostream& strm, const Limiter& lim)
{
    switch(lim._type) {
#define CASE(CODE, Type) case ArrayType::CODE: showArr<Type>(strm, lim._base, lim._count, lim._limit); break
    CASE(Bool, bool);
    CASE(UInt8, uint8_t);
    CASE(UInt16, uint16_t);
    CASE(UInt32, uint32_t);
    CASE(UInt64, uint64_t);
    CASE(Int8, int8_t);
    CASE(Int16, int16_t);
    CASE(Int32, int32_t);
    CASE(Int64, int64_t);
    CASE(Float32, float);
    CASE(Float64, double);
    CASE(String, std::string);
#undef CASE
    case ArrayType::Null:
        strm<<"{\?}[]";
        break;
    default:
        strm<<"[\?\?\?]";
    }
    return strm;
}

void _throw_bad_cast(ArrayType from, ArrayType to)
{
    throw std::logic_error(SB()<<"Unable to cast array from "<<from<<" to "<<to);
}

namespace {

template<typename Src, typename Dest>
void convertCast(const void *sbase, void *dbase, size_t count)
{
    auto S = static_cast<const Src*>(sbase);
    auto D = static_cast<Dest*>(dbase);
    for(auto i : range(count))
        D[i] = Dest(S[i]);
}

void printValue(std::string& dest, const bool& src)
{
    dest = src ? "true" : "false";
}

template<typename Src>
typename std::enable_if<!std::is_same<Src, bool>::value>::type
printValue(std::string& dest, const Src& src)
{
    std::ostringstream strm;
    strm<<src;
    // no error check, we only print POD scalar types which are unambiguous
    dest = strm.str();
}

template<typename Src>
void convertToStr(const void *sbase, void *dbase, size_t count)
{
    auto S = static_cast<const Src*>(sbase);
    auto D = static_cast<std::string*>(dbase);
    for(auto i : range(count))
        printValue(D[i], S[i]);
}

void parseValue(bool& dest, const std::string& src)
{
    if(src=="true")
        dest = true;
    else if(src=="false")
        dest = false;
    else
        throw std::runtime_error(SB()<<"Expected \"true\" or \"false\", not \""<<escape(src)<<"\"");
}

template<typename Dest>
typename std::enable_if<std::is_integral<Dest>::value && std::is_signed<Dest>::value>::type
parseValue(Dest& dest, const std::string& src)
{
    dest = Dest(parseTo<int64_t>(src));
}

template<typename Dest>
typename std::enable_if<std::is_integral<Dest>::value && !std::is_signed<Dest>::value && !std::is_same<Dest, bool>::value>::type
parseValue(Dest& dest, const std::string& src)
{
    dest = Dest(parseTo<uint64_t>(src));
}

template<typename Dest>
typename std::enable_if<std::is_floating_point<Dest>::value>::type
parseValue(Dest& dest, const std::string& src)
{
    dest = Dest(parseTo<double>(src));
}

template<typename Dest>
void convertFromStr(const void *sbase, void *dbase, size_t count)
{
    auto S = static_cast<const std::string*>(sbase);
    auto D = static_cast<Dest*>(dbase);
    for(auto i : range(count))
        parseValue(D[i], S[i]);
}

} // namespace

void convertArr(ArrayType dtype,       void *dbase,
                ArrayType stype, const void *sbase,
                size_t count)
{
    if(count==0u)
        return; // ignore type when no elements.  (conflating empty array with Null array)

    switch (stype) {
    case ArrayType::Bool:
        switch(dtype) {
        case ArrayType::Bool:   memcpy(dbase, sbase, count*sizeof(bool)); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<bool, uint8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<bool, uint16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<bool, uint32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<bool, uint64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<bool, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<bool, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<bool>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Int8:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<int8_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  memcpy(dbase, sbase, count*sizeof(int8_t)); return;
            // cast sint -> *int always sign extends
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<int8_t, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<int8_t, int32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<int8_t, int64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<int8_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<int8_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<int8_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Int16:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<int16_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<int16_t, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: memcpy(dbase, sbase, count*sizeof(int16_t)); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<int16_t, int32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<int16_t, int64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<int16_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<int16_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<int16_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Int32:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<int32_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<int32_t, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<int32_t, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: memcpy(dbase, sbase, count*sizeof(int32_t)); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<int32_t, int64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<int32_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<int32_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<int32_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Int64:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<int64_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<int64_t, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<int64_t, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<int64_t, int32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: memcpy(dbase, sbase, count*sizeof(int64_t)); return;
        case ArrayType::Float32:convertCast<int64_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<int64_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<int64_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::UInt8:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<uint8_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  memcpy(dbase, sbase, count*sizeof(uint8_t)); return;
            //case uint -> *int never sign extends
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<uint8_t, uint16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<uint8_t, uint32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<uint8_t, uint64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<uint8_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<uint8_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<uint8_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::UInt16:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<uint16_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<uint16_t, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: memcpy(dbase, sbase, count*sizeof(uint16_t)); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<uint16_t, uint32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<uint16_t, uint64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<uint16_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<uint16_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<uint16_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::UInt32:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<uint32_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<uint32_t, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<uint32_t, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: memcpy(dbase, sbase, count*sizeof(uint32_t)); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<uint32_t, int64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertCast<uint32_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<uint32_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<uint32_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::UInt64:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<uint64_t, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<uint64_t, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<uint64_t, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<uint64_t, int32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: memcpy(dbase, sbase, count*sizeof(uint64_t)); return;
        case ArrayType::Float32:convertCast<uint64_t, float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertCast<uint64_t, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<uint64_t>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Float32:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<float, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<float, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<float, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<float, int32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<float, int64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:memcpy(dbase, sbase, count*sizeof(float)); return;
        case ArrayType::Float64:convertCast<float, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<float>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Float64:
        switch(dtype) {
        case ArrayType::Bool:   convertCast<double, bool>(sbase, dbase, count); return;
        case ArrayType::Int8:
        case ArrayType::UInt8:  convertCast<double, int8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:
        case ArrayType::UInt16: convertCast<double, int16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:
        case ArrayType::UInt32: convertCast<double, int32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:
        case ArrayType::UInt64: convertCast<double, int64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:memcpy(dbase, sbase, count*sizeof(double)); return;
        case ArrayType::Float64:convertCast<double, double>(sbase, dbase, count); return;
        case ArrayType::String: convertToStr<double>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::String:
        switch(dtype) {
        case ArrayType::Bool:   convertFromStr<bool>(sbase, dbase, count); return;
        case ArrayType::Int8:   convertFromStr<int8_t>(sbase, dbase, count); return;
        case ArrayType::UInt8:  convertFromStr<uint8_t>(sbase, dbase, count); return;
        case ArrayType::Int16:  convertFromStr<int16_t>(sbase, dbase, count); return;
        case ArrayType::UInt16: convertFromStr<uint16_t>(sbase, dbase, count); return;
        case ArrayType::Int32:  convertFromStr<int32_t>(sbase, dbase, count); return;
        case ArrayType::UInt32: convertFromStr<uint32_t>(sbase, dbase, count); return;
        case ArrayType::Int64:  convertFromStr<int64_t>(sbase, dbase, count); return;
        case ArrayType::UInt64: convertFromStr<uint64_t>(sbase, dbase, count); return;
        case ArrayType::Float32:convertFromStr<float>(sbase, dbase, count); return;
        case ArrayType::Float64:convertFromStr<double>(sbase, dbase, count); return;
            break;
        case ArrayType::String: convertCast<std::string, std::string>(sbase, dbase, count); return;
        case ArrayType::Value:
        case ArrayType::Null: break; // no convert
        }
        break;
    case ArrayType::Value:
    case ArrayType::Null:
        break;
    }
    throw NoConvert(SB()<<"No array conversion from "<<stype<<" to "<<dtype);
}

shared_array<void> copyAs(ArrayType dtype, ArrayType stype, const void *sbase, size_t count)
{
    shared_array<void> ret;
    switch(dtype) {
#define CASE(CODE, Type) case ArrayType::CODE: ret = shared_array<Type>(count).castTo<void>(); break
    CASE(Bool, bool);
    CASE(UInt8, uint8_t);
    CASE(UInt16, uint16_t);
    CASE(UInt32, uint32_t);
    CASE(UInt64, uint64_t);
    CASE(Int8, int8_t);
    CASE(Int16, int16_t);
    CASE(Int32, int32_t);
    CASE(Int64, int64_t);
    CASE(Float32, float);
    CASE(Float64, double);
    CASE(String, std::string);
    CASE(Value, Value);
#undef CASE
    case ArrayType::Null:
        break;
    }
    if(stype!=ArrayType::Null)
        convertArr(dtype, ret.data(), stype, sbase, count);
    return ret;
}

} // namespace detail

} // namespace pvxs
