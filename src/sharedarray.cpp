/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */


#include <pvxs/sharedArray.h>
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

namespace detail {

namespace {
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
        strm<<base[i];
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

} // namespace detail

} // namespace pvxs
