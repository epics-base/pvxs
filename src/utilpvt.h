/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef UTILPVT_H
#define UTILPVT_H

#include <string>
#include <sstream>

#include <pvxs/version.h>
#include <pvxs/util.h>

namespace pvxsimpl {
using namespace  pvxs;

//! in-line string builder (eg. for exception messages)
//! eg. @code throw std::runtime_error(SB()<<"Some message"<<42); @endcode
struct SB {
    std::ostringstream strm;
    SB() {}
    operator std::string() const { return strm.str(); }
    template<typename T>
    SB& operator<<(T i) { strm<<i; return *this; }
};

namespace detail {
// specific specializations in util.cpp
template <typename T>
struct as_str {PVXS_API static T op(const char *s);};
} // namespace detail

template <typename T>
inline T lexical_cast(const char *s)
{
    return detail::as_str<T>::op(s);
}

template <typename T>
inline T lexical_cast(const std::string& s)
{
    return detail::as_str<T>::op(s.c_str());
}

} // namespace pvxsimpl

#endif // UTILPVT_H
