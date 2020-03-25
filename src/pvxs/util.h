/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_UTIL_H
#define PVXS_UTIL_H

#include <map>
#include <functional>
#include <ostream>
#include <type_traits>

#include <osiSock.h>
#include <event2/util.h>

#ifdef _WIN32
#  include <ws2ipdef.h>
#endif

#include <pvxs/version.h>

namespace pvxs {

namespace detail {
// ref. wrapper to mark string for escaping
class Escaper
{
    const char* val;
    size_t count;
    friend std::ostream& operator<<(std::ostream& strm, const Escaper& esc);
public:
    PVXS_API explicit Escaper(const char* v);
    constexpr explicit Escaper(const char* v, size_t l) :val(v),count(l) {}
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Escaper& esc);

} // namespace detail

//! Print string to output stream with non-printable charactors escaped.
//!
//! Outputs (almost) C-style escapes.
//! Prefers short escapes for newline, tab, quote, etc ("\\n").
//! Falls back to hex escape (eg. "\xab").
//!
//! Unlike C, hex escapes are always 2 chars.  eg. the output "\xabcase"
//! would need to be manually changed to "\xab""case" to be used as C source.
//!
//! @code
//!   std::string blah("this \"is a test\"");
//!   std::cout<<pvxs::escape(blah);
//! @endcode
inline detail::Escaper escape(const std::string& s) {
    return detail::Escaper(s.c_str(), s.size());
}
//! Print nil terminated char array to output stream with non-printable charactors escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"");
//! @endcode
inline detail::Escaper escape(const char* s) {
    return detail::Escaper(s);
}
//! Print fixed length char array to output stream with non-printable charactors escaped.
//! @code
//!   std::cout<<pvxs::escape("this \"is a test\"", 6);
//!   // prints 'this \"'
//! @endcode
inline detail::Escaper escape(const char* s,size_t n) {
    return detail::Escaper(s,n);
}

#if !defined(__rtems__) && !defined(vxWorks)

/** minimal portable process signal handling in CLI tools.
 *
 * @code
 *     epicsEvent evt;
 *     SigInt handle([&evt]() {
 *          evt.trigger();
 *     });
 *     ... setup network operations
 *     evt.wait();
 *     // completion, or SIGINT
 * @endcode
 */
class PVXS_API SigInt {
    void (*prevINT)(int);
    void (*prevTERM)(int);
    std::function<void()> handler;
    static void _handle(int);
public:
    SigInt(decltype (handler)&& handler);
    ~SigInt();
};

#else // !defined(__rtems__) && !defined(vxWorks)

class SigInt {
public:
    SigInt(std::function<void()>&& handler) {}
}

#endif // !defined(__rtems__) && !defined(vxWorks)

//! return a snapshot of internal instance counters
PVXS_API
std::map<std::string, size_t> instanceSnapshot();

} // namespace pvxs

#endif // PVXS_UTIL_H
