/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_UNITTEST_H
#define PVXS_UNITTEST_H

/** @file pvxs/unittest.h
 *
 * C++ helpers for use with epicsUnitTest.h
 */

#include <sstream>

#include <pvxs/version.h>
#include <pvxs/util.h>

namespace pvxs {

class PVXS_API testCase
{
    enum {
        Nothing, // after move()'d
        Diag,    // no test, just print
        Pass,
        Fail,
    } result;
    std::ostringstream msg;
public:
    //! new diag message
    testCase();
    //! new test case
    explicit testCase(bool result);
    testCase(const testCase&) = delete;
    testCase& operator=(const testCase&) = delete;
    testCase(testCase&&) noexcept;
    testCase& operator=(testCase&&) noexcept;
    ~testCase();

    template<typename T>
    inline testCase& operator<<(const T& v) {
        msg<<v;
        return *this;
    }
};

namespace detail {

// control how testEq() and testNotEq() print things
template<typename T>
struct test_print {
    template<class C>
    static inline void op(C& strm, const T& v) {
        strm<<v;
    }
};
template <>
struct test_print<std::string> {
    template<class C>
    static inline void op(C& strm, const std::string& v) {
        strm<<'"'<<escape(v)<<'"';
    }
};
template <>
struct test_print<const char*> {
    template<class C>
    static inline void op(C& strm, const char* v) {
        strm<<'"'<<escape(v)<<'"';
    }
};

template<typename LHS, typename RHS>
testCase testEq(const char *sLHS, const LHS& lhs, const char *sRHS, const RHS& rhs)
{
    testCase ret(lhs==rhs);
    ret<<sLHS<<" (";
    test_print<LHS>::op(ret, lhs);
    ret<<") == "<<sRHS<<" (";
    test_print<RHS>::op(ret, rhs);
    ret<<") ";
    return std::move(ret);
}

template<typename LHS, typename RHS>
testCase testNotEq(const char *sLHS, const LHS& lhs, const char *sRHS, const RHS& rhs)
{
    testCase ret(lhs!=rhs);
    ret<<sLHS<<" (";
    test_print<LHS>::op(ret, lhs);
    ret<<") != "<<sRHS<<" (";
    test_print<RHS>::op(ret, rhs);
    ret<<") ";
    return std::move(ret);
}

} // namespace detail

} // namespace pvxs

#define testEq(LHS, RHS) ::pvxs::detail::testEq(#LHS, LHS, #RHS, RHS)
#define testNotEq(LHS, RHS) ::pvxs::detail::testNotEq(#LHS, LHS, #RHS, RHS)

#endif // PVXS_UNITTEST_H
