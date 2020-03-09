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
#include <vector>
#include <functional>
#include <type_traits>

#include <pvxs/version.h>
#include <pvxs/util.h>

namespace pvxs {

/** A single test case (or diagnostic line).
 *
 * Acts as an output string to accumulate test comment.
 * Multi-line output results in one test line, and subsequent diagnostic lines.
 *
 * Test line is printed when an active (non-moved) testCase is destroyed.
 */
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

    //! true when passing
    explicit operator bool() const { return result==Pass; }

    //! Override current pass/fail result
    testCase& setPass(bool v) {
        result = v ? Pass : Fail;
        return *this;
    }

    //! Append to message
    template<typename T>
    inline testCase& operator<<(const T& v) {
        msg<<v;
        return *this;
    }
};

namespace detail {

// control how testEq() and testNotEq() print things
template<typename T, typename Enable=void>
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
template<typename E>
struct test_print<std::vector<E>, typename std::enable_if<sizeof(E)==1>::type> {
    template<class C>
    static inline void op(C& strm, const std::vector<E>& v) {
        strm<<'"'<<escape((const char*)v.data(), v.size())<<'"';
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
    return ret;
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
    return ret;
}

} // namespace detail

/** Assert that an exception is thrown.
 *
 * @tparam Exception The exception type which should be thrown
 * @param fn A callable
 *
 * @returns A testCase which passes if an Exception instance was caught,
 *          and false otherwise (wrong type, or no exception).
 *
 * @code
 * testThrows<std::runtime_error>([]() {
 *      testShow()<<"Now you see me";
 *      throw std::runtime_error("I happened");
 *      testShow()<<"Now you don't";
 * })<<"some message";
 * @endcode
 */
template<class Exception, typename FN>
testCase testThrows(FN fn)
{
    testCase ret(false);
    try {
        fn();
        ret<<"Unexpected success - ";
    }catch(Exception& e){
        ret.setPass(true)<<"Expected exception \""<<e.what()<<"\" - ";
    }catch(std::exception& e){
        ret<<"Unexpected exception "<<typeid(e).name()<<" \""<<e.what()<<"\" - ";
    }
    return ret;
}

} // namespace pvxs

//! Macro which assert that an expression evaluate to 'true'.
//! Evaluates to a pvxs::testCase
#define testTrue(EXPR) ::pvxs::testCase(EXPR)<<(" " #EXPR)

//! Macro which assert that an expression evaluate to 'true'.
//! Evaluates to a pvxs::testCase
#define testFalse(EXPR) ::pvxs::testCase(!(EXPR))<<(" !" #EXPR)

//! Macro which asserts equality between LHS and RHS.
//! Evaluates to a pvxs::testCase
//! Roughly equivalent to @code testOk((LHS)==(RHS), "..."); @endcode
#define testEq(LHS, RHS) ::pvxs::detail::testEq(#LHS, LHS, #RHS, RHS)

//! Macro which asserts in-equality between LHS and RHS.
//! Evaluates to a pvxs::testCase
//! Roughly equivalent to @code testOk((LHS)!=(RHS), "..."); @endcode
#define testNotEq(LHS, RHS) ::pvxs::detail::testNotEq(#LHS, LHS, #RHS, RHS)

//! Macro which prints diagnostic (non-test) lines.
//! Evaluates to a pvxs::testCase
//! Roughly equivalent to @code testDiag("..."); @endcode
#define testShow() ::pvxs::testCase()

#endif // PVXS_UNITTEST_H
