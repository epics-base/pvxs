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

/** Prepare for testing.  Call after testPlan()
 */
PVXS_API
void testSetup();

/** Free some internal global allocations to avoid false positives in
 *  valgrind (or similar) tools looking for memory leaks.
 *
 *  Calls libevent_global_shutdown() when available (libevent >=2.1).
 *
 * @warning This function is optional.
 *          If you don't understand the intended use case, then do not call it!
 *
 * @pre Caller must release all resources explicitly allocated through PVXS (on all threads).
 * @post Invalidates internal state.
 *       Use of __any__ API functions afterwards is undefined!
 */
PVXS_API
void cleanup_for_valgrind();

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

    //! Override current pass/fail result if input matches a regular expression
    //! @since 0.2.1 Expression syntax is POSIX extended.
    //! @since 0.1.1 Added
    testCase& setPassMatch(const std::string& expr, const std::string& inp);

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

template<typename T>
struct as_str {
    static const char* op(const T& v) { return v; }
};
template<> struct as_str<std::string> {
    static const char* op(const std::string& v) { return v.c_str(); }
};
template<> struct as_str<const std::string> {
    static const char* op(const std::string& v) { return v.c_str(); }
};

template<typename T>
const char* asStr(const T& v) { return as_str<T>::op(v); }

PVXS_API
testCase _testStrTest(unsigned op, const char *sLHS, const char* lhs, const char *sRHS, const char* rhs);

PVXS_API
testCase _testStrMatch(const char *spat, const std::string& pat, const char *sstr, const std::string& str);

template<typename LHS, typename RHS>
testCase testArrEq(const char *sLHS, const LHS& lhs, const char *sRHS, const RHS& rhs)
{
    bool eq = lhs.size()==rhs.size();
    testCase ret;
    ret<<sLHS<<" (";
    test_print<LHS>::op(ret, lhs);
    ret<<") == "<<sRHS<<" (";
    test_print<RHS>::op(ret, rhs);
    ret<<")\n";
    for(size_t i=0; i<lhs.size() && i<rhs.size(); i++) {
        if(lhs[i]!=rhs[i]) {
            eq = false;
            ret<<" ["<<i<<"] -> "<<lhs[i]<<" != "<<rhs[i]<<"\n";
        }
    }
    ret.setPass(eq);
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

/** Assert that an exception is throw with a certain message.
 *
 * @tparam Exception The exception type which should be thrown
 * @param expr A regular expression
 * @param fn A callable
 *
 * @returns A testCase which passes if an Exception instance was caught
 *          and std::exception::what() matched the provided regular expression.
 *
 * @code
 * testThrowsMatch<std::runtime_error>("happened", []() {
 *      testShow()<<"Now you see me";
 *      throw std::runtime_error("I happened");
 *      testShow()<<"Now you don't";
 * })<<"some message";
 * @endcode
 *
 * @since 0.1.1
 */
template<class Exception, typename FN>
testCase testThrowsMatch(const std::string& expr, FN fn)
{
    testCase ret(false);
    try {
        fn();
        ret<<"Unexpected success - ";
    }catch(Exception& e){
        ret.setPassMatch(expr, e.what())<<"Expected matching (\""<<expr<<"\") exception \""<<e.what()<<"\" - ";
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

//! Macro which asserts equality between LHS and RHS.
//! Evaluates to a pvxs::testCase
//! Functionally equivalent to testEq() with two std::string instances.
//! Prints diff-like output which is friendlier to multi-line strings.
#define testStrEq(LHS, RHS) ::pvxs::detail::_testStrTest(1, #LHS, ::pvxs::detail::asStr(LHS), #RHS, ::pvxs::detail::asStr(RHS))

//! Macro which asserts inequality between LHS and RHS.
//! Evaluates to a pvxs::testCase
//! Functionally equivalent to testNotEq() with two std::string instances.
//! Prints diff-like output which is friendlier to multi-line strings.
//! @since 0.2.0
#define testStrNotEq(LHS, RHS) ::pvxs::detail::_testStrTest(0, #LHS, ::pvxs::detail::asStr(LHS), #RHS, ::pvxs::detail::asStr(RHS))

//! Macro which asserts that STR matches the regular expression EXPR
//! Evaluates to a pvxs::testCase
//! @since 0.2.1 Expression syntax is POSIX extended.
//! @since 0.1.1
#define testStrMatch(EXPR, STR) ::pvxs::detail::_testStrMatch(#EXPR, EXPR, #STR, STR)

//! Macro which asserts equality between LHS and RHS.
//! Evaluates to a pvxs::testCase
//! Functionally equivalent to testEq() for objects with .size() and operator[].
//! Prints element by element differences
#define testArrEq(LHS, RHS) ::pvxs::detail::testArrEq(#LHS, LHS, #RHS, RHS)

//! Macro which prints diagnostic (non-test) lines.
//! Evaluates to a pvxs::testCase
//! Roughly equivalent to @code testDiag("..."); @endcode
#define testShow() ::pvxs::testCase()

#endif // PVXS_UNITTEST_H
