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

    explicit operator bool() const { return result==Pass; }

    testCase& setPass(bool v) {
        result = v ? Pass : Fail;
        return *this;
    }

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

#define testEq(LHS, RHS) ::pvxs::detail::testEq(#LHS, LHS, #RHS, RHS)
#define testNotEq(LHS, RHS) ::pvxs::detail::testNotEq(#LHS, LHS, #RHS, RHS)
#define testShow() ::pvxs::testCase()

#endif // PVXS_UNITTEST_H
