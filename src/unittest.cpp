/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsUnitTest.h>

#include "pvxs/unittest.h"
#include "utilpvt.h"

namespace pvxs {

testCase::testCase()
    :result(Diag)
{}

testCase::testCase(bool result)
    :result(result ? Pass : Fail)
{}

testCase::testCase(testCase&& o) noexcept
    :result(o.result)
#if !GCC_VERSION || GCC_VERSION>=VERSION_INT(4,10,0,0)
    ,msg(std::move(o.msg))
#else
    // gcc 4.8 (at least) doesn't provide a move ctor yet
    ,msg(o.msg.str())
#endif
{
    o.result = Nothing;
}

testCase& testCase::operator=(testCase&& o) noexcept
{
    if(this!=&o) {
        result = o.result;
        o.result = Nothing;
#if !GCC_VERSION || GCC_VERSION>=VERSION_INT(4,10,0,0)
        msg = std::move(o.msg);
#else
        msg.seekp(0);
        msg.str(o.msg.str());
#endif
    }
    return *this;
}

testCase::~testCase()
{
    if(result==Nothing)
        return;

    std::istringstream strm(msg.str());

    for(std::string line; std::getline(strm, line);) {
        if(result==Diag) {
            testDiag("%s", line.c_str());

        } else {
            testOk(result==Pass, "%s", line.c_str());
            result=Diag;
        }
    }
}

namespace detail {

size_t findNextLine(const std::string& s, size_t pos=0u)
{
    size_t next = s.find_first_of('\n', pos);
    if(next!=std::string::npos)
        next++;
    return next;
}

testCase _testStrEq(const char *sLHS, const std::string& lhs, const char *sRHS, const std::string& rhs)
{
    testCase ret(lhs==rhs);
    ret<<sLHS<<" == "<<sRHS<<"\n";

    size_t posL=0u, posR=0u;

    while(posL<lhs.size() && posR<rhs.size()) {
        size_t eolL = findNextLine(lhs, posL);
        size_t eolR = findNextLine(rhs, posR);

        auto L = lhs.substr(posL, eolL-posL);
        auto R = rhs.substr(posR, eolR-posR);

        if(L==R) {
            ret<<"  \""<<escape(L)<<"\"\n";
        } else {
            ret<<"+ \""<<escape(R)<<"\"\n";
            ret<<"- \""<<escape(L)<<"\"\n";
        }

        posL = eolL;
        posR = eolR;
    }

    while(posR<rhs.size()) {
        size_t eol = findNextLine(rhs, posR);
        auto line = rhs.substr(posR, eol-posR);
        ret<<"+ \""<<escape(line)<<"\"\n";

        posR = eol;
    }

    while(posL<lhs.size()) {
        size_t eol = findNextLine(lhs, posL);
        auto line = lhs.substr(posL, eol-posL);
        ret<<"- \""<<escape(line)<<"\"\n";

        posL = eol;
    }

    return ret;
}

} // namespace detail
} // namespace pvxs
