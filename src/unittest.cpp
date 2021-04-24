/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <regex>

#include <epicsUnitTest.h>

#include "pvxs/unittest.h"
#include "utilpvt.h"
#include "udp_collector.h"

namespace pvxs {

void testSetup()
{
#ifdef _WIN32
    // One of the SEM_* options, either SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX,
    // depending on who you ask, acts to disable Windows Error Reporting entirely.
    // This also prevents the AeDebug facility from triggering.
    UINT prev = SetErrorMode(0);
    if(prev)
        testDiag("SetErrorMode() disables 0x%x\n", (unsigned)prev);
#endif
}

void cleanup_for_valgrind()
{
    for(auto& pair : instanceSnapshot()) {
        // This will mess up test counts, but is the only way
        // 'prove' will print the result in CI runs.
        if(pair.second!=0)
            testFail("Instance leak %s : %zu", pair.first.c_str(), pair.second);
    }
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
    libevent_global_shutdown();
#endif
    impl::logger_shutdown();
    impl::UDPManager::cleanup();
}

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

testCase& testCase::setPassMatch(const std::string& expr, const std::string& inp)
{
    std::regex ex;
    try {
        ex.assign(expr);
        setPass(std::regex_match(inp, ex));

    }catch(std::regex_error& e) {
        setPass(false);
        (*this)<<" expression error: "<<e.what()<<" :";
    }
    return *this;
}

namespace detail {

size_t findNextLine(const std::string& s, size_t pos=0u)
{
    size_t next = s.find_first_of('\n', pos);
    if(next!=std::string::npos)
        next++;
    return next;
}

testCase _testStrTest(unsigned op, const char *sLHS, const char* rlhs, const char *sRHS, const char* rrhs)
{
    bool eq;
    if(rlhs==rrhs) // same string.  handles NULL==NULL
        eq = true;
    else if(!rlhs ^ !rrhs) // one NULL
        eq = false;
    else
        eq = strcmp(rlhs, rrhs)==0;
    testCase ret(eq==op);
    ret<<sLHS<<(op ? " == " : " != ")<<sRHS<<"\n";

    std::string lhs(rlhs ? rlhs : "<null>");
    std::string rhs(rrhs ? rrhs : "<null>");

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

testCase _testStrMatch(const char *spat, const std::string& pat, const char *sstr, const std::string& str)
{
    std::regex expr;
    testCase ret;
    ret.setPassMatch(pat, str);
    ret<<spat<<" (\""<<pat<<"\") match "<<str<<" (\""<<escape(str)<<"\")";
    return ret;
}

} // namespace detail
} // namespace pvxs
