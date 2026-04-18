/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>

#include "pvxs/version.h"

#if !defined(GCC_VERSION) || GCC_VERSION>VERSION_INT(4,9,0,0)
#  include <regex>

#else
// GCC 4.8 provides the regex header and symbols, but with a no-op implementation
// so fill in the gap with POSIX regex
#  include <sys/types.h>
#  include <regex.h>
#  define USE_POSIX_REGEX
#endif

#include <epicsUnitTest.h>
#include <epicsString.h>
#define epicsStdioStdStreams
#define epicsStdioStdPrintfEtc
#include <epicsStdio.h>

#include "pvxs/unittest.h"
#include "utilpvt.h"
#include "udp_collector.h"

namespace pvxs {

static std::atomic<bool> thisIsATest{false};

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
    thisIsATest = true;
}

namespace impl {
bool inUnitTest()
{
    return thisIsATest;
}

loc_bad_alloc::loc_bad_alloc(const char *file, int line)
{
    if(auto sep = strrchr(file, '/')) {
        file = sep+1;
    }
#ifdef _WIN32
    if(auto sep = strrchr(file, '\\')) {
        file = sep+1;
    }
#endif
    epicsSnprintf(msg, sizeof(msg)-1u, "bad_alloc %s:%d", file, line);
}

loc_bad_alloc::~loc_bad_alloc() {}

const char* loc_bad_alloc::what() const noexcept
{
    return msg;
}

} // namespace impl

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
    IfaceMap::cleanup();
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
#ifdef USE_POSIX_REGEX
    regex_t ex{};

    if(auto err = regcomp(&ex, expr.c_str(), REG_EXTENDED|REG_NOSUB)) {
        auto len = regerror(err, &ex, nullptr, 0u);
        std::vector<char> msg(len+1);
        (void)regerror(err, &ex, msg.data(), len);
        msg[len] = '\0'; // paranoia
        setPass(false);
        (*this)<<" expression error: "<<msg.data()<<" :";

    } else {
        setPass(regexec(&ex, inp.c_str(), 0, nullptr, 0)!=REG_NOMATCH);
        regfree(&ex);
    }

#else
    std::regex ex;
    try {
        ex.assign(expr, std::regex_constants::extended);
        setPass(std::regex_match(inp, ex));

    }catch(std::regex_error& e) {
        setPass(false);
        (*this)<<" expression error: "<<e.what()<<" :";
    }
#endif
    return *this;
}

namespace detail {

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
    strDiff(ret.stream(), rlhs, rrhs);

    return ret;
}

testCase _testStrMatch(const char *spat, const std::string& pat, const char *sstr, const std::string& str)
{
    testCase ret;
    ret.setPassMatch(pat, str);
    ret<<spat<<" (\""<<pat<<"\") match "<<sstr<<" (\""<<escape(str)<<"\")";
    return ret;
}

} // namespace detail
} // namespace pvxs
