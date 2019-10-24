/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsUnitTest.h>

#include "pvxs/unittest.h"

namespace pvxs {

testCase::testCase()
    :result(Diag)
{}

testCase::testCase(bool result)
    :result(result ? Pass : Fail)
{}

testCase::testCase(testCase&& o) noexcept
    :result(o.result)
#if !GCC_VERSION || GCC_VERSION>=VERSION_INT(4,9,0,0)
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
#if !GCC_VERSION || GCC_VERSION>=VERSION_INT(4,9,0,0)
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
    if(result==Nothing) {
        // do nothing!
    } else if(result==Diag) {
        testDiag("%s", msg.str().c_str());
    } else {
        testOk(result==Pass, "%s", msg.str().c_str());
    }
}

} // namespace pvxs
