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
    ,msg(std::move(o.msg))
{
    o.result = Nothing;
}

testCase& testCase::operator=(testCase&& o) noexcept
{
    if(this!=&o) {
        result = o.result;
        o.result = Nothing;
        msg = std::move(o.msg);
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
