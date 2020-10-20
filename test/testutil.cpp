/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <epicsThread.h>

#include <pvxs/unittest.h>
#include <pvxs/util.h>

namespace {
using namespace pvxs;


} // namespace

MAIN(testutil)
{
    testPlan(0);
    return testDone();
}
