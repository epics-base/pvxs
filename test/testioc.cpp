/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>
#include <dbUnitTest.h>
#include <dbAccess.h>
#include <iocsh.h>

#include <pvxs/iochooks.h>
#include <pvxs/server.h>
#include <pvxs/unittest.h>

extern "C" {
extern int testioc_registerRecordDeviceDriver(struct dbBase*);
}

using namespace pvxs;

namespace {

} // namespace

MAIN(testioc)
{
    testPlan(4);

    testdbPrepare();

    testThrows<std::logic_error>([]{
        ioc::server();
    });

    testdbReadDatabase("testioc.dbd", nullptr, nullptr);
    testEq(0, testioc_registerRecordDeviceDriver(pdbbase));
    testEq(0, iocshCmd("var atExitDebug 1"));

    testTrue(!!ioc::server());

    testIocInitOk();

    testIocShutdownOk();

    testdbCleanup();

    return testDone();
}
