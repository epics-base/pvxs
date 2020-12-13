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
    testPlan(5);
    testSetup();

    testdbPrepare();

    testThrows<std::logic_error>([]{
        ioc::server();
    });

    testdbReadDatabase("testioc.dbd", nullptr, nullptr);
    testEq(0, testioc_registerRecordDeviceDriver(pdbbase));
    testEq(0, iocshCmd("pvxsr()"));
    testEq(0, iocshCmd("pvxs_target_info()"));

    testTrue(!!ioc::server());

    testIocInitOk();

    testIocShutdownOk();

    testdbCleanup();

    return testDone();
}
