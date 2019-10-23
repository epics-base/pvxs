/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <epicsUnitTest.h>

#include <pvxs/unittest.h>
#include <evhelper.h>

namespace  {
using namespace pvxsimpl;

struct my_special_error : public std::runtime_error
{
    my_special_error() : std::runtime_error("Special") {}
};

void test_call()
{
    testDiag("%s", __func__);

    evbase base("TEST");

    testOk1(!base.inLoop());

    {
        bool called = false;
        base.call([&called, &base]() {
            testDiag("in loop 1");
            called = true;
            testOk1(!!base.inLoop());
            base.assertInLoop();
        });
        testOk1(called==true);
    }

    {
        bool called = false;
        base.dispatch([&called]() {
            testDiag("in loop 2");
            called = true;
        });

        base.sync();
        testOk1(called==true);
    }

    try {
        base.call([](){
            testDiag("in loop 3");
            throw my_special_error();
        });
        testFail("Unexpected success");
    }catch(my_special_error&) {
        testPass("Caught expected exception");
    }catch(std::exception& e) {
        testFail("Caught wrong exception : %s \"%s\"", typeid(e).name(), e.what());
    }

}

} // namespace

MAIN(testev)
{
    testPlan(5);
    test_call();
    return testDone();
}
