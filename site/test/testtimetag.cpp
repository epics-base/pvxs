/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Tests for Q:time:tag, exercised through the site-extension post-processor hook.

#include <testMain.h>
#include <dbAccess.h>
#include <dbUnitTest.h>
#include <epicsExit.h>
#include <epicsEvent.h>
#include <generalTimeSup.h>

#include <pvxs/client.h>
#include <pvxs/iochooks.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/unittest.h>

extern "C" {
extern int testioc_registerRecordDeviceDriver(struct dbBase*);
}

using namespace pvxs;

namespace {

// Simulated time: fixed nsec=102030 so the test is deterministic.
// nsec:lsb:8 mask = 0xFF = 255:  nanoseconds -> 101888, userTag -> 142
// nsec:lsb:4 mask = 0x0F =  15:  nanoseconds -> 102016, userTag ->  14
static const int32_t kRawNsec       = 102030;
static const int32_t kMaskedNsec8   = 101888;  // 102030 & ~0xFF
static const int32_t kUserTag8      = 142;      // 102030 &  0xFF
static const int32_t kMaskedNsec4   = 102016;  // 102030 & ~0x0F
static const int32_t kUserTag4      = 14;       // 102030 &  0x0F

int testTimeCurrent(epicsTimeStamp* pDest)
{
    pDest->secPastEpoch = 12345678u;
    pDest->nsec         = uint32_t(kRawNsec);
    return 0;
}

struct TestClient : client::Context {
    TestClient() : client::Context(ioc::server().clientConfig().build()) {}
};

struct TestSubscription {
    epicsEvent evt;
    const std::shared_ptr<client::Subscription> sub;
    explicit TestSubscription(client::MonitorBuilder b)
        : sub(b.event([this](client::Subscription&) { evt.signal(); }).exec())
    {}
    Value waitForUpdate() {
        while(true) {
            if(auto val = sub->pop()) return val;
            if(!evt.wait(5.0)) { testFail("timeout waiting for monitor update"); return {}; }
        }
    }
};

// Verify that Q:time:tag "nsec:lsb:8" masks nanoseconds and fills userTag on GET.
void testTimeTagGet()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbPutFieldOk("test:timetag.PROC", DBF_LONG, 0);

    auto val = ctxt.get("test:timetag").exec()->wait(5.0);
    testEq(val["timeStamp.nanoseconds"].as<int32_t>(), kMaskedNsec8);
    testEq(val["timeStamp.userTag"].as<int32_t>(),     kUserTag8);
}

// Verify that Q:time:tag masking works via a monitor subscription.
// Regression: subscriptionCallback formerly passed MappingInfo() instead of the
// real MappingInfo, leaving nsecMask=0 and skipping timestamp masking on updates.
void testTimeTagMonitor()
{
    testDiag("%s", __func__);

    TestClient ctxt;
    TestSubscription sub(ctxt.monitor("test:timetag")
                         .maskConnected(true)
                         .maskDisconnected(true));

    auto val = sub.waitForUpdate();
    testEq(val["timeStamp.nanoseconds"].as<int32_t>(), kMaskedNsec8);
    testEq(val["timeStamp.userTag"].as<int32_t>(),     kUserTag8);
}

// Verify that a different bit-width (nsec:lsb:4) produces the correct mask.
void testDifferentWidth()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbPutFieldOk("test:timetag4.PROC", DBF_LONG, 0);

    auto val = ctxt.get("test:timetag4").exec()->wait(5.0);
    testEq(val["timeStamp.nanoseconds"].as<int32_t>(), kMaskedNsec4);
    testEq(val["timeStamp.userTag"].as<int32_t>(),     kUserTag4);
}

// Verify that an unrecognised Q:time:tag format is silently ignored:
// nanoseconds must be unmasked and userTag left at zero.
void testInvalidTag()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbPutFieldOk("test:badtag.PROC", DBF_LONG, 0);

    auto val = ctxt.get("test:badtag").exec()->wait(5.0);
    testEq(val["timeStamp.nanoseconds"].as<int32_t>(), kRawNsec);
    testEq(val["timeStamp.userTag"].as<int32_t>(), 0);
}

// Verify that a record without Q:time:tag is not affected: nanoseconds pass through unmasked.
void testNoTag()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbPutFieldOk("test:notag.PROC", DBF_LONG, 0);

    auto val = ctxt.get("test:notag").exec()->wait(5.0);
    testEq(val["timeStamp.nanoseconds"].as<int32_t>(), kRawNsec);
    testEq(val["timeStamp.userTag"].as<int32_t>(), 0);
}

} // namespace

MAIN(testtimetag)
{
    testPlan(15);
    testSetup();
    pvxs::logger_config_env();
    generalTimeRegisterCurrentProvider("test", 1, &testTimeCurrent);
    {
        ioc::TestIOC ioc;
        testdbReadDatabase("testioc.dbd", nullptr, nullptr);
        testOk1(!testioc_registerRecordDeviceDriver(pdbbase));
        testdbReadDatabase("testtimetag.db", nullptr, nullptr);
        ioc.init();
        testTimeTagGet();
        testTimeTagMonitor();
        testDifferentWidth();
        testInvalidTag();
        testNoTag();
    }
    epicsExitCallAtExits();
    cleanup_for_valgrind();
    return testDone();
}
