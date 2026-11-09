/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>

#include <testMain.h>
#include <alarm.h>
#include <asDbLib.h>
#include <dbAccess.h>
#include <dbLock.h>
#include <epicsTime.h>
#include <epicsExit.h>
#include <asTrapWrite.h>
#include <generalTimeSup.h>
#include <iocsh.h>

#include "dblocker.h"
#include "testioc.h"
#include "utilpvt.h"

extern "C" {
extern int testioc_registerRecordDeviceDriver(struct dbBase*);
}

using namespace pvxs;

namespace {

std::atomic<bool> timeSim{true};
std::atomic<uint32_t> testTimeSec{12345678};

int testTimeCurrent(epicsTimeStamp *pDest)
{
    if(timeSim) {
        pDest->secPastEpoch = testTimeSec;
        pDest->nsec = 102030;
        return 0;
    } else {
        return 1;
    }
}

void testQSIConst(TestClient& ctxt)
{
    testDiag("%s", __func__);

    auto val(ctxt.get("qsi1").exec()->wait(5.0));
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    string value = \"initial\"\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 3\n"
              "        int32_t status = 0\n"
              "        string message = \"\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 0\n"
              "        int32_t nanoseconds = 0\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "}\n")<<" initial qsi1";

    testdbPutFieldOk("qsi1.PROC", DBF_LONG, 1);

    val = ctxt.get("qsi1").exec()->wait(5.0);
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    string value = \"initial\"\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 0\n"
              "        int32_t status = 0\n"
              "        string message = \"\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 643497678\n"
              "        int32_t nanoseconds = 102030\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "}\n")<<" updated qsi1";
}

void testQSILink(TestClient& ctxt)
{
    testDiag("%s", __func__);

    auto val(ctxt.get("qsi2").exec()->wait(5.0));
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    string value = \"\"\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 3\n"
              "        int32_t status = 0\n"
              "        string message = \"\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 0\n"
              "        int32_t nanoseconds = 0\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "}\n")<<" initial qsi2";

    testdbPutFieldOk("qsi2.PROC", DBF_LONG, 1);

    val = ctxt.get("qsi2").exec()->wait(5.0);
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    string value = \"special\"\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 0\n"
              "        int32_t status = 0\n"
              "        string message = \"\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 643497678\n"
              "        int32_t nanoseconds = 102030\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "}\n")<<" updated qsi2";
}

} // namespace

MAIN(testqfield)
{
    testPlan(7);
    testSetup();
    pvxs::logger_config_env();
    generalTimeRegisterCurrentProvider("test", 1, &testTimeCurrent);
    {
        ioc::TestIOC ioc;
        testdbReadDatabase("testioc.dbd", nullptr, nullptr);
        testOk1(!testioc_registerRecordDeviceDriver(pdbbase));
        testdbReadDatabase("testqfield.db", nullptr, nullptr);
        ioc.init();
        TestClient ctxt;
        testQSIConst(ctxt);
        testQSILink(ctxt);
    }
    // call epics atexits explicitly to handle older base w/o de-init hooks
    epicsExitCallAtExits();
    cleanup_for_valgrind();
    return testDone();
}
