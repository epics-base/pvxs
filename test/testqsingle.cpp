/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>

#include <stdio.h>
#include <string.h>

#include <testMain.h>
#include <asDbLib.h>
#include <dbAccess.h>
#include <dbLock.h>
#include <epicsTime.h>
#include <epicsExit.h>
#include <asTrapWrite.h>
#include <generalTimeSup.h>

#include "dblocker.h"
#include "testioc.h"
#include "utilpvt.h"

#if EPICS_VERSION_INT >= VERSION_INT(3, 15, 0, 2)
#  define HAVE_lsi
#endif

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

void forceUTAG(const char *rec)
{
    dbCommon *prec = testdbRecordPtr(rec);
    dbScanLock(prec);
#ifdef DBR_UTAG
    prec->utag = 42;
#endif
    dbScanUnlock(prec);
}

void checkUTAG(Value& v, int32_t expect=42)
{
#ifdef DBR_UTAG
    auto utag = v["timeStamp.userTag"];
    if(!utag.isMarked() || utag.as<int32_t>()!=expect)
        testFail("userTag not set");
    utag = 0;
    utag.unmark();
#endif
}

void testGetScalar()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbPutFieldOk("test:ai.PROC", DBF_LONG, 0);
    forceUTAG("test:ai");

    auto val(ctxt.get("test:ai").exec()->wait(5.0));
    checkUTAG(val);
    testFldEq<uint32_t>(val, "timeStamp.secondsPastEpoch", testTimeSec + POSIX_TIME_AT_EPICS_EPOCH);
    testStrEq(std::string(SB()<<val.format()),
            "struct \"epics:nt/NTScalar:1.0\" {\n"
            "    double value = 42.2\n"
            "    struct \"alarm_t\" {\n"
            "        int32_t severity = 2\n"
            "        int32_t status = 1\n"
            "        string message = \"HIGH\"\n"
            "    } alarm\n"
            "    struct \"time_t\" {\n"
            "        int64_t secondsPastEpoch = 643497678\n"
            "        int32_t nanoseconds = 102030\n"
            "        int32_t userTag = 0\n"
            "    } timeStamp\n"
            "    struct {\n"
            "        double limitLow = 0\n"
            "        double limitHigh = 100\n"
            "        string description = \"Analog input\"\n"
            "        string units = \"arb\"\n"
            "        int32_t precision = 1\n"
            "        struct \"enum_t\" {\n"
            "            int32_t index = 6\n"
            "            string[] choices = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
            "        } form\n"
            "    } display\n"
            "    struct {\n"
            "        double limitLow = 0\n"
            "        double limitHigh = 100\n"
            "        double minStep = 0\n"
            "    } control\n"
            "    struct {\n"
            "        bool active = false\n"
            "        double lowAlarmLimit = 0\n"
            "        double lowWarningLimit = 4\n"
            "        double highWarningLimit = 6\n"
            "        double highAlarmLimit = 100\n"
            "        int32_t lowAlarmSeverity = 0\n"
            "        int32_t lowWarningSeverity = 0\n"
            "        int32_t highWarningSeverity = 0\n"
            "        int32_t highAlarmSeverity = 0\n"
            "        double hysteresis = 0\n"
            "    } valueAlarm\n"
            "}\n")<<" fetch VAL w/ meta-data";
    testStrEq(std::string(SB()<<val.format().delta()),
              "value double = 42.2\n"
              "alarm.severity int32_t = 2\n"
              "alarm.status int32_t = 1\n"
              "alarm.message string = \"HIGH\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497678\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
              "display.limitLow double = 0\n"
              "display.limitHigh double = 100\n"
              "display.description string = \"Analog input\"\n"
              "display.units string = \"arb\"\n"
              "display.precision int32_t = 1\n"
              "display.form.index int32_t = 6\n"
              "display.form.choices string[] = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "control.limitLow double = 0\n"
              "control.limitHigh double = 100\n"
              "valueAlarm.lowAlarmLimit double = 0\n"
              "valueAlarm.lowWarningLimit double = 4\n"
              "valueAlarm.highWarningLimit double = 6\n"
              "valueAlarm.highAlarmLimit double = 100\n"
            )<<" fetch VAL w/ meta-data.  delta output";

    val = ctxt.get("test:ai.DESC").exec()->wait(5.0);
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    string value = \"Analog input\"\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 2\n"
              "        int32_t status = 1\n"
              "        string message = \"HIGH\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 643497678\n"
              "        int32_t nanoseconds = 102030\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "    struct {\n"
              "        string description = \"Analog input\"\n"
              "        string units = \"\"\n"
              "    } display\n"
              "}\n");

    val = ctxt.get("test:ai.SCAN").exec()->wait(5.0);
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTEnum:1.0\" {\n"
              "    struct \"enum_t\" {\n"
              "        int32_t index = 0\n"
              "        string[] choices = {10}[\"Passive\", \"Event\", \"I/O Intr\", \"10 second\", \"5 second\", \"2 second\", \"1 second\", \".5 second\", \".2 second\", \".1 second\"]\n"
              "    } value\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 2\n"
              "        int32_t status = 1\n"
              "        string message = \"HIGH\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 643497678\n"
              "        int32_t nanoseconds = 102030\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "    struct {\n"
              "        string description = \"Analog input\"\n"
              "    } display\n"
              "}\n");

    val = ctxt.get("test:ai.RVAL").exec()->wait(5.0);
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    int32_t value = 123\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 2\n"
              "        int32_t status = 1\n"
              "        string message = \"HIGH\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 643497678\n"
              "        int32_t nanoseconds = 102030\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "    struct {\n"
              "        int32_t limitLow = -2147483648\n"
              "        int32_t limitHigh = 2147483647\n"
              "        string description = \"Analog input\"\n"
              "        string units = \"\"\n"
              "        int32_t precision = 0\n"
              "        struct \"enum_t\" {\n"
              "            int32_t index = 0\n"
              "            string[] choices = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "        } form\n"
              "    } display\n"
              "    struct {\n"
              "        int32_t limitLow = -2147483648\n"
              "        int32_t limitHigh = 2147483647\n"
              "        int32_t minStep = 0\n"
              "    } control\n"
              "    struct {\n"
              "        bool active = false\n"
              "        int32_t lowAlarmLimit = 0\n"
              "        int32_t lowWarningLimit = 0\n"
              "        int32_t highWarningLimit = 0\n"
              "        int32_t highAlarmLimit = 0\n"
              "        int32_t lowAlarmSeverity = 0\n"
              "        int32_t lowWarningSeverity = 0\n"
              "        int32_t highWarningSeverity = 0\n"
              "        int32_t highAlarmSeverity = 0\n"
              "        double hysteresis = 0\n"
              "    } valueAlarm\n"
              "}\n");

    val = ctxt.get("test:ai.FLNK").exec()->wait(5.0);
    checkUTAG(val);
#if EPICS_VERSION_INT < VERSION_INT(3, 16, 0, 0)
    if(val["value"].as<std::string>()=="0")
        val["value"] = "";
#endif
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalar:1.0\" {\n"
              "    string value = \"\"\n"
              "    struct \"alarm_t\" {\n"
              "        int32_t severity = 2\n"
              "        int32_t status = 1\n"
              "        string message = \"HIGH\"\n"
              "    } alarm\n"
              "    struct \"time_t\" {\n"
              "        int64_t secondsPastEpoch = 643497678\n"
              "        int32_t nanoseconds = 102030\n"
              "        int32_t userTag = 0\n"
              "    } timeStamp\n"
              "    struct {\n"
              "        string description = \"Analog input\"\n"
              "        string units = \"\"\n"
              "    } display\n"
              "}\n");

    testFldEq<std::string>(ctxt.get("test:this:is:a:really:really:long:record:name.NAME").exec()->wait(5000.0),
                           "value", "test:this:is:a:really:really:long:record:name");

    testFldEq<std::string>(ctxt.get("test:this:is:a:really:really:long:record:name.NAME$").exec()->wait(5.0),
                           "value", "test:this:is:a:really:really:long:record:name");

    testFldEq<std::string>(ctxt.get("test:src.INP").exec()->wait(5.0),
                           "value", "test:this:is:a:really:really:long:record:name NPP NMS");

    testFldEq<std::string>(ctxt.get("test:src.INP$").exec()->wait(5.0),
                           "value", "test:this:is:a:really:really:long:record:name NPP NMS");

    testdbPutFieldOk("test:nsec.PROC", DBF_LONG, 0);
    forceUTAG("test:nsec"); // forced value should be ignored

    val = ctxt.get("test:nsec").exec()->wait(5.0);
#ifdef DBR_UTAG
    testFldEq(val, "timeStamp.userTag", 142);
    val["timeStamp.userTag"].unmark();
#else
    testSkip(1, "not UTAG");
#endif
    testStrEq(std::string(SB()<<val.format().delta()),
              "value int32_t = 100\n"
              "alarm.severity int32_t = 0\n"
              "alarm.status int32_t = 0\n"
              "alarm.message string = \"\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497678\n"
              "timeStamp.nanoseconds int32_t = 101888\n"
              "display.limitLow int32_t = 0\n"
              "display.limitHigh int32_t = 0\n"
              "display.description string = \"\"\n"
              "display.units string = \"\"\n"
              "display.form.index int32_t = 0\n"
              "display.form.choices string[] = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "control.limitLow int32_t = 0\n"
              "control.limitHigh int32_t = 0\n"
              "valueAlarm.lowAlarmLimit int32_t = 0\n"
              "valueAlarm.lowWarningLimit int32_t = 0\n"
              "valueAlarm.highWarningLimit int32_t = 0\n"
              "valueAlarm.highAlarmLimit int32_t = 0\n");
}

void testLongString()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    ctxt.put("test:long:str:wf")
            .set("value", "test:this:is:a:really:really:long:string:value")
            .exec()->wait(5.0);

    auto val(ctxt.get("test:long:str:wf").exec()->wait(5.0));
    testEq(val["value"].as<std::string>(), "test:this:is:a:really:really:long:string:value");

#ifdef HAVE_lsi
    ctxt.put("test:long:str:lsi.VAL")
            .set("value", "test:this:is:a:really:really:long:string:value")
            .exec()->wait(5.0);

    val = ctxt.get("test:long:str:lsi.VAL").exec()->wait(5.0);
    testEq(val["value"].as<std::string>(), "test:this:is:a:really:really:long:string:value");

#else
    testSkip(1, "No lsiRecord");
#endif
}

void testGetArray()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    {
        const double dbl[] = {1.0, 2.2, 3.0};
        testdbPutArrFieldOk("test:wf:f64", DBF_DOUBLE, NELEMENTS(dbl), dbl);
        const epicsInt32 lng[] = {4, 5, 6, 7};
        testdbPutArrFieldOk("test:wf:i32", DBF_LONG, NELEMENTS(lng), lng);
        char str[MAX_STRING_SIZE*3u] = {};
        strcpy(&str[MAX_STRING_SIZE*0u], "one");
        strcpy(&str[MAX_STRING_SIZE*1u], "two");
        strcpy(&str[MAX_STRING_SIZE*2u], "three");
        testdbPutArrFieldOk("test:wf:s", DBF_STRING, 3u, str);
    }

    forceUTAG("test:wf:f64");
    forceUTAG("test:wf:i32");
    forceUTAG("test:wf:s");

    auto val(ctxt.get("test:wf:f64").exec()->wait(5.0));
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format()),
              "struct \"epics:nt/NTScalarArray:1.0\" {\n"
              "    double[] value = {3}[1, 2.2, 3]\n"
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
              "    struct {\n"
              "        double limitLow = 0\n"
              "        double limitHigh = 0\n"
              "        string description = \"\"\n"
              "        string units = \"\"\n"
              "        int32_t precision = 0\n"
              "        struct \"enum_t\" {\n"
              "            int32_t index = 0\n"
              "            string[] choices = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "        } form\n"
              "    } display\n"
              "    struct {\n"
              "        double limitLow = 0\n"
              "        double limitHigh = 0\n"
              "        double minStep = 0\n"
              "    } control\n"
              "    struct {\n"
              "        bool active = false\n"
              "        double lowAlarmLimit = 0\n"
              "        double lowWarningLimit = 0\n"
              "        double highWarningLimit = 0\n"
              "        double highAlarmLimit = 0\n"
              "        int32_t lowAlarmSeverity = 0\n"
              "        int32_t lowWarningSeverity = 0\n"
              "        int32_t highWarningSeverity = 0\n"
              "        int32_t highAlarmSeverity = 0\n"
              "        double hysteresis = 0\n"
              "    } valueAlarm\n"
              "}\n");

    val = ctxt.get("test:wf:i32").exec()->wait(5.0);
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format().delta()),
              "value int32_t[] = {4}[4, 5, 6, 7]\n"
              "alarm.severity int32_t = 0\n"
              "alarm.status int32_t = 0\n"
              "alarm.message string = \"\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497678\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
              "display.limitLow int32_t = 0\n"
              "display.limitHigh int32_t = 0\n"
              "display.description string = \"\"\n"
              "display.units string = \"\"\n"
              "display.form.index int32_t = 0\n"
              "display.form.choices string[] = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "control.limitLow int32_t = 0\n"
              "control.limitHigh int32_t = 0\n");

    val = ctxt.get("test:wf:s").exec()->wait(5.0);
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format().delta()),
              "value string[] = {3}[\"one\", \"two\", \"three\"]\n"
              "alarm.severity int32_t = 0\n"
              "alarm.status int32_t = 0\n"
              "alarm.message string = \"\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497678\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
              "display.description string = \"\"\n"
              "display.units string = \"\"\n");

    val = ctxt.get("test:wf:i32.[1:2]").exec()->wait(5.0);
    testStrEq(std::string(SB()<<val["value"].format()),
              "int32_t[] = {2}[5, 6]\n");
}

void testPut()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    ctxt.put("test:ai").set("value", 53.2).exec()->wait(5.0);
    testdbGetFieldEqual("test:ai", DBF_DOUBLE, 53.2);

    ctxt.put("test:ai.DESC").set("value", "testing").exec()->wait(5.0);
    testdbGetFieldEqual("test:ai.DESC", DBF_STRING, "testing");

    ctxt.put("test:bo").set("value.index", 1).exec()->wait(5.0);
    testdbGetFieldEqual("test:bo", DBF_STRING, "One");

    {
        shared_array<const int32_t> arr({1, -3, 5, -7});
        ctxt.put("test:wf:i32").set("value", arr).exec()->wait(5.0);
        testdbGetArrFieldEqual("test:wf:i32", DBR_LONG, arr.size(), arr.size(), arr.data());
    }
    {
        shared_array<const double> arr({2.0, 3.2, 5.6});
        ctxt.put("test:wf:f64").set("value", arr).exec()->wait(5.0);
        testdbGetArrFieldEqual("test:wf:f64", DBR_DOUBLE, arr.size(), arr.size(), arr.data());
    }
    {
        shared_array<const std::string> arr({"x", "why", "that last one"});
        ctxt.put("test:wf:s").set("value", arr).exec()->wait(5.0);

        char str[MAX_STRING_SIZE*3u] = {};
        strcpy(&str[MAX_STRING_SIZE*0u], "x");
        strcpy(&str[MAX_STRING_SIZE*1u], "why");
        strcpy(&str[MAX_STRING_SIZE*2u], "that last one");
        testdbGetArrFieldEqual("test:wf:s", DBR_STRING, 3, 3, str);
    }

    testdbGetFieldEqual("test:ai2.INP", DBF_STRING, "test:ai NPP NMS");

    ctxt.put("test:ai2.INP").set("value", "").exec()->wait(5.0);
    testdbGetFieldEqual("test:ai2.INP", DBF_STRING, "");

    ctxt.put("test:ai2.INP").set("value", "test:ai").exec()->wait(5.0);
    testdbGetFieldEqual("test:ai2.INP", DBF_STRING, "test:ai NPP NMS");

    ctxt.put("test:ai2.INP$").set("value", "test:this:is:a:really:really:long:record:name").exec()->wait(5.0);
    testdbGetFieldEqual("test:ai2.INP", DBF_STRING, "test:this:is:a:really:really:long:recor");
    {
        const char expect[] = "test:this:is:a:really:really:long:record:name NPP NMS";
        testdbGetArrFieldEqual("test:ai2.INP$", DBR_CHAR, NELEMENTS(expect), NELEMENTS(expect), expect);
    }

    ctxt.put("test:ai2.INP$").set("value", "").exec()->wait(5.0);
    testdbGetFieldEqual("test:ai2.INP", DBF_STRING, "");

    try{
        ctxt.put("test:ai.STAT").set("value.index", 1).exec()->wait(5.0);
        testFail("test:ai.STAT was writable");
    }catch(pvxs::client::RemoteError& e){
        std::string msg(e.what());
        testTrue(msg.find("noMod")!=msg.npos || msg.find("511")!=msg.npos)
                <<" expected RemoteError: "<<msg;
    }

    try{
        ctxt.put("test:ro").set("value", 42).exec()->wait(5.0);
        testFail("test:ro was writable");
    }catch(pvxs::client::RemoteError& e){
        testStrEq(e.what(), "Put not permitted");
    }

    try{
        ctxt.put("test:disp").set("value", 42).exec()->wait(5.0);
        testFail("test:disp was writable");
    }catch(pvxs::client::RemoteError& e){
        testStrMatch(".*Field Disabled.*", e.what());
    }
}

void testGetPut64()
{
#ifdef DBR_UINT64
    testDiag("%s", __func__);
    TestClient ctxt;

    {
        const epicsUInt64 dbl[] = {11111111111111111, 222222222222222, 3333333333333};
        testdbPutArrFieldOk("test:wf:u64", DBF_UINT64, NELEMENTS(dbl), dbl);
    }

    testdbPutFieldOk("test:i64.PROC", DBF_LONG, 0);
    forceUTAG("test:i64");
    forceUTAG("test:wf:u64");

    auto val(ctxt.get("test:i64").exec()->wait(5.0));
    checkUTAG(val);
    testFldEq<uint64_t>(val, "value", 12345678901234);

    val = ctxt.get("test:wf:u64").exec()->wait(5.0);
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format().delta()),
              "value uint64_t[] = {3}[11111111111111111, 222222222222222, 3333333333333]\n"
              "alarm.severity int32_t = 0\n"
              "alarm.status int32_t = 0\n"
              "alarm.message string = \"\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497678\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
              "display.limitLow uint64_t = 0\n"
              "display.limitHigh uint64_t = 0\n"
              "display.description string = \"\"\n"
              "display.units string = \"\"\n"
              "display.form.index int32_t = 0\n"
              "display.form.choices string[] = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "control.limitLow uint64_t = 0\n"
              "control.limitHigh uint64_t = 0\n");


    ctxt.put("test:i64").set<uint64_t>("value", 12345678901230).exec()->wait(5.0);
    testdbGetFieldEqual("test:i64", DBF_INT64, 12345678901230ll);

    {
        shared_array<const uint64_t> arr({5555555555555555, 66666666666666});
        ctxt.put("test:wf:u64").set("value", arr).exec()->wait(5.0);
        testdbGetArrFieldEqual("test:wf:u64", DBR_UINT64, arr.size(), arr.size(), arr.data());
    }

#else // DBR_UINT64
    testSkip(6, "No INT64");
#endif // DBR_UINT64
}

void testPutProc()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbGetFieldEqual("test:counter", DBF_LONG, 0);

    // assume calcRecord has HIGH marked pp(TRUE), and LOPR marked pp(FALSE)

    ctxt.put("test:counter.LOPR").set("value", 0).exec()->wait(5.0);
    testdbGetFieldEqual("test:counter", DBF_LONG, 0);

    ctxt.put("test:counter.LOPR").set("value", 0).pvRequest("record[process=passive]").exec()->wait(5.0);
    testdbGetFieldEqual("test:counter", DBF_LONG, 0);

    ctxt.put("test:counter.LOPR").set("value", 0).pvRequest("record[process=false]").exec()->wait(5.0);
    testdbGetFieldEqual("test:counter", DBF_LONG, 0);

    ctxt.put("test:counter.LOPR").set("value", 0).pvRequest("record[process=true]").exec()->wait(5.0);
    testdbGetFieldEqual("test:counter", DBF_LONG, 1);
}

void testPutLog()
{
    testDiag("%s", __func__);
    TestClient ctxt;

    static std::ostringstream messages;
    struct AsLog {
        const asTrapWriteId id;
        static
        void message(asTrapWriteMessage *pmessage,int after)
        {
            // caPutLog assumes "serverSpecific" is always available, and a dbChannel*
            // (or dbAddr* with 3.14)
            auto *pchan = (dbChannel*)pmessage->serverSpecific;

            char val[MAX_STRING_SIZE+1u];

            dbChannelGetField(pchan, DBR_STRING, val, nullptr, nullptr, nullptr);
            val[MAX_STRING_SIZE] = '\0';

            if(!after) {
                // for repeatability, don't include host and user
                messages<<"host:user "<<dbChannelName(pchan)<<" "<<val;

            } else {
                messages<<" -> "<<val<<"\n";
            }
        }
        AsLog()
            :id(asTrapWriteRegisterListener(&message))
        {}
        ~AsLog() {
            asTrapWriteUnregisterListener(id);
        }
    } asLog;

    ctxt.put("test:log").set("value.index", 1).exec()->wait(5.0);
    ctxt.put("test:log").set("value.index", 0).exec()->wait(5.0);
    ctxt.put("test:log").set("value.index", 0).exec()->wait(5.0);

    auto log(messages.str());

    testStrEq(log,
              "host:user test:log Something -> Else\n"
              "host:user test:log Else -> Something\n"
              "host:user test:log Something -> Something\n");
}

void testPutBlock()
{
#if EPICS_VERSION_INT >= VERSION_INT(3, 16, 0, 1)
    testDiag("%s", __func__);
    TestClient ctxt;

    testdbGetFieldEqual("test:slowmo", DBR_DOUBLE, 0.0);

    auto start(epicsTime::getCurrent());
    ctxt.put("test:slowmo.PROC").set("value", 0).pvRequest("record[block=true]").exec()->wait(5.0);
    auto elapsed(epicsTime::getCurrent()-start);

    testdbGetFieldEqual("test:slowmo", DBR_DOUBLE, 1.0);
    testTrue(elapsed>=0.75)<<"time elapsed "<<elapsed<<" s";

    // so long it should not complete
    testdbPutFieldOk("test:slowmo.ODLY", DBR_LONG, 30);

    auto op(ctxt.put("test:slowmo.PROC").set("value", 5).pvRequest("record[block=true]").exec());

    // wait until processing has started
    {
        auto prec = testdbRecordPtr("test:slowmo");
        while(1) {
            dbScanLock(prec);
            auto pact(prec->pact);
            dbScanUnlock(prec);
            if(pact)
                break;
            testDiag("waiting for slowmo");
            epicsThreadSleep(1.0);
        }
    }

    testTrue(op->cancel());
    op.reset();

    // ensure processing still in progress
    {
        auto prec = testdbRecordPtr("test:slowmo");
        dbScanLock(prec);
        auto pact(prec->pact);
        dbScanUnlock(prec);
        testTrue(pact)<<" still busy";
    }

    testdbGetFieldEqual("test:slowmo", DBR_DOUBLE, 2.0);

    testdbPutFieldOk("test:bo", DBR_LONG, 0);
    ctxt.put("test:bo").set("value.index", 1).pvRequest("record[block=true]").exec()->wait(5.0);

    testdbGetFieldEqual("test:bo", DBR_LONG, 1);

#else
    testSkip(9, "dbNotify testing broken on 3.15");
    /* epics-base 3.15 circa a249561677de73e3f174ec8e4478937a7a55a9b2
     * contains ddaa6e4eb6647545db7a43c9b83ca7e2c497f3b8
     * but not a7a87372aab2c086f7ac60db4a5d9e39f08b9f05
     */
#endif
}

void testMonitorAI(TestClient& ctxt)
{
    testDiag("%s", __func__);

    TestSubscription sub(ctxt.monitor("test:ai")
                         .maskConnected(true)
                         .maskDisconnected(true));

    auto val(sub.waitForUpdate());
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format().delta()),
              "value double = 53.2\n"
              "alarm.severity int32_t = 2\n"
              "alarm.status int32_t = 1\n"
              "alarm.message string = \"HIGH\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497678\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
              "display.limitLow double = 0\n"
              "display.limitHigh double = 100\n"
              "display.description string = \"testing\"\n"
              "display.units string = \"arb\"\n"
              "display.precision int32_t = 1\n"
              "display.form.index int32_t = 6\n"
              "display.form.choices string[] = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
              "control.limitLow double = 0\n"
              "control.limitHigh double = 100\n"
              "valueAlarm.lowAlarmLimit double = 0\n"
              "valueAlarm.lowWarningLimit double = 4\n"
              "valueAlarm.highWarningLimit double = 6\n"
              "valueAlarm.highAlarmLimit double = 100\n"
            )<<" initial VAL w/ meta-data.  delta output";

    testTimeSec++;
    testdbPutFieldOk("test:ai", DBR_DOUBLE, 66.5); // triggers only DBE_VALUE

    val = sub.waitForUpdate();
    checkUTAG(val);
#if EPICS_VERSION_INT < VERSION_INT(7, 0, 6, 0)
    // lacks db_field_log::mask
    val["alarm"].unmark();
#endif
    testStrEq(std::string(SB()<<val.format().delta()),
              "value double = 66.5\n"
              "timeStamp.secondsPastEpoch int64_t = 643497679\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
            )<<" fetch VAL w/ meta-data.  delta output";

    testTimeSec++;
    testdbPutFieldOk("test:ai", DBR_DOUBLE, 5.0); // triggers DBE_VALUE | DBE_ALARM

    val = sub.waitForUpdate();
    checkUTAG(val);
    testStrEq(std::string(SB()<<val.format().delta()),
              "value double = 5\n"
              "alarm.severity int32_t = 0\n"
              "alarm.status int32_t = 0\n"
              "alarm.message string = \"\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497680\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
            )<<" fetch VAL w/ meta-data.  delta output";

    testTimeSec++;
    testdbPutFieldOk("test:ai.HIGH", DBR_DOUBLE, 7.0); // triggers only DBE_PROPERTY

    val = sub.waitForUpdate();
    testStrEq(std::string(SB()<<val.format().delta()),
              "display.limitLow double = 0\n"
              "display.limitHigh double = 100\n"
              "display.description string = \"testing\"\n"
              "display.units string = \"arb\"\n"
              "display.precision int32_t = 1\n"
              "control.limitLow double = 0\n"
              "control.limitHigh double = 100\n"
              "valueAlarm.lowAlarmLimit double = 0\n"
              "valueAlarm.lowWarningLimit double = 4\n"
              "valueAlarm.highWarningLimit double = 7\n"
              "valueAlarm.highAlarmLimit double = 100\n"
            )<<" fetch VAL w/ meta-data.  delta output";

    sub.testEmpty();
}

void testMonitorBO(TestClient& ctxt)
{
    testDiag("%s", __func__);

    testdbPutFieldOk("test:bo", DBR_STRING, "One");

    TestSubscription sub(ctxt.monitor("test:bo")
                         .maskConnected(true)
                         .maskDisconnected(true));

    auto val(sub.waitForUpdate());
    checkUTAG(val, 0);
    testStrEq(std::string(SB()<<val.format().delta()),
              "value.index int32_t = 1\n"
              "value.choices string[] = {2}[\"Zero\", \"One\"]\n"
              "alarm.severity int32_t = 0\n"
              "alarm.status int32_t = 0\n"
              "alarm.message string = \"\"\n"
              "timeStamp.secondsPastEpoch int64_t = 643497681\n"
              "timeStamp.nanoseconds int32_t = 102030\n"
              "display.description string = \"\"\n");

    testTimeSec++;
    testdbPutFieldOk("test:bo", DBR_STRING, "Zero");

    val = sub.waitForUpdate();
    checkUTAG(val, 0);
#if EPICS_VERSION_INT < VERSION_INT(7, 0, 6, 0)
    // lacks db_field_log::mask
    val["alarm"].unmark();
#endif
    testStrEq(std::string(SB()<<val.format().delta()),
              "value.index int32_t = 0\n"
              "timeStamp.secondsPastEpoch int64_t = 643497682\n"
              "timeStamp.nanoseconds int32_t = 102030\n");

    testTimeSec++;
    testdbPutFieldOk("test:bo.ZNAM", DBR_STRING, "Off");

    val = sub.waitForUpdate();
    testStrEq(std::string(SB()<<val.format().delta()),
              "value.choices string[] = {2}[\"Off\", \"One\"]\n"
              "display.description string = \"\"\n");

    sub.testEmpty();
}

void testMonitorAIFilt(TestClient& ctxt)
{
    testDiag("%s", __func__);

    TestSubscription sub1(ctxt.monitor("test:ai.VAL{\"dbnd\":{\"d\":0.0}}")
                         .maskConnected(true)
                         .maskDisconnected(true));
    TestSubscription sub2(ctxt.monitor("test:ai.VAL{\"dbnd\":{\"d\":2.0}}")
                         .maskConnected(true)
                         .maskDisconnected(true));

    Value val;
    {
        auto expect = "value double = 5\n"
                      "alarm.severity int32_t = 0\n"
                      "alarm.status int32_t = 0\n"
                      "alarm.message string = \"\"\n"
                      "timeStamp.secondsPastEpoch int64_t = 643497681\n"
                      "timeStamp.nanoseconds int32_t = 102030\n"
                      "display.limitLow double = 0\n"
                      "display.limitHigh double = 100\n"
                      "display.description string = \"testing\"\n"
                      "display.units string = \"arb\"\n"
                      "display.precision int32_t = 1\n"
                      "display.form.index int32_t = 6\n"
                      "display.form.choices string[] = {7}[\"Default\", \"String\", \"Binary\", \"Decimal\", \"Hex\", \"Exponential\", \"Engineering\"]\n"
                      "control.limitLow double = 0\n"
                      "control.limitHigh double = 100\n"
                      "valueAlarm.lowAlarmLimit double = 0\n"
                      "valueAlarm.lowWarningLimit double = 4\n"
                      "valueAlarm.highWarningLimit double = 7\n"
                      "valueAlarm.highAlarmLimit double = 100\n";
        val = sub1.waitForUpdate();
        checkUTAG(val);
        testStrEq(std::string(SB()<<val.format().delta()), expect)<<" initial dbnd 0";
        val = sub2.waitForUpdate();
        checkUTAG(val);
        testStrEq(std::string(SB()<<val.format().delta()), expect)<<" initial dbnd 2";
    }

    testdbPutFieldOk("test:ai", DBR_DOUBLE, 6.0);

    val = sub1.waitForUpdate();
    testFldEq(val, "value", 6.0);
    testFalse(val["display"].isMarked(true, true));
    sub2.testEmpty();

    testdbPutFieldOk("test:ai", DBR_DOUBLE, 8.0);

    val = sub1.waitForUpdate();
    testFldEq(val, "value", 8.0);
    val = sub2.waitForUpdate();
    testFldEq(val, "value", 8.0);

    sub1.testEmpty();
    sub2.testEmpty();
}

void testMonitorDBE(TestClient& ctxt)
{
    testDiag("%s", __func__);

    TestSubscription sub(ctxt.monitor("test:ai.TPRO")
                         .record("DBE", DBE_ARCHIVE)
                         .maskConnected(true)
                         .maskDisconnected(true));

    auto val(sub.waitForUpdate());
    testShow()<<val.format().delta();

    auto prec(testdbRecordPtr("test:ai"));

    {
        ioc::DBLocker L(prec);

        prec->tpro = 42; // event discarded
        db_post_events(prec, &prec->tpro, DBE_VALUE);
        prec->tpro = 43;
        db_post_events(prec, &prec->tpro, DBE_VALUE|DBE_ARCHIVE);
    }

    val = sub.waitForUpdate();
    testShow()<<val.format().delta();
    testEq(val["value"].as<int32_t>(), 43);
}

} // namespace

MAIN(testqsingle)
{
    testPlan(89);
    testSetup();
    pvxs::logger_config_env();
    generalTimeRegisterCurrentProvider("test", 1, &testTimeCurrent);
#if EPICS_VERSION_INT>=VERSION_INT(7, 0, 0, 0)
    // start up once to check shutdown and re-start
    {
        ioc::TestIOC ioc;
        testdbReadDatabase("testioc.dbd", nullptr, nullptr);
        testOk1(!testioc_registerRecordDeviceDriver(pdbbase));
        testdbReadDatabase("testqsingle.db", nullptr, nullptr);
        ioc.init();
    }
#else
    // eg. arrInitialize() had a local "firstTime" flag
    testSkip(1, "test ioc reinit did not work yet...");
#endif
    {
        ioc::TestIOC ioc;
        // https://github.com/epics-base/epics-base/issues/438
        asSetFilename("../testioc.acf");
        testdbReadDatabase("testioc.dbd", nullptr, nullptr);
        testOk1(!testioc_registerRecordDeviceDriver(pdbbase));
        testdbReadDatabase("testqsingle.db", nullptr, nullptr);
#ifdef HAVE_lsi
        testdbReadDatabase("testqsinglelsi.db", nullptr, nullptr);
#endif
#ifdef DBR_UINT64
        testdbReadDatabase("testqsingle64.db", nullptr, nullptr);
#endif
        ioc.init();
        testGetScalar();
        testLongString();
        testGetArray();
        testPut();
        testGetPut64();
        testPutProc();
        testPutLog();
        {
            TestClient mctxt;
            testMonitorAI(mctxt);
            testMonitorBO(mctxt);
            testMonitorAIFilt(mctxt);
            testMonitorDBE(mctxt);
        }
        timeSim = false;
        testPutBlock();
    }
    // call epics atexits explicitly to handle older base w/o de-init hooks
    epicsExitCallAtExits();
    cleanup_for_valgrind();
    return testDone();
}
