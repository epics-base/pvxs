/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>
#include <epicsExit.h>
#include <dbLock.h>
#include <dbLink.h>
#include <dbUnitTest.h>
#include <aiRecord.h>
#include <aaoRecord.h>
#include <aaiRecord.h>
#include <calcRecord.h>
#include <calcoutRecord.h>
#include <longinRecord.h>
#include <longoutRecord.h>
#include <stringoutRecord.h>

#define PVXS_ENABLE_EXPERT_API

#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/iochooks.h>
#include <pvxs/unittest.h>
#include <pvxs/nt.h>
#include <pvxs/sharedpv.h>

#include "dblocker.h"
#include "qsrvpvt.h"
#include "pvalink.h"

using namespace pvxs::ioc;
using namespace pvxs;

namespace {
    struct TestMonitor {
        testMonitor * const mon;
        TestMonitor(const char* pvname, unsigned dbe_mask, unsigned opt=0)
            :mon(testMonitorCreate(pvname, dbe_mask, opt))
        {}
        ~TestMonitor() { testMonitorDestroy(mon); }
        void wait() { testMonitorWait(mon); }
        unsigned count(bool reset=true) { return testMonitorCount(mon, reset); }
    };

    void testGet()
    {
        testDiag("==== testGet ====");

        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testqsrvWaitForLinkConnected(&i1->inp);

        testdbGetFieldEqual("target:i.VAL", DBF_LONG, 42L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 0L); // value before first process

        testdbGetFieldEqual("src:i1.INP", DBF_STRING, "{\"pva\":\"target:i\"}");

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 42L);

        testdbPutFieldOk("src:i1.INP", DBF_STRING, "{\"pva\":\"target:ai\"}");

        testqsrvWaitForLinkConnected(&i1->inp);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 42L); // changing link doesn't automatically process

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 4L); // now it's changed
    }

    void testFieldLinks() {

        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testDiag("==== Test field links ====");

        std::string pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"field\":\"display.precision\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length()+1, pv_name.c_str());

        testqsrvWaitForLinkConnected(&i1->inp);
        
        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 4L); // changing link doesn't automatically process

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 2L); // changing link doesn't automatically process

    }
    
    void testProc()
    {

        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testDiag("==== Test proc settings ====");

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 2L);

        // Set it to CPP
        std::string pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"proc\":\"CPP\"}}";
        {
            TestMonitor m("src:i1", DBE_VALUE);
            testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length()+1, pv_name.c_str());
            // wait for initial scan
            m.wait();
        }

        // Link should read current value of target.
        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 4L);

        {
            QSrvWaitForLinkUpdate C(&i1->inp);
            testdbPutFieldOk("target:ai", DBF_FLOAT, 5.0);
        }

        // now it's changed
        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 5L);
    }

    void testSevr()
    {
        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testDiag("==== Test severity forwarding (NMS, MS, MSI) ====");

        std::string pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"sevr\":\"NMS\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length() + 1, pv_name.c_str());

        testqsrvWaitForLinkConnected(&i1->inp);

        testdbPutFieldOk("target:ai.LOLO", DBF_FLOAT, 5.0);
        testdbPutFieldOk("target:ai.LLSV", DBF_STRING, "MAJOR");
        testdbPutFieldOk("target:ai", DBF_FLOAT, 0.0);

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevNone);

        pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"sevr\":\"MS\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length() + 1, pv_name.c_str());

        testqsrvWaitForLinkConnected(&i1->inp);

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevMajor);

        pv_name = "{\"pva\":{\"pv\":\"target:mbbi\",\"sevr\":\"MSI\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length() + 1, pv_name.c_str());

        testqsrvWaitForLinkConnected(&i1->inp);

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevNone);

        {
            QSrvWaitForLinkUpdate C(&i1->inp);
            testdbPutFieldOk("target:ai", DBF_FLOAT, 1.0);
        }

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevInvalid);
    }

    void testPut()
    {
        testDiag("==== testPut ====");

        longoutRecord *o2 = (longoutRecord *)testdbRecordPtr("src:o2");

        testqsrvWaitForLinkConnected(&o2->out);

        testdbGetFieldEqual("target:i2.VAL", DBF_LONG, 43L);
        testdbGetFieldEqual("src:o2.VAL", DBF_LONG, 0L);
        testdbGetFieldEqual("src:o2.OUT", DBF_STRING, "{\"pva\":\"target:i2\"}");

        {
            QSrvWaitForLinkUpdate C(&o2->out);
            testdbPutFieldOk("src:o2.VAL", DBF_LONG, 14L);
        }

        testdbGetFieldEqual("target:i2.VAL", DBF_LONG, 14L);
        testdbGetFieldEqual("src:o2.VAL", DBF_LONG, 14L);
    }

    void testStrings()
    {
        testDiag("==== testStrings ====");

        stringoutRecord *so = (stringoutRecord *)testdbRecordPtr("src:str");

        testdbGetFieldEqual("target:str1", DBF_STRING, "foo");
        testdbPutFieldOk("target:str1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("target:str1", DBF_STRING, "bar");

        testdbPutFieldOk("src:str.OUT", DBF_STRING, R"({"pva" : "target:str2"})");

        testqsrvWaitForLinkConnected(&so->out);

        {
            QSrvWaitForLinkUpdate C(&so->out);
            testdbPutFieldOk("src:str.PROC", DBF_LONG, 1L);
        }

        testdbGetFieldEqual("target:str2", DBF_STRING, "bar");
    }

    void testToFromString()
    {
        testDiag("==== %s ====", __func__);

        testqsrvWaitForLinkConnected("testToFromString:src.OUT");
        testqsrvWaitForLinkConnected("testToFromString:str2.INP");
        testqsrvWaitForLinkConnected("testToFromString:out.INP");

        {
            QSrvWaitForLinkUpdate C("testToFromString:out.INP");
            testdbPutFieldOk("testToFromString:src", DBR_LONG, 43);
        }

        testdbGetFieldEqual("testToFromString:str1", DBR_STRING, "43");
        testdbGetFieldEqual("testToFromString:str2", DBR_STRING, "43");
        testdbGetFieldEqual("testToFromString:out", DBR_LONG, 43);
    }

    void testArrays()
    {
        auto aai_inp = (aaiRecord *)testdbRecordPtr("target:aai_inp");
        testDiag("==== testArrays ====");
        static const epicsFloat32 input_arr[] =  {1, 2, -1, 1.2, 0};
        {
            QSrvWaitForLinkUpdate C(&aai_inp->inp);
            testdbPutArrFieldOk("source:aao", DBR_FLOAT, 5, input_arr);
        }

        // underlying channel cache updated, but record has not be re-processed
        testdbGetArrFieldEqual("target:aai_inp", DBF_CHAR, 10, 0, NULL);

        static const epicsInt8 expected_char[] = {1, 2, -1, 1, 0};
        testdbPutFieldOk("target:aai_inp.PROC", DBF_LONG, 1L);
        testdbGetArrFieldEqual("target:aai_inp", DBF_CHAR, 10, 5, expected_char);

        static const epicsUInt32 expected_ulong[] = {1L, 2L, 4294967295L, 1L, 0};
        testdbGetArrFieldEqual("target:aai_inp", DBF_ULONG, 10, 5, expected_ulong);

        testqsrvWaitForLinkConnected("target:aai_inp_first.INP");
        testdbPutFieldOk("target:aai_inp_first.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("target:aai_inp_first", DBR_DOUBLE, 1.0);
    }

    void testStringArray()
    {
        testDiag("==== %s ====", __func__);

        testqsrvWaitForLinkConnected("sarr:inp.INP");

        const char expect[3][MAX_STRING_SIZE] = {"one", "two", "three"};
        {
            QSrvWaitForLinkUpdate U("sarr:inp.INP");

            testdbPutArrFieldOk("sarr:src", DBR_STRING, 3, expect);
        }

        testdbPutFieldOk("sarr:inp.PROC", DBR_LONG, 0);

        testdbGetArrFieldEqual("sarr:inp", DBR_STRING, 4, 3, expect);
    }

    void testPutAsync()
    {
        testDiag("==== testPutAsync ====");

        auto trig = (longoutRecord *)testdbRecordPtr("async:trig");
        auto seq = (calcRecord *)testdbRecordPtr("async:seq");

        testqsrvWaitForLinkConnected(&trig->out);

        TestMonitor done("async:seq", DBE_VALUE, 0);

        testdbPutFieldOk("async:trig.PROC", DBF_LONG, 1);
        dbScanLock((dbCommon*)seq);
        while(seq->val < 2) {
            dbScanUnlock((dbCommon*)seq);
            done.wait();
            dbScanLock((dbCommon*)seq);
        }
        dbScanUnlock((dbCommon*)seq);

        testdbGetFieldEqual("async:target", DBF_LONG, 1);
        testdbGetFieldEqual("async:next", DBF_LONG, 2);
        testdbGetFieldEqual("async:seq", DBF_LONG, 2);
    }

    void testDisconnect()
    {
        testDiag("==== %s ====", __func__);
        auto serv(ioc::server());

        testdbPutFieldFail(-1, "disconnected.PROC", DBF_LONG, 1);
        testdbGetFieldEqual("disconnected.SEVR", DBF_SHORT, epicsSevInvalid);

        auto special(server::SharedPV::buildReadonly());
        special.open(nt::NTScalar{TypeCode::Int32}.create()
                     .update("value", 43));
        serv.addPV("special:pv", special);

        testqsrvWaitForLinkConnected("disconnected.INP");

        testdbPutFieldOk("disconnected.PROC", DBF_LONG, 1);
        testdbGetFieldEqual("disconnected.SEVR", DBF_SHORT, epicsSevNone);

        serv.removePV("special:pv");
        special.close();

        testqsrvWaitForLinkConnected("disconnected.INP", false);

        testdbPutFieldFail(-1, "disconnected.PROC", DBF_LONG, 1);
        testdbGetFieldEqual("disconnected.SEVR", DBF_SHORT, epicsSevInvalid);

        testdbPutFieldOk("disconnected.INP", DBR_STRING, ""); // avoid further log messages
    }

    void testMeta()
    {
        testDiag("==== %s ====", __func__);

        testqsrvWaitForLinkConnected("meta:inp.INP");

        {
            auto src = (aiRecord*)testdbRecordPtr("meta:src");
            QSrvWaitForLinkUpdate U("meta:inp.INP");
            dbScanLock((dbCommon*)src);
            src->tse = epicsTimeEventDeviceTime;
            src->time.secPastEpoch = 0x12345678;
            src->time.nsec = 0x10203040;
            src->val = 7;
            dbProcess((dbCommon*)src);
            dbScanUnlock((dbCommon*)src);
        }
        auto inp = (aiRecord*)testdbRecordPtr("meta:inp");

        long ret, nelem;
        epicsEnum16 stat, sevr;
        epicsTimeStamp time;
        char egu[10] = "";
        short prec;
        double val, lolo, low, high, hihi;

        dbScanLock((dbCommon*)inp);

        testTrue(dbIsLinkConnected(&inp->inp)!=0);

        testEq(dbGetLinkDBFtype(&inp->inp), DBF_DOUBLE);

        // alarm and time meta-data will be "latched" by a call to dbGetLink.
        // until then, the initial values are used

        testTrue((ret=dbGetAlarm(&inp->inp, &stat, &sevr))==0
                 && stat==LINK_ALARM && sevr==INVALID_ALARM)
                <<" ret="<<ret<<" stat="<<stat<<" sevr="<<sevr;

        testTrue((ret=dbGetTimeStamp(&inp->inp, &time))==0
                 && time.secPastEpoch==0 && time.nsec==0)
                <<" ret="<<ret<<" sec="<<time.secPastEpoch<<" ns="<<time.nsec;

        testTrue((ret=dbGetLink(&inp->inp, DBR_DOUBLE, &val, nullptr, nullptr))==0
                 && val==7.0)<<" ret="<<ret<<" val="<<val;

        // now latched...
        testTrue((ret=dbGetAlarm(&inp->inp, &stat, &sevr))==0
                 && stat==LINK_ALARM && sevr==MINOR_ALARM)
                <<" ret="<<ret<<" stat="<<stat<<" sevr="<<sevr;

        testTrue((ret=dbGetTimeStamp(&inp->inp, &time))==0
                 && time.secPastEpoch==0x12345678 && time.nsec==0x10203040)
                <<" ret="<<ret<<" sec="<<time.secPastEpoch<<" ns="<<time.nsec;

        testTrue((ret=dbGetGraphicLimits(&inp->inp, &low, &high))==0 && low==-9 && high==9)
                <<" ret="<<ret<<" low="<<low<<" high="<<high;

        testTrue((ret=dbGetControlLimits(&inp->inp, &low, &high))==0 && low==-10 && high==10)
                <<" ret="<<ret<<" low="<<low<<" high="<<high;

        testTrue((ret=dbGetAlarmLimits(&inp->inp, &lolo, &low, &high, &hihi))==0
                 && lolo==-8 && low==-7 && high==7 && hihi==8)
                <<" ret="<<ret<<" lolo="<<lolo<<" low="<<low<<" high="<<high<<" hihi="<<hihi;

        testTrue((ret=dbGetPrecision(&inp->inp, &prec))==0 && prec==2)
                <<" ret="<<ret<<" prec="<<prec;

        testTrue((ret=dbGetUnits(&inp->inp, egu, sizeof(egu)))==0 && strcmp(egu, "arb")==0)
                <<" ret="<<ret<<" egu='"<<egu<<"'";

        testTrue((ret=dbGetNelements(&inp->inp, &nelem))==0 && nelem==1)
                <<" ret="<<ret<<" nelem='"<<nelem<<"'";

        dbScanUnlock((dbCommon*)inp);
    }

    void testFwd()
    {
        testDiag("==== %s ====", __func__);

        testqsrvWaitForLinkConnected("flnk:src.FLNK");

        testdbGetFieldEqual("flnk:tgt", DBF_LONG, 0);

        testdbPutFieldOk("flnk:src.PROC", DBF_LONG, 1);

        {
            auto prec = testdbRecordPtr("flnk:tgt");
            TestMonitor mon("flnk:tgt", DBE_VALUE);

            dbScanLock(prec);
            while(((calcRecord*)prec)->val==0) {
                dbScanUnlock(prec);
                mon.wait();
                dbScanLock(prec);
            }
            dbScanUnlock(prec);
        }

        testdbGetFieldEqual("flnk:tgt", DBF_LONG, 1);
    }

    void testAtomic()
    {
        testDiag("==== %s ====", __func__);

        testqsrvWaitForLinkConnected("atomic:lnk:1.INP");
        testqsrvWaitForLinkConnected("atomic:lnk:2.INP");

        {
            QSrvWaitForLinkUpdate A("atomic:lnk:1.INP");
            QSrvWaitForLinkUpdate B("atomic:lnk:2.INP");

            testdbPutFieldOk("atomic:src:1.PROC", DBR_LONG, 0);
        }

        epicsUInt32 expect;
        {
            auto src1(testdbRecordPtr("atomic:src:1"));
            dbScanLock(src1);
            expect = ((calcoutRecord*)src1)->val;
            testEq(expect & ~0xff, 0u);
            expect |= expect<<8u;
            dbScanUnlock(src1);
        }

        testdbGetFieldEqual("atomic:lnk:out", DBF_ULONG, expect);
    }

    void testEnum()
    {
        testDiag("==== %s ====", __func__);

        testqsrvWaitForLinkConnected("enum:src:b.OUT");
        testqsrvWaitForLinkConnected("enum:src:s.OUT");
        testqsrvWaitForLinkConnected("enum:tgt:s.INP");
        testqsrvWaitForLinkConnected("enum:tgt:b.INP");

        {
            QSrvWaitForLinkUpdate A("enum:tgt:b.INP"); // last in chain...

            testdbPutFieldOk("enum:src:b", DBR_STRING, "one");
        }

        testdbGetFieldEqual("enum:tgt:s", DBR_STRING, "one");
        // not clear how to handle this case, where a string is
        // read as DBR_USHORT, which is actually as DBF_ENUM
        testTodoBegin("Not yet implemented");
        testdbGetFieldEqual("enum:tgt:b", DBR_STRING, "one");
        testTodoEnd();
    }
} // namespace

extern "C" void testioc_registerRecordDeviceDriver(struct dbBase *);

MAIN(testpvalink)
{
    testPlan(92);
    testSetup();
    pvxs::logger_config_env();

    try
    {
        TestIOC IOC;

        testdbReadDatabase("testioc.dbd", NULL, NULL);
        testioc_registerRecordDeviceDriver(pdbbase);
        testdbReadDatabase("testpvalink.db", NULL, NULL);

        IOC.init();

        testGet();
        testFieldLinks();
        testProc();
        testSevr();
        testPut();
        testStrings();
        testToFromString();
        testArrays();
        testStringArray();
        testPutAsync();
        testDisconnect();
        testMeta();
        testFwd();
        testAtomic();
        testEnum();
    }
    catch (std::exception &e)
    {
        testFail("Unexpected exception: %s", e.what());
    }
    // call epics atexits explicitly to handle older base w/o de-init hooks
    epicsExitCallAtExits();
    cleanup_for_valgrind();
    return testDone();
}
