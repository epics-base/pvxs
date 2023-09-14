
#include <testMain.h>
#include <aaoRecord.h>
#include <longinRecord.h>
#include <longoutRecord.h>
#include <stringoutRecord.h>

//#include <pv/qsrv.h>
//#include "utilities.h"
#include "dblocker.h"
#include "pvxs/iochooks.h"
#include "pvalink.h"
#include "testioc.h"
//#include "pv/qsrv.h"

using namespace pvxs::ioc;
using namespace pvxs;

namespace
{
    void testGet()
    {
        testDiag("==== testGet ====");

        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);

        testdbGetFieldEqual("target:i.VAL", DBF_LONG, 42L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 0L); // value before first process

        testdbGetFieldEqual("src:i1.INP", DBF_STRING, "{\"pva\":\"target:i\"}");

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 42L);

        testdbPutFieldOk("src:i1.INP", DBF_STRING, "{\"pva\":\"target:ai\"}");

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 42L); // changing link doesn't automatically process

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 4L); // now it's changed
    }

    void testFieldLinks() {

        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testDiag("==== Test field links ====");

        std::string pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"field\":\"display.precision\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length()+1, pv_name.c_str());

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);
        
        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 4L); // changing link doesn't automatically process

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);

        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 2L); // changing link doesn't automatically process

    }
    
    void testProc()
    {

        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testDiag("==== Test proc settings ====");

        // Set it to CPP
        std::string pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"proc\":\"CPP\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length()+1, pv_name.c_str());

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);

        // Link should read old value again
        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 4L);

        testdbPutFieldOk("target:ai", DBF_FLOAT, 5.0);

        // We are already connected at this point, wait for the update.
        testqsrvWaitForLinkEvent(&i1->inp);

        // now it's changed
        testdbGetFieldEqual("src:i1.VAL", DBF_LONG, 5L);
    }

    void testSevr()
    {
        longinRecord *i1 = (longinRecord *)testdbRecordPtr("src:i1");

        testDiag("==== Test severity forwarding (NMS, MS, MSI) ====");

        std::string pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"sevr\":\"NMS\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length() + 1, pv_name.c_str());

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);

        testdbPutFieldOk("target:ai.LOLO", DBF_FLOAT, 5.0);
        testdbPutFieldOk("target:ai.LLSV", DBF_STRING, "MAJOR");
        testdbPutFieldOk("target:ai", DBF_FLOAT, 0.0);

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevNone);

        pv_name = "{\"pva\":{\"pv\":\"target:ai\",\"sevr\":\"MS\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length() + 1, pv_name.c_str());

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevMajor);

        pv_name = "{\"pva\":{\"pv\":\"target:mbbi\",\"sevr\":\"MSI\"}}";
        testdbPutArrFieldOk("src:i1.INP$", DBF_CHAR, pv_name.length() + 1, pv_name.c_str());

        while (!dbIsLinkConnected(&i1->inp))
            testqsrvWaitForLinkEvent(&i1->inp);

        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevNone);

        testdbPutFieldOk("target:ai", DBF_FLOAT, 1.0);
        testqsrvWaitForLinkEvent(&i1->inp);
        testdbPutFieldOk("src:i1.PROC", DBF_LONG, 1L);
        testdbGetFieldEqual("src:i1.SEVR", DBF_SHORT, epicsSevInvalid);
    }

    void testPut()
    {
        testDiag("==== testPut ====");

        longoutRecord *o2 = (longoutRecord *)testdbRecordPtr("src:o2");

        while (!dbIsLinkConnected(&o2->out))
            testqsrvWaitForLinkEvent(&o2->out);

        testdbGetFieldEqual("target:i2.VAL", DBF_LONG, 43L);
        testdbGetFieldEqual("src:o2.VAL", DBF_LONG, 0L);
        testdbGetFieldEqual("src:o2.OUT", DBF_STRING, "{\"pva\":\"target:i2\"}");

        testdbPutFieldOk("src:o2.VAL", DBF_LONG, 14L);

        testqsrvWaitForLinkEvent(&o2->out);
        testqsrvWaitForLinkEvent(&o2->out);

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

        testdbPutFieldOk("src:str.OUT", DBF_STRING, "{pva : \"target:str2\"}");

        while (!dbIsLinkConnected(&so->out))
            testqsrvWaitForLinkEvent(&so->out);

        testdbPutFieldOk("src:str.PROC", DBF_LONG, 1L);

        testqsrvWaitForLinkEvent(&so->out);

        testdbGetFieldEqual("target:str2", DBF_STRING, "bar");
    }

    void testArrays()
    {
        aaoRecord *aao = (aaoRecord *)testdbRecordPtr("source:aao");
        testDiag("==== testArrays ====");
        static const epicsFloat32 input_arr[] =  {1, 2, -1, 1.2, 0};
        testdbPutArrFieldOk("source:aao", DBR_FLOAT, 5, input_arr);

        testdbGetArrFieldEqual("target:aai_inp", DBF_CHAR, 10, 0, NULL);

        testqsrvWaitForLinkEvent(&aao->out);
        testqsrvWaitForLinkEvent(&aao->out);

        static const epicsInt8 expected_char[] = {1, 2, -1, 1, 0};
        testdbPutFieldOk("target:aai_inp.PROC", DBF_LONG, 1L);
        testdbGetArrFieldEqual("target:aai_inp", DBF_CHAR, 10, 5, expected_char);

        static const epicsUInt32 expected_ulong[] = {1L, 2L, 4294967295L, 1L, 0};
        testdbGetArrFieldEqual("target:aai_inp", DBF_ULONG, 10, 5, expected_ulong);
    }

    void testPutAsync()
    {
#ifdef USE_MULTILOCK
        testDiag("==== testPutAsync ====");

        longoutRecord *trig = (longoutRecord *)testdbRecordPtr("async:trig");

        while (!dbIsLinkConnected(&trig->out))
            testqsrvWaitForLinkEvent(&trig->out);

        testMonitor *done = testMonitorCreate("async:after", DBE_VALUE, 0);

        testdbPutFieldOk("async:trig.PROC", DBF_LONG, 1);
        testMonitorWait(done);

        testdbGetFieldEqual("async:trig", DBF_LONG, 1);
        testdbGetFieldEqual("async:slow", DBF_LONG, 1); // pushed from async:trig
        testdbGetFieldEqual("async:slow2", DBF_LONG, 2);
        testdbGetFieldEqual("async:after", DBF_LONG, 3);

#else
        testSkip(5, "Not USE_MULTILOCK");
#endif
    }

} // namespace

extern "C" void testioc_registerRecordDeviceDriver(struct dbBase *);

MAIN(testpvalink)
{
    testPlan(49);
    testSetup();

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
        testArrays();
        (void)testPutAsync;
        testqsrvShutdownOk();
        IOC.shutdown();
        testqsrvCleanup();
    }
    catch (std::exception &e)
    {
        testFail("Unexpected exception: %s", e.what());
    }
    // call epics atexits explicitly as workaround for c++ static dtor issues...
    epicsExit(testDone());
}
