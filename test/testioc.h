/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef TESTIOC_H
#define TESTIOC_H

#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/unittest.h>
#include <pvxs/iochooks.h>

#include <epicsEvent.h>
#include <dbUnitTest.h>
#include <dbChannel.h>

struct TestClient : pvxs::client::Context
{
    TestClient() : pvxs::client::Context(pvxs::ioc::server().clientConfig().build()) {}
};

struct TestSubscription
{
    epicsEvent evt;
    const std::shared_ptr<pvxs::client::Subscription> sub;
    TestSubscription(pvxs::client::MonitorBuilder b)
        :sub(b.event([this](pvxs::client::Subscription& subscription) {
             testDiag("%s update event occurred", subscription.name().c_str());
             evt.signal();
         }).exec())
    {}
    pvxs::Value waitForUpdate() {
        while (true) {
            if (auto value = sub->pop()) {
                testDiag("Update %s", sub->name().c_str());
                return value;
            } else if (!evt.wait(5.0)) {
                testFail("timeout waiting for event for %s", sub->name().c_str());
                return {};
            }
        }
    }
    void testEmpty() {
        while (true) {
            if (auto value = sub->pop()) {
                testTrue(false)<<" Unexpected update for "<<sub->name()<<"\n"
                               <<value.format().delta().arrayLimit(5u);
                return;
            } else if (!evt.wait(1.0)) {
                testPass("Not updates for %s", sub->name().c_str());
                return;
            }
        }
    }
};

template<typename T>
void testFldEq(const pvxs::Value& top, const char* fldname, const T& expect)
{
    if(auto fld = top[fldname]) {
        T actual;
        if(fld.as<T>(actual)) {
            testEq(expect, actual);
        } else {
            testFalse(false)<<" unable to convert "<<fldname<<" to "<<typeid(T).name()<<"\n"
                            <<top.format();
        }
    } else {
        testFalse(false)<<" Missing field: "<<fldname<<"\n"<<top.format();
    }
}

#if EPICS_VERSION_INT < VERSION_INT(3, 16, 1, 0)
static
void testdbPutArrFieldOk(const char* pv, short dbrType, unsigned long count, const void *pbuf)
{
    dbChannel *chan = dbChannelCreate(pv);
    long status = -1;

    if(!chan || (status=dbChannelOpen(chan))) {
        testFail("Channel error (%p, %ld) : %s", chan, status, pv);
        goto done;
    }

    status = dbChannelPutField(chan, dbrType, pbuf, count);

    testOk(status==0, "dbPutField(\"%s\", dbr=%d, count=%lu, ...) -> %ld", pv, dbrType, count, status);

done:
    if(chan)
        dbChannelDelete(chan);
}
#endif

#endif // TESTIOC_H
