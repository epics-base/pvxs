/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <atomic>
#include <typeinfo>

#include <testMain.h>

#include <epicsUnitTest.h>

#include <epicsEvent.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/nt.h>

namespace {
using namespace pvxs;

struct BasicTest {
    Value initial;
    server::SharedPV mbox;
    server::Server serv;
    client::Context cli;

    epicsEvent evt;
    std::shared_ptr<client::Subscription> sub;

    BasicTest()
        :initial(nt::NTScalar{TypeCode::Int32}.create())
        ,mbox(server::SharedPV::buildReadonly())
        ,serv(server::Config::isolated()
              .build()
              .addPV("mailbox", mbox))
        ,cli(serv.clientConfig().build())
    {
        testShow()<<"Server:\n"<<serv.config()
                  <<"Client:\n"<<cli.config();

        initial["value"] = 42;
    }

    ~BasicTest()
    {
        if(cli.use_count()>1u)
            testAbort("Tester Context leak");
    }

    void subscribe(const char *name)
    {
        sub = cli.monitor(name)
                .maskConnected(false)
                .maskDisconnected(false)
                .event([this](client::Subscription& sub) {
                    testDiag("Event evt");
                    evt.signal();
                })
                .exec();
    }

    void post(int32_t v)
    {
        auto update(initial.cloneEmpty());
        update["value"] = v;
        mbox.post(update);
    }

    static
    Value pop(const std::shared_ptr<client::Subscription>& sub, epicsEvent& evt)
    {
        while(true) {
            if(auto ret = sub->pop()) {
                return ret;

            } else if (!evt.wait(5.0)) {
                testAbort("timeout waiting for event");
            }
        }
    }

    void orphan()
    {
        testShow()<<__func__;

        auto op = cli.monitor("nonexistent").exec();

        // clear Context to orphan in-progress operation
        cli = client::Context();
        op.reset();
    }

    void cancel()
    {
        testShow()<<__func__;
        epicsEvent done;

        cli.monitor("nonexistent")
                .onInit([&done](client::Subscription&, const Value&)
        {
            done.signal();
        })
                .exec();

        testOk1(!done.wait(1.1));
    }

    void asyncCancel()
    {
        testShow()<<__func__;
        auto done(std::make_shared<epicsEvent>());

        cli.monitor("nonexistent")
                .syncCancel(false)
                .onInit([done](client::Subscription&, const Value&)
        {
            done->signal();
        })
                .exec();

        testOk1(!done->wait(1.1));
    }

    void badRequest()
    {
        testShow()<<__func__;

        serv.start();
        mbox.open(initial);

        auto sub(cli.monitor("mailbox")
                 .field("nonexistent")
                 .maskConnected(false)
                 .maskDisconnected(false)
                 .event([this](client::Subscription&) {
                     testDiag("Event evt");
                     evt.signal();
                 })
                 .exec());

        cli.hurryUp();

        testThrows<client::Connected>([this, &sub]() {
            testShow()<<pop(sub, evt);
        });

        testThrows<client::RemoteError>([this, &sub]() {
            testShow()<<pop(sub, evt);
        });
    }
};

struct TestLifeCycle : public BasicTest
{
    TestLifeCycle()
    {
        serv.start();
        mbox.open(initial);
        subscribe("mailbox");

        cli.hurryUp();

        testThrows<client::Connected>([this](){
            pop(sub, evt);
        });
    }

    void phase1()
    {
        testShow()<<"begin "<<__func__;

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 42);
        } else {
            testFail("Missing data update");
        }

        post(123);

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 123);
        } else {
            testFail("Missing data update 2");
        }

        testShow()<<"end "<<__func__;
    }

    void phase2(bool howdisconn)
    {
        testShow()<<"begin "<<__func__;

        if(howdisconn) {
            testDiag("Stopping server");
            serv.stop();
        } else {
            testDiag("close() mbox");
            mbox.close();
        }

        testThrows<client::Disconnect>([this](){
            pop(sub, evt);
            sub->pop();
        });

        testShow()<<"end "<<__func__;
    }

    void testBasic(bool howdisconn)
    {
        testShow()<<__func__<<" "<<howdisconn;
        phase1();
        phase2(howdisconn);
        testFalse(sub->pop())<<"No events after Disconnect";
    }

    void testSecond()
    {
        testShow()<<__func__;

        epicsEvent evt2;

        auto mbox2(server::SharedPV::buildReadonly());
        mbox2.open(initial);
        serv.addPV("mailbox2", mbox2);

        auto sub2 = cli.monitor("mailbox2")
                        .maskConnected(true)
                        .maskDisconnected(false)
                        .event([&evt2](client::Subscription& sub) {
                            testDiag("Event evt2");
                            evt2.signal();
                        })
                        .exec();

        phase1();

        if(auto val = pop(sub2, evt2)) {
            testEq(val["value"].as<int32_t>(), 42);
        } else {
            testFail("Missing data update");
        }

        phase2(false);

        // closing mbox should not disconnect mbox2.

        auto update(initial.cloneEmpty());
        update["value"] = 39;
        mbox2.post(update);

        if(auto val = pop(sub2, evt2)) {
            testEq(val["value"].as<int32_t>(), 39);
        } else {
            testFail("Missing data update");
        }
    }

    void testDelta()
    {
        testShow()<<__func__;

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 42);
            testEq(val["alarm.severity"].as<uint32_t>(), 0u);
            testTrue(val["value"].isMarked(false));
            testFalse(val["alarm.severity"].isMarked(false));
        } else {
            testFail("Missing data update");
        }

        // leave .value at 42
        {
            auto update(initial.cloneEmpty());
            update["alarm.severity"] = 1;
            mbox.post(update);
        }

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 42);
            testEq(val["alarm.severity"].as<uint32_t>(), 1u);
            testFalse(val["value"].isMarked(false));
            testTrue(val["alarm.severity"].isMarked(false));
        } else {
            testFail("Missing data update");
        }
    }
};

struct TestReconn : public BasicTest
{
    void testReconn(bool closechan)
    {
        testShow()<<__func__;

        serv.start();
        mbox.open(initial);
        subscribe("mailbox");

        cli.hurryUp();

        testThrows<client::Connected>([this](){
            auto val(pop(sub, evt));
            testTrue(false)<<" unexpected\n"<<val.format();
        });

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 42)<<"Initial data update";
        } else {
            testFail("Missing data update");
        }

        if(closechan) {
            testDiag("Close channel");
            mbox.close();

        } else {
            testDiag("Stop server");
            serv.stop();
        }

        testThrows<client::Disconnect>([this](){
            pop(sub, evt);
        })<<"Expecting Disconnect after stopping server";

        testFalse(sub->pop())<<"No events after Disconnect";
        errlogFlush();

        initial["value"] = 15;

        if(closechan) {
            testDiag("reopen channel");
            mbox.open(initial);

        } else {
            testDiag("Starting server");
            mbox.post(initial);
            serv.start();
        }

        testThrows<client::Connected>([this](){
            auto x = pop(sub, evt);
            testTrue(false)<<"Unexpected event : "<<x;
        })<<"Expecting Connected after restarting server";
        errlogFlush();

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 15);
        } else {
            testFail("Missing data update");
        }
    }
};

} // namespace

MAIN(testmon)
{
    testPlan(41);
    testSetup();
    try{
        logger_config_env();
        BasicTest().orphan();
        BasicTest().cancel();
        BasicTest().asyncCancel();
        BasicTest().badRequest();
        TestLifeCycle().testBasic(true);
        TestLifeCycle().testBasic(false);
        TestLifeCycle().testSecond();
        TestLifeCycle().testDelta();
        TestReconn().testReconn(false);
        TestReconn().testReconn(true);
    }catch(std::exception& e) {
        testFail("Unhandled exception %s : %s", typeid(e).name(), e.what());
        throw;
    }
    cleanup_for_valgrind();
    return testDone();
}
