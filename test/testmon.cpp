/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <atomic>
#include <typeinfo>

#include <string.h>

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

// a Source whose Monitor setup fails.  ViaConnect is the case a Source which
// does not repeat SharedPV's internal try/catch hits without any error of its
// own: MonitorSetupOp::connect() throws for a pvRequest selecting no fields.
struct ThrowingSource : public server::Source {
    enum mode_t {AtSetup, AtStart, ViaConnect};
    const mode_t mode;
    const Value prototype;
    // signaled just before a callback throws of its own accord
    const std::shared_ptr<epicsEvent> entered;

    explicit ThrowingSource(mode_t mode)
        :mode(mode)
        ,prototype(nt::NTScalar{TypeCode::Int32}.create())
        ,entered(std::make_shared<epicsEvent>())
    {}

    virtual void onSearch(Search &op) override final {
        for(auto& pv : op) {
            if(strcmp(pv.name(), "thrower")==0)
                pv.claim();
        }
    }

    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&rop) override final {
        if(rop->name()!="thrower")
            return;

        auto op(std::move(rop));
        auto mode(this->mode);
        auto ptype(prototype);
        auto entered(this->entered);
        op->onSubscribe([mode, ptype, entered](std::unique_ptr<server::MonitorSetupOp>&& mop) {
            if(mode==AtSetup) {
                entered->signal();
                throw std::runtime_error("onSubscribe throws");
            }

            // for ViaConnect this is where the client's pvRequest throws
            std::shared_ptr<server::MonitorControlOp> ctrl(mop->connect(ptype));

            if(mode==AtStart) {
                // the callback holds the control op alive; MonitorOp::cleanup()
                // clears onStart and so breaks the cycle.  throws on start, and
                // again on the stop which ServerOp::cleanup() synthesizes when
                // the client destroys the operation
                ctrl->onStart([ctrl, entered](bool start) {
                    entered->signal();
                    throw std::runtime_error(start ? "onStart(true) throws" : "onStart(false) throws");
                });
            }
        });
    }
};

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

    void cancelDuringEvent()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        // A heap-allocated captured value the callback reads AFTER cancelling.
        // If the functor (and this capture) were freed by the in-call cancel,
        // touching `canary` would be a use-after-free (caught under ASan).
        auto canary(std::make_shared<std::string>("alive"));
        auto fired(std::make_shared<epicsEvent>());
        auto ok(std::make_shared<std::atomic<bool>>(false));

        std::shared_ptr<client::Subscription> self;
        self = cli.monitor("mailbox")
                   .maskConnected(true)
                   .maskDisconnected(true)
                   .event([canary, fired, ok](client::Subscription& s) {
                       // Re-entrant cancel on this same loop: move-destroys `event`.
                       s.cancel();
                       // Touch the capture after the cancel; must still be valid.
                       ok->store(*canary == "alive");
                       fired->signal();
                   })
                   .exec();

        post(1);

        testOk1(fired->wait(5.0));
        testOk1(ok->load());
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

    // a Source which does not guard connect() itself, as SharedPV does, is
    // failed by a pvRequest the client chooses
    void connectThrows()
    {
        testShow()<<__func__;

        serv.addSource("thrower", std::make_shared<ThrowingSource>(ThrowingSource::ViaConnect));
        serv.start();
        mbox.open(initial);
        subscribe("mailbox");

        testThrows<client::Connected>([this](){
            pop(sub, evt);
        });
        testEq(pop(sub, evt)["value"].as<int32_t>(), 42);

        epicsEvent bevt;
        auto bad(cli.monitor("thrower")
                 .field("nonexistent")
                 .maskConnected(true)
                 .maskDisconnected(false)
                 .event([&bevt](client::Subscription&) {
                     bevt.signal();
                 })
                 .exec());
        cli.hurryUp();

        testThrows<client::RemoteError>([&bad, &bevt]() {
            testShow()<<pop(bad, bevt);
        });

        post(43);
        bool survived = false;
        try {
            survived = pop(sub, evt)["value"].as<int32_t>()==43;
        }catch(std::exception& e){
            testDiag("circuit lost: %s : %s", typeid(e).name(), e.what());
        }
        testOk(survived, "monitor survives a rejected pvRequest on the same circuit");
    }

    void setupThrows()
    {
        testShow()<<__func__;

        serv.addSource("thrower", std::make_shared<ThrowingSource>(ThrowingSource::AtSetup));
        serv.start();
        mbox.open(initial);
        subscribe("mailbox");

        testThrows<client::Connected>([this](){
            pop(sub, evt);
        });
        testEq(pop(sub, evt)["value"].as<int32_t>(), 42);

        // a Source callback which throws fails only its own operation ...
        epicsEvent bevt;
        auto bad(cli.monitor("thrower")
                 .maskConnected(true)
                 .maskDisconnected(false)
                 .event([&bevt](client::Subscription&) {
                     bevt.signal();
                 })
                 .exec());
        cli.hurryUp();

        testThrows<client::RemoteError>([&bad, &bevt]() {
            testShow()<<pop(bad, bevt);
        });

        // ... and leaves the TCP circuit it shares with "mailbox" intact
        post(43);
        bool survived = false;
        try {
            survived = pop(sub, evt)["value"].as<int32_t>()==43;
        }catch(std::exception& e){
            testDiag("circuit lost: %s : %s", typeid(e).name(), e.what());
        }
        testOk(survived, "monitor survives a throwing setup on the same circuit");
    }

    void startThrows()
    {
        testShow()<<__func__;

        auto src(std::make_shared<ThrowingSource>(ThrowingSource::AtStart));
        serv.addSource("thrower", src);
        serv.start();
        mbox.open(initial);
        subscribe("mailbox");

        testThrows<client::Connected>([this](){
            pop(sub, evt);
        });
        testEq(pop(sub, evt)["value"].as<int32_t>(), 42);

        // setup succeeds; the server calls onStart() when the client starts it
        epicsEvent bevt;
        auto bad(cli.monitor("thrower")
                 .maskConnected(true)
                 .maskDisconnected(true)
                 .event([&bevt](client::Subscription&) {
                     bevt.signal();
                 })
                 .exec());
        cli.hurryUp();
        testTrue(src->entered->wait(5.0))<<"onStart(true) reached";

        post(43);
        bool survived = false;
        try {
            survived = pop(sub, evt)["value"].as<int32_t>()==43;
        }catch(std::exception& e){
            testDiag("circuit lost: %s : %s", typeid(e).name(), e.what());
        }
        testOk(survived, "monitor survives a throwing onStart on the same circuit");

        // destroying the operation makes ServerOp::cleanup() stop it, which
        // calls onStart(false) from a path the client uses for every teardown
        bad.reset();
        testTrue(src->entered->wait(5.0))<<"onStart(false) reached";

        post(44);
        survived = false;
        try {
            survived = pop(sub, evt)["value"].as<int32_t>()==44;
        }catch(std::exception& e){
            testDiag("circuit lost: %s : %s", typeid(e).name(), e.what());
        }
        testOk(survived, "monitor survives a throwing stop on the same circuit");
    }

    void testNoMark()
    {
        initial.unmark();
        mbox.open(initial);
        serv.start();
        subscribe("mailbox");

        testThrows<client::Connected>([this](){
            pop(sub, evt);
        });

        if(auto val = pop(sub, evt)) {
            testEq(val["value"].as<int32_t>(), 0);
        } else {
            testFail("Missing initial data update");
        }
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
    testPlan(59);
    testSetup();
    try{
        logger_config_env();
        BasicTest().orphan();
        BasicTest().cancel();
        BasicTest().asyncCancel();
        BasicTest().cancelDuringEvent();
        BasicTest().badRequest();
        BasicTest().connectThrows();
        BasicTest().setupThrows();
        BasicTest().startThrows();
        BasicTest().testNoMark();
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
