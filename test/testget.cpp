/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <atomic>

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
#include "evhelper.h"

namespace {
using namespace pvxs;

struct Tester {
    Value initial;
    server::SharedPV mbox;
    server::Server serv;
    client::Context cli;

    Tester(int family=AF_INET)
        :initial(nt::NTScalar{TypeCode::Int32}.create())
        ,mbox(server::SharedPV::buildReadonly())
        ,serv(server::Config::isolated(family)
              .build()
              .addPV("mailbox", mbox))
        ,cli(serv.clientConfig().build())
    {
        testShow()<<"Server:\n"<<serv.config()
                  <<"Client:\n"<<cli.config();

        initial["value"] = 42;
    }

    ~Tester()
    {
        if(cli.use_count()>1u)
            testAbort("Tester Context leak: %u", unsigned(cli.use_count()));
    }

    void testConnector()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        struct info {
            epicsEvent evt;
            std::atomic<bool> current{false};
            std::atomic<size_t> connd{0}, discd{0};
            bool wait(bool state, double timeout) {
                while(current!=state) {
                    if(!evt.wait(timeout))
                        return false;
                }
                return true;
            }
        } evt, evt2, evt3;

        auto setup = [this](info& i) -> std::shared_ptr<client::Connect> {
            return cli.connect("mailbox")
                    .onConnect([&i]()
            {
                i.current = true;
                i.connd++;
                testDiag("onConnect %p %zu", &i, i.connd.load());
                i.evt.signal();
            })
                    .onDisconnect([&i]()
            {
                i.current = false;
                i.discd++;
                testDiag("onDisconnect %p %zu", &i, i.discd.load());
                i.evt.signal();
            })
                    .exec();
        };

        auto ctor(setup(evt));
        // ensure de-dup
        auto ctor2(setup(evt2));

        testTrue(evt.wait(true, 5.0))<<" Wait for Connect 1";
        testEq(evt.discd, 1u); // initially disconnected
        testEq(evt.connd, 1u);
        testTrue(evt2.wait(true, 5.0))<<" Wait for Connect 2";
        // evt2 may not see the initial "fake" disconnected event if the channel has already connected
        testOk(evt2.discd<=1u, "second event #discd=%zu", evt2.discd.load()); // initially disconnected
        testEq(evt2.connd, 1u);

        // ensure de-dup of connected
        auto ctor3(setup(evt3));

        testTrue(evt3.wait(true, 5.0))<<" Wait for Connect 3";
        testEq(evt3.discd, 0u); // initially connected
        testEq(evt3.connd, 1u);

        testTrue(ctor->connected());
        testTrue(ctor2->connected());
        testTrue(ctor3->connected());

        // generate some traffic on the channel
        (void)cli.get("mailbox").exec()->wait(1.0);

        auto sreport(serv.report());
        auto creport(cli.report());

        testDiag("Stop server");
        serv.stop();

        testTrue(evt.wait(false, 5.0))<<" Wait for Disconnect 1";
        testEq(evt.discd, 2u);
        testEq(evt.connd, 1u);
        testFalse(ctor->connected());

        auto checkReport = [](const impl::Report& report) {
            if(testEq(report.connections.size(), 1u)) {
                auto& conn = report.connections.front();
                testNotEq(conn.tx, 0u);
                testNotEq(conn.rx, 0u);
                if(testEq(conn.channels.size(), 1u)) {
                    auto& chan = conn.channels.front();
                    testNotEq(chan.tx, 0u);
                    testNotEq(chan.rx, 0u);
                    testEq(chan.name, "mailbox");
                }
            }
        };
        checkReport(sreport);
        checkReport(creport);
    }

    void testWaiter()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();
        std::atomic<bool> hadInit{false};

        auto op = cli.get("mailbox")
                .onInit([&hadInit](const Value& prototype) {
                    testShow()<<"onInit() << "<<prototype;
                    hadInit.store(prototype["value"].valid());
                })
                .exec();

        cli.hurryUp();

        auto result = op->wait(5.0);

        testEq(result["value"].as<int32_t>(), 42);
        testTrue(hadInit.load());
    }

    void testWait()
    {
        client::Result actual;
        epicsEvent done;

        auto op = cli.get("mailbox")
                .result([&actual, &done](client::Result&& result) {
                    actual = std::move(result);
                    done.signal();
                })
                .exec();

        cli.hurryUp();

        if(testOk1(done.wait(5.0))) {
            testEq(actual()["value"].as<int32_t>(), 42);
        } else {
            testSkip(1, "timeout");
        }

        op.reset();
        cli.cacheClear();
    }

    void loopback()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        testWait();
    }

    void lazy()
    {
        testShow()<<__func__;

        std::atomic<bool> onFC{false}, onLD{false};
        epicsEvent done;

        mbox.onFirstConnect([this, &onFC](server::SharedPV&){
            testShow()<<"In onFirstConnect()";

            mbox.open(initial);
            onFC.store(true);
        });
        mbox.onLastDisconnect([this, &onLD, &done](server::SharedPV&){
            testShow()<<"In onLastDisconnect";
            mbox.close();
            onLD.store(true);
            done.signal();
        });

        serv.start();

        testWait();
        testOk1(done.wait(5.0));

        serv.stop();

        testOk1(!mbox.isOpen());
        testOk1(!!onFC.load());
        testOk1(!!onLD.load());
    }

    void timeout()
    {
        testShow()<<__func__;

        client::Result actual;
        epicsEvent done;

        // server not started

        auto op = cli.info("mailbox")
                .result([&actual, &done](client::Result&& result) {
                    actual = std::move(result);
                    done.signal();
                })
                .exec();

        cli.hurryUp();

        testOk1(!done.wait(1.1));
    }

    void cancel()
    {
        testShow()<<__func__;

        client::Result actual;
        epicsEvent done;

        serv.start();

        // not storing Operation -> immediate cancel()
        cli.info("mailbox")
                .result([&actual, &done](client::Result&& result) {
                    actual = std::move(result);
                    done.signal();
                })
                .exec();

        cli.hurryUp();

        testOk1(!done.wait(2.1));
    }

    void asyncCancel()
    {
        testShow()<<__func__;

        struct info_t {
            client::Result actual;
            epicsEvent done;
        };
        auto info(std::make_shared<info_t>());

        serv.start();

        // not storing Operation -> immediate cancel()
        cli.info("mailbox")
                .syncCancel(false)
                .result([info](client::Result&& result) {
                    info->actual = std::move(result);
                    info->done.signal();
                })
                .exec();

        cli.hurryUp();

        testOk1(!info->done.wait(2.1));
    }

    void orphan()
    {
        testShow()<<__func__;

        auto op = cli.get("nonexistent").exec();

        // clear Context to orphan in-progress operation
        cli = client::Context();
        op.reset();
    }

    void manualExec()
    {
        testShow()<<__func__;

        epicsEvent initd;
        epicsEvent done;

        mbox.open(initial);
        serv.start();

        auto op = cli.get("mailbox")
                .autoExec(false)
                .onInit([&initd](const Value& prototype) {
                    testDiag("onInit()");
                    initd.signal();
                })
                .result([&initd](client::Result&& result) {
                    testFail("result() unexpected error prior to onInit()");
                    initd.signal();
                })
                .exec();

        testOk1(initd.wait(5.0));
        testDiag("reExec() 1");
        op->reExecGet([&done](client::Result&& result) {
            testTrue(!!result());
            testDiag("result() 1");
            done.signal();
        });

        testOk1(done.wait(5.0));
        testDiag("reExec() 2");
        op->reExecGet([&done](client::Result&& result) {
            testTrue(!!result());
            testDiag("result() 2");
            done.signal();
        });
        testOk1(done.wait(5.0));

        serv.stop();
        serv.start();
        // TODO: should reExec* while disconnected be queued?
        testOk1(initd.wait(5.0));

        testDiag("reExec() 3");
        op->reExecGet([&done](client::Result&& result) {
            testTrue(!!result());
            testDiag("result() 3");
            done.signal();
        });

        testOk1(done.wait(5.0));
    }

    void badRequest()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        auto op = cli.get("mailbox")
                .field("invalid")
                .exec();

        testThrowsMatch<std::runtime_error>("pvRequest must select at least one field", [&op]() {
            testShow()<<op->wait(4.0);
        })<<" pvRequest selects no fields";
    }

    void delayExec()
    {
        testShow()<<__func__;

        // ref'd by both put and timer functors
        auto done(std::make_shared<epicsEvent>());
        // ref'd by put functor
        auto slowdown(std::make_shared<Timer>());

        mbox.onPut([this, done, slowdown](server::SharedPV& pv,
                   std::unique_ptr<server::ExecOp>&& rawop, Value&& rawval) {
            // on server worker
            std::shared_ptr<server::ExecOp> op(std::move(rawop));
            auto val(std::move(rawval));
            testPass("In onPut");

            *slowdown = op->timerOneShot(0.01, [](){
                testFail("I should not run.");
            });

            testTrue(slowdown->cancel());

            *slowdown = op->timerOneShot(0.01, [this, done, op, val](){
                testPass("I should run");
                done->signal();
                mbox.post(val);
                op->reply();
            });

            // op->reply() from timer
        });

        mbox.open(initial);
        serv.start();

        auto op = cli.put("mailbox")
                .set("value", 42)
                .exec()->wait(5.0);
    }

    void ordering()
    {
        testShow()<<__func__;

        auto src2(server::StaticSource::build());
        auto mbox2(server::SharedPV::buildMailbox());
        src2.add("mailbox", mbox2);

        serv.addSource("other", src2.source(), -50);

        auto other = initial["value"].as<int32_t>()+1;

        mbox.open(initial);
        mbox2.open(initial.cloneEmpty()
                   .update("value", other));
        serv.start();

        auto val = cli.get("mailbox").exec()->wait(5.0);

        testEq(val["value"].as<int32_t>(), other);
    }
};

struct ErrorSource : public server::Source
{
    const bool phase = false;
    const Value type;
    explicit ErrorSource(bool phase)
        :phase(phase)
        ,type(nt::NTScalar{TypeCode::Int32}.create())
    {}

    virtual void onSearch(Search &op) override final
    {
        for(auto& name : op) {
            name.claim();
        }
    }
    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&op) override final
    {
        auto chan = std::move(op);

        chan->onOp([this](std::unique_ptr<server::ConnectOp>&& op) {
            if(!phase) {
                op->error("haha");
                return;
            }
            op->onGet([](std::unique_ptr<server::ExecOp>&& op) {
                op->error("nice try");
            });
            op->connect(type);
        });
    }
};

void testError(bool phase)
{
    testShow()<<__func__<<" phase="<<phase;

    auto serv = server::Config::isolated()
            .build()
            .addSource("err", std::make_shared<ErrorSource>(phase))
            .start();

    auto cli = serv.clientConfig().build();

    client::Result actual;
    epicsEvent done;

    auto op = cli.get("mailbox")
            .result([&actual, &done](client::Result&& result) {
                actual = std::move(result);
                done.signal();
            })
            .exec();

    cli.hurryUp();

    if(testOk1(done.wait(5.0))) {
        testThrows<client::RemoteError>([&actual]() {
            auto val = actual();
            testShow()<<"unexpected result\n"<<val;
        });

    } else {
        testSkip(1, "timeout");
    }
}

} // namespace

MAIN(testget)
{
    testPlan(62);
    testSetup();
    logger_config_env();
    const bool canIPv6 = pvxs::impl::evsocket::canIPv6;
    Tester().testConnector();
    Tester().testWaiter();
    Tester(AF_INET).loopback();
    if(canIPv6) {
        Tester(AF_INET6).loopback();
    } else {
        testSkip(2, "No IPv6 Support");
    }
    Tester().lazy();
    Tester().timeout();
    Tester().cancel();
    Tester().asyncCancel();
    Tester().orphan();
    Tester().manualExec();
    Tester().badRequest();
    Tester().delayExec();
    Tester().ordering();
    testError(false);
    testError(true);
    cleanup_for_valgrind();
    return testDone();
}
