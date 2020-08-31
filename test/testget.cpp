/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

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

namespace {
using namespace pvxs;

struct Tester {
    Value initial;
    server::SharedPV mbox;
    server::Server serv;
    client::Context cli;

    Tester()
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

        epicsEvent evt;
        bool connd = false,
             discd = false;

        auto ctor = cli.connect("mailbox")
                .onConnect([&evt, &connd]()
        {
            testDiag("onConnect%c", !connd ? '.' : '?');
            connd = true;
            evt.signal();
        })
                .onDisconnect([&evt, &discd]()
        {
            testDiag("onDisconnect%c", !discd ? '.' : '?');
            discd = true;
            evt.signal();
        })
                .exec();

        // ensure de-dup
        auto ctor2 = cli.connect("mailbox").exec();

        testTrue(evt.wait(5.0))<<"Wait for Connect";
        testTrue(connd);

        // ensure de-dup
        auto ctor3 = cli.connect("mailbox").exec();

        testTrue(ctor->connected());
        testTrue(ctor2->connected());
        testTrue(ctor3->connected());

        serv.stop();

        testTrue(evt.wait(5.0))<<"Wait for Disconnect";
        testTrue(discd);
        testFalse(ctor->connected());
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

    void orphan()
    {
        testShow()<<__func__;

        auto op = cli.get("nonexistent").exec();

        // clear Context to orphan in-progress operation
        cli = client::Context();
        op.reset();
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
    testPlan(24);
    testSetup();
    logger_config_env();
    Tester().testConnector();
    Tester().testWaiter();
    Tester().loopback();
    Tester().lazy();
    Tester().timeout();
    Tester().cancel();
    Tester().orphan();
    testError(false);
    testError(true);
    cleanup_for_valgrind();
    return testDone();
}
