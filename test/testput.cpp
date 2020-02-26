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
        ,mbox(server::SharedPV::buildMailbox())
        ,serv(server::Config::localhost()
              .build()
              .addPV("mailbox", mbox))
        ,cli(serv.clientConfig().build())
    {
        testShow()<<"Server:\n"<<serv.config()
                  <<"Client:\n"<<cli.config();

        initial["value"] = 1;
    }

    void testWait(bool get)
    {
        client::Result actual;
        epicsEvent done;

        auto op = cli.put("mailbox")
                .fetchPresent(get)
                .build([get](Value&& prototype) -> Value {
                    if(get)
                        testEq(prototype["value"].as<int32_t>(), 1);
                    else
                        testOk1(!prototype["value"].isMarked());

                    auto val = prototype.cloneEmpty();
                    val["value"] = 2;
                    return val;
                })
                .result([&actual, &done](client::Result&& result) {
                    actual = std::move(result);
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        if(testOk1(done.wait(5.0))) {
            try {
                actual();
                testPass("Put success");
            }catch(std::exception& e){
                testFail("Put error %s : %s", typeid (e).name(), e.what());
            }

            auto cur = initial.cloneEmpty();
            mbox.fetch(cur);
            testEq(cur["value"].as<int32_t>(), 2);
        } else {
            testSkip(2, "timeout");
        }
    }

    void loopback(bool get)
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        testWait(get);
    }

    void lazy()
    {
        testShow()<<__func__;

        std::atomic<bool> onFC{false}, onLD{false};

        mbox.onFirstConnect([this, &onFC](){
            testShow()<<__func__;

            mbox.open(initial);
            onFC.store(true);
        });
        mbox.onLastDisconnect([this, &onLD](){
            testShow()<<__func__;
            mbox.close();
            onLD.store(true);
        });

        serv.start();

        testWait(false);

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
                    done.trigger();
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
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        testOk1(!done.wait(2.1));
    }
};

void testRO()
{
    testShow()<<__func__;

    auto mbox(server::SharedPV::buildReadonly());
    auto initial = nt::NTScalar{TypeCode::Int32}.create();
    initial["value"] = 1;
    mbox.open(initial);

    auto serv = server::Config::localhost()
            .build()
            .addPV("mailbox", mbox)
            .start();

    auto cli = serv.clientConfig().build();

    client::Result actual;
    epicsEvent done;

    auto op = cli.put("mailbox")
            .fetchPresent(false)
            .build([](Value&& prototype) -> Value {
                auto v = prototype.cloneEmpty();
                v["value"] = 2;
                return v;
            })
            .result([&actual, &done](client::Result&& result) {
                actual = std::move(result);
                done.trigger();
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

struct ErrorSource : public server::Source
{
    virtual void onSearch(Search &op) override final
    {
        for(auto& name : op) {
            name.claim();
        }
    }
    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&op) override final
    {
        auto chan = std::move(op);

        chan->onOp([](std::unique_ptr<server::ConnectOp>&& op) {
            op->error("haha");
        });
    }
};

void testError()
{
    testShow()<<__func__;

    auto serv = server::Config::localhost()
            .build()
            .addSource("err", std::make_shared<ErrorSource>())
            .start();

    auto cli = serv.clientConfig().build();

    client::Result actual;
    epicsEvent done;

    auto op = cli.get("mailbox")
            .result([&actual, &done](client::Result&& result) {
                actual = std::move(result);
                done.trigger();
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

MAIN(testput)
{
    testPlan(0);
    logger_config_env();
    Tester().loopback(false);
    Tester().loopback(true);
    Tester().lazy();
    Tester().timeout();
    Tester().cancel();
    testRO();
    testError();
    cleanup_for_valgrind();
    return testDone();
}
