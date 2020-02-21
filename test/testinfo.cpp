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
        ,serv(server::Config::localhost()
              .build()
              .addPV("mailbox", mbox))
        ,cli(serv.clientConfig().build())
    {
        testShow()<<"Server:\n"<<serv.config()
                  <<"Client:\n"<<cli.config();
    }

    void testWait()
    {
        client::Result actual;
        epicsEvent done;

        auto op = cli.info("mailbox")
                .result([&actual, &done](client::Result&& result) {
                    actual = std::move(result);
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        if(testOk1(done.wait(5.0))) {
            testEq(actual()["value"].type(), TypeCode::Int32);
        } else {
            testSkip(1, "timeout");
        }
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

        testWait();

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

    auto op = cli.info("mailbox")
            .result([&actual, &done](client::Result&& result) {
                actual = std::move(result);
                done.trigger();
            })
            .exec();

    cli.hurryUp();

    if(testOk1(done.wait(5.0))) {
        testThrows<client::RemoteError>([&actual]() {
            actual();
        });

    } else {
        testSkip(1, "timeout");
    }
}

} // namespace

MAIN(testinfo)
{
    testPlan(11);
    logger_config_env();
    Tester().loopback();
    Tester().lazy();
    Tester().timeout();
    Tester().cancel();
    testError();
    return testDone();
}
