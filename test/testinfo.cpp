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
    }

    void testWait()
    {
        client::Result actual;
        epicsEvent done;

        auto op = cli.info("mailbox")
                .result([&actual, &done](client::Result&& result) {
                    actual = std::move(result);
                    done.signal();
                })
                .exec();

        cli.hurryUp();

        if(testOk1(done.wait(5.0))) {
            testEq(actual()["value"].type(), TypeCode::Int32);
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

        auto op = cli.info("nonexistent").exec();

        // clear Context to orphan in-progress operation
        cli = client::Context();
        op.reset();
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

    auto serv = server::Config::isolated()
            .build()
            .addSource("err", std::make_shared<ErrorSource>())
            .start();

    auto cli = serv.clientConfig().build();

    client::Result actual;
    epicsEvent done;

    auto op = cli.info("mailbox")
            .result([&actual, &done](client::Result&& result) {
                actual = std::move(result);
                done.signal();
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
    testPlan(13);
    testSetup();
    logger_config_env();
    Tester().loopback();
    Tester().lazy();
    Tester().timeout();
    Tester().cancel();
    Tester().asyncCancel();
    Tester().orphan();
    testError();
    return testDone();
}
