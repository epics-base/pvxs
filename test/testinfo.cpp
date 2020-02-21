/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <testMain.h>

#include <epicsUnitTest.h>

#include <epicsEvent.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
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
        Value actual;
        epicsEvent done;

        auto op = cli.info("mailbox")
                .result([&actual, &done](Value&& val) {
                    actual = std::move(val);
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        if(testOk1(done.wait(5.0))) {
            testEq(actual["value"].type(), TypeCode::Int32);
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

        mbox.onFirstConnect([this](){
            testShow()<<__func__;

            mbox.open(initial);
        });
        mbox.onLastDisconnect([this](){
            testShow()<<__func__;
            mbox.close();
        });

        serv.start();

        testWait();
    }

    void timeout()
    {
        testShow()<<__func__;

        Value actual;
        epicsEvent done;

        // server not started

        auto op = cli.info("mailbox")
                .result([&actual, &done](Value&& val) {
                    actual = std::move(val);
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        testOk1(!done.wait(1.1));
    }

    void cancel()
    {
        testShow()<<__func__;

        Value actual;
        epicsEvent done;

        serv.start();

        // not storing Operation -> immediate cancel()
        cli.info("mailbox")
                .result([&actual, &done](Value&& val) {
                    actual = std::move(val);
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        testOk1(!done.wait(2.1));
    }
};

} // namespace

MAIN(testinfo)
{
    testPlan(6);
    logger_config_env();
    Tester().loopback();
    Tester().lazy();
    Tester().timeout();
    Tester().cancel();
    return testDone();
}
