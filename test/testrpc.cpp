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
    client::Result actual;
    epicsEvent done;
    IValue initial;
    server::SharedPV mbox;
    server::Server serv;
    client::Context cli;
    bool fail = false;

    Tester()
        :initial(nt::NTScalar{TypeCode::Int32}
                 .create()
                 .update("value", 1)
                 .freeze())
        ,mbox(server::SharedPV::buildMailbox())
        ,serv(server::Config::isolated()
              .build()
              .addPV("mailbox", mbox))
        ,cli(serv.clientConfig().build())
    {
        testShow()<<"Server:\n"<<serv.config()
                  <<"Client:\n"<<cli.config();

        mbox.onRPC([this](server::SharedPV& pv, std::unique_ptr<server::ExecOp>&& op, const IValue& arg) {
            if(fail)
                op->error("oops");
            else
                op->reply(arg); // echo
        });
    }

    std::shared_ptr<client::Operation> doCall(const IValue& arg)
    {

        auto op = cli.rpc("mailbox", arg)
                .result([this](client::Result&& result) {
                    actual = std::move(result);
                    done.trigger();
                })
                .exec();

        cli.hurryUp();

        return op;
    }

    IValue testWaitOk()
    {
        if(testOk1(done.wait(5.0))) {
            try {
                auto ret = actual();
                testPass("RPC success");
                return ret;
            }catch(std::exception& e){
                testFail("RPC error %s : %s", typeid (e).name(), e.what());
            }
        } else {
            testSkip(1, "timeout");
        }
        return IValue();
    }

    void echo()
    {
        mbox.open(initial);
        serv.start();

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(arg.freeze());
        if(auto ret = testWaitOk()) {

            int32_t v=0;
            testOk1(!!ret["value"].as(v));
            testEq(v, 42);
        }
    }

    void lazy()
    {
        // mbox not open
        serv.start();

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(arg.freeze());
        if(auto ret = testWaitOk()) {

            int32_t v=0;
            testOk1(!!ret["value"].as(v));
            testEq(v, 42);
        }
    }

    void null()
    {
        mbox.open(initial);
        serv.start();

        auto op = doCall(IValue());
        if(auto ret = testWaitOk()) {

            testOk1(!ret.valid());
        }
    }

    void timeout()
    {
        // server not started

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(arg.freeze());
        testOk1(!done.wait(2.1));
    }

    void cancel()
    {
        mbox.open(initial);
        serv.start();

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        (void)doCall(arg.freeze());
        testOk1(!done.wait(2.1));

    }

    void error()
    {
        mbox.open(initial);
        serv.start();
        fail=true;

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(arg.freeze());

        if(testOk1(done.wait(5.0))) {
            testThrows<client::RemoteError>([this](){
                actual();
            });
        } else {
            testSkip(1, "timeout");
        }
    }
};

} // namespace

MAIN(testrpc)
{
    testPlan(14);
    Tester().echo();
    Tester().lazy();
    Tester().null();
    Tester().timeout();
    Tester().cancel();
    Tester().error();
    cleanup_for_valgrind();
    return testDone();
}
