/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define PVXS_ENABLE_EXPERT_API

#include <atomic>
#include <sstream>

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
#include "utilpvt.h"

namespace {
using namespace pvxs;

struct Tester {
    client::Result actual;
    epicsEvent start, done;
    Value initial;
    server::SharedPV mbox;
    server::Server serv;
    client::Context cli;
    bool fail = false;
    bool wait = false;

    Tester()
        :initial(nt::NTScalar{TypeCode::Int32}.create())
        ,mbox(server::SharedPV::buildMailbox())
        ,serv(server::Config::isolated()
              .build()
              .addPV("mailbox", mbox))
        ,cli(serv.clientConfig().build())
    {
        testShow()<<"Server:\n"<<serv.config()
                  <<"Client:\n"<<cli.config();

        initial["value"] = 1;

        mbox.onRPC([this](server::SharedPV& pv, std::unique_ptr<server::ExecOp>&& op, Value&& arg) {
            if(fail) {
                op->error("oops");
            } else {
                if(wait)
                    start.wait(10.0);
                op->reply(arg); // echo
            }
        });
    }

    std::shared_ptr<client::Operation> doCall(Value&& arg)
    {

        auto op = cli.rpc("mailbox", std::move(arg))
                .result([this](client::Result&& result) {
                    actual = std::move(result);
                    done.signal();
                })
                .exec();

        cli.hurryUp();

        return op;
    }

    Value testWaitOk()
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
        return Value();
    }

    void echo()
    {
        mbox.open(initial);
        serv.start();

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(std::move(arg));
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

        std::atomic<bool> onFC{false}, onLD{false};
        epicsEvent fldone;

        mbox.onFirstConnect([&onFC](server::SharedPV&){
            testShow()<<"In onFirstConnect()";

            onFC.store(true);
        });
        mbox.onLastDisconnect([&onLD, &fldone](server::SharedPV&){
            testShow()<<"In onLastDisconnect";
            onLD.store(true);
            fldone.signal();
        });

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(std::move(arg));
        if(auto ret = testWaitOk()) {

            int32_t v=0;
            testOk1(!!ret["value"].as(v));
            testEq(v, 42);
        }

        op.reset();
        cli.cacheClear();
        testOk1(fldone.wait(5.0));

        testOk1(!mbox.isOpen());
        testOk1(!!onFC.load());
        testOk1(!!onLD.load());
    }

    void null()
    {
        mbox.open(initial);
        serv.start();

        auto op = doCall(Value());
        if(auto ret = testWaitOk()) {

            testOk1(!ret.valid());
        }
    }

    void timeout()
    {
        // server not started

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(std::move(arg));
        testOk1(!done.wait(2.1));
    }

    void cancel()
    {
        mbox.open(initial);
        serv.start();
        wait = true;

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        (void)doCall(std::move(arg));
        // implicit cancel
        start.signal();
        if(!testOk1(!done.wait(2.1))) {
            try {
                auto R = actual();
                testTrue(false)<<" unexpected success "<<R;
            }catch(std::exception& e){
                testTrue(false)<<" unexpected error "<<e.what();
            }
        }

    }

    void error()
    {
        mbox.open(initial);
        serv.start();
        fail=true;

        auto arg = initial.cloneEmpty();
        arg["value"] = 42;
        auto op = doCall(std::move(arg));

        if(testOk1(done.wait(5.0))) {
            testThrows<client::RemoteError>([this](){
                actual();
            });
        } else {
            testSkip(1, "timeout");
        }
    }

    void builder()
    {
        mbox.open(initial);
        serv.start();


        auto op = cli.rpc("mailbox")
                .arg("a", 5)
                .arg("b", "hello")
                .exec();

        cli.hurryUp();

        auto result = op->wait();

        testEq(result["query.a"].as<int32_t>(), 5);
        testEq(result["query.b"].as<std::string>(), "hello");
    }

    void orphan()
    {
        testShow()<<__func__;

        auto op = cli.rpc("nonexistent").exec();

        // clear Context to orphan in-progress operation
        cli = client::Context();
        op.reset();
    }

    void serversrc()
    {
        using namespace pvxs::members;
        testShow()<<__func__;

        serv.start();

        std::string servaddr = SB()<<"127.0.0.1:"<<serv.config().tcp_port;

        auto uri(nt::NTURI({
                               String("op"),
                           }));

        {
            Value query = nt::NTURI({}).call();
            auto result(cli.rpc("server", uri.call("channels"))
                        .server(servaddr).exec()->wait(5.0));

            shared_array<const std::string> channels({"mailbox"});
            testArrEq(result["value"].as<shared_array<const std::string>>(), channels);
        }

        {
            Value query = nt::NTURI({}).call();
            auto result(cli.rpc("server", uri.call("info"))
                        .server(servaddr).exec()->wait(5.0));

            testEq(result["implLang"].as<std::string>(), "cpp");
            testStrMatch("PVXS.*", result["version"].as<std::string>());
        }
    }
};

} // namespace

MAIN(testrpc)
{
    testPlan(23);
    testSetup();
    Tester().echo();
    Tester().lazy();
    Tester().null();
    Tester().timeout();
    Tester().cancel();
    Tester().error();
    Tester().builder();
    Tester().orphan();
    Tester().serversrc();
    cleanup_for_valgrind();
    return testDone();
}
