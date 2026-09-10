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
#include "utilpvt.h"

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

    // cacheClear with Clean action: calls cacheClean twice (mark then sweep)
    void testCacheCleanMarkSweep()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        {
            auto op(cli.get("mailbox").exec());
            auto result(op->wait(5.0));
            testEq(result["value"].as<int32_t>(), 42)<<" first get";
        }
        // op dropped, channel idle in cache

        // cacheClear(Clean) calls cacheClean twice internally:
        // first call marks, second call sweeps
        cli.cacheClear(std::string(), client::Context::Clean);

        // channel swept, next get must rebuild
        {
            auto op(cli.get("mailbox").exec());
            cli.hurryUp();
            auto result(op->wait(5.0));
            testEq(result["value"].as<int32_t>(), 42)<<" get after sweep";
        }
    }

    // channel reuse: get reuses cached channel before any sweep
    void testChannelReuse()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        std::atomic<unsigned> connd{0u}, discd{0u};
        epicsEvent evt;

        auto ctor(cli.connect("mailbox")
                  .onConnect([&connd, &evt](){
                      connd++;
                      evt.signal();
                  })
                  .onDisconnect([&discd, &evt](){
                      discd++;
                      evt.signal();
                  })
                  .exec());

        cli.hurryUp();
        evt.wait(5.0);
        testEq(connd.load(), 1u)<<" initial connect";

        // first get
        {
            auto op(cli.get("mailbox").exec());
            auto result(op->wait(5.0));
            testEq(result["value"].as<int32_t>(), 42)<<" first get";
        }
        // op dropped, but channel still held by Connect op (ctor)

        // second get reuses same channel (no disconnect should fire)
        {
            auto op(cli.get("mailbox").exec());
            auto result(op->wait(5.0));
            testEq(result["value"].as<int32_t>(), 42)<<" reuse get";
        }

        // still only one connect, no disconnects
        testEq(connd.load(), 1u)<<" still connected (reused)";
        testEq(discd.load(), 0u)<<" no disconnect";

        ctor.reset();
        cli.cacheClear();
    }

    // Disconnect action sweeps immediately
    void testCacheCleanDisconnect()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        std::atomic<unsigned> connd{0u}, discd{0u};
        epicsEvent evt;

        auto ctor(cli.connect("mailbox")
                  .onConnect([&connd, &evt](){
                      connd++;
                      evt.signal();
                  })
                  .onDisconnect([&discd, &evt](){
                      discd++;
                      evt.signal();
                  })
                  .exec());

        cli.hurryUp();
        evt.wait(5.0);
        testEq(connd.load(), 1u)<<" connected";

        // Disconnect forces immediate sweep + op cancellation
        cli.cacheClear(std::string(), client::Context::Disconnect);

        // wait for disconnect callback
        while(discd.load()==0u) {
            if(!evt.wait(5.0)) {
                testFail("timeout waiting for disconnect");
                break;
            }
        }
        testEq(discd.load(), 1u)<<" disconnected after Disconnect action";

        ctor.reset();
        cli.cacheClear();
    }
};

} // namespace

MAIN(testgc)
{
    testPlan(9);
    testSetup();
    logger_config_env();
    Tester().testCacheCleanMarkSweep();
    Tester().testChannelReuse();
    Tester().testCacheCleanDisconnect();
    cleanup_for_valgrind();
    return testDone();
}
