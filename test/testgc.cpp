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

        // verify channel present in report before sweep
        {
            auto rpt(cli.report(false));
            size_t nMailbox = 0u; // count of "mailbox" channels across all connections
            for(auto& conn : rpt.connections)
                for(auto& ch : conn.channels)
                    if(ch.name=="mailbox") nMailbox++;
            testEq(nMailbox, 1u)<<" channel in cache before sweep";
        }

        // cacheClear(Clean) calls cacheClean twice internally:
        // first call marks garbage=true, second call sweeps marked channels
        cli.cacheClear(std::string(), client::Context::Clean);

        // verify channel gone from report after sweep
        {
            auto rpt(cli.report(false));
            size_t nMailbox = 0u;
            for(auto& conn : rpt.connections)
                for(auto& ch : conn.channels)
                    if(ch.name=="mailbox") nMailbox++;
            testEq(nMailbox, 0u)<<" channel removed after sweep";
        }

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

        std::atomic<bool> current{false}; // true when channel is currently connected
        std::atomic<unsigned> connd{0u}; // total connect callback count
        std::atomic<unsigned> discd{0u}; // total disconnect callback count
        epicsEvent evt; // signaled on any connect/disconnect callback

        // hold a Connect monitor — keeps the channel alive in cache
        auto ctor(cli.connect("mailbox")
                  .onConnect([&current, &connd, &evt](){
                      current = true;
                      connd++;
                      evt.signal();
                  })
                  .onDisconnect([&current, &discd, &evt](){
                      current = false;
                      discd++;
                      evt.signal();
                  })
                  .exec());

        // wait for connected (may see initial disconnect first)
        while(!current.load()) {
            if(!evt.wait(5.0)) {
                testFail("timeout waiting for connect");
                break;
            }
        }
        testEq(connd.load(), 1u)<<" initial connect";

        // snapshot disconnect count before gets, to detect spurious disconnects
        auto discd_before = discd.load();

        // first get — establishes baseline tx bytes on the channel
        size_t txAfterFirst = 0u; // tx bytes on "mailbox" channel after first get
        {
            auto op(cli.get("mailbox").exec());
            auto result(op->wait(5.0));
            testEq(result["value"].as<int32_t>(), 42)<<" first get";
        }
        {
            auto rpt(cli.report(false));
            size_t nMailbox = 0u; // count of "mailbox" channels across all connections
            for(auto& conn : rpt.connections)
                for(auto& ch : conn.channels)
                    if(ch.name=="mailbox") { nMailbox++; txAfterFirst = ch.tx; }
            testEq(nMailbox, 1u)<<" one channel after first get";
            testOk(txAfterFirst > 0u, "tx > 0 after first get (tx=%zu)", txAfterFirst);
        }
        // op dropped, but channel still held by Connect monitor (ctor)

        // second get — should reuse same channel (no disconnect should fire)
        {
            auto op(cli.get("mailbox").exec());
            auto result(op->wait(5.0));
            testEq(result["value"].as<int32_t>(), 42)<<" reuse get";
        }
        {
            auto rpt(cli.report(false));
            size_t nMailbox = 0u;
            size_t txAfterSecond = 0u; // tx bytes after second get, must exceed txAfterFirst
            for(auto& conn : rpt.connections)
                for(auto& ch : conn.channels)
                    if(ch.name=="mailbox") { nMailbox++; txAfterSecond = ch.tx; }
            testEq(nMailbox, 1u)<<" still one channel after reuse";
            // growing tx on same channel proves both gets shared one channel
            testOk(txAfterSecond > txAfterFirst,
                   "tx grew on same channel (%zu > %zu)", txAfterSecond, txAfterFirst);
        }

        // still only one connect, no new disconnects since gets started
        testEq(connd.load(), 1u)<<" still connected (reused)";
        testEq(discd.load(), discd_before)<<" no new disconnect";

        ctor.reset();
        cli.cacheClear();
    }

    // Disconnect action sweeps immediately
    void testCacheCleanDisconnect()
    {
        testShow()<<__func__;

        mbox.open(initial);
        serv.start();

        std::atomic<bool> current{false}; // true when channel is currently connected
        std::atomic<unsigned> connd{0u}; // total connect callback count
        std::atomic<unsigned> discd{0u}; // total disconnect callback count
        epicsEvent evt; // signaled on any connect/disconnect callback

        // hold a Connect monitor — keeps the channel alive in cache
        auto ctor(cli.connect("mailbox")
                  .onConnect([&current, &connd, &evt](){
                      current = true;
                      connd++;
                      evt.signal();
                  })
                  .onDisconnect([&current, &discd, &evt](){
                      current = false;
                      discd++;
                      evt.signal();
                  })
                  .exec());

        // wait for connected (may see initial disconnect first)
        while(!current.load()) {
            if(!evt.wait(5.0)) {
                testFail("timeout waiting for connect");
                break;
            }
        }
        testEq(connd.load(), 1u)<<" connected";

        // snapshot disconnect count before forced disconnect
        auto discd_before = discd.load();

        // Disconnect forces immediate sweep + op cancellation
        cli.cacheClear(std::string(), client::Context::Disconnect);

        // wait for disconnect callback
        while(discd.load()==discd_before) {
            if(!evt.wait(5.0)) {
                testFail("timeout waiting for disconnect");
                break;
            }
        }
        testEq(discd.load(), discd_before+1u)<<" disconnected after Disconnect action";

        ctor.reset();
        cli.cacheClear();
    }
};

} // namespace

MAIN(testgc)
{
    testPlan(15);
    testSetup();
    logger_config_env();
    Tester().testCacheCleanMarkSweep();
    Tester().testChannelReuse();
    Tester().testCacheCleanDisconnect();
    cleanup_for_valgrind();
    return testDone();
}
