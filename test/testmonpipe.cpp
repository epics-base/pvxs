/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>

#include <string.h>

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

struct Spammer : public server::Source {
    Value prototype;

    Spammer()
        :prototype(nt::NTScalar{TypeCode::UInt16}.create())
    {}

    virtual void onSearch(Search &op) override final {
        for(auto& pv : op) {
            if(strcmp(pv.name(), "spam")==0)
                pv.claim();
        }
    }

    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&rop) override final {
        if(rop->name()!="spam")
            return;

        auto op(std::move(rop));

        auto ptype(prototype);
        op->onSubscribe([ptype](std::unique_ptr<server::MonitorSetupOp>&& mop) {

            uint32_t highMark = 0u;
            mop->pvRequest()["record._options.highMark"].as(highMark);

            uint16_t lastVal = 10u;
            mop->pvRequest()["record._options.lastVal"].as(lastVal);

            struct SpamCounter {
                std::unique_ptr<server::MonitorControlOp> mctrl;
                Value prototype;
                uint16_t nextCnt = 0u;
                uint16_t lastVal;

                void push() {
                    testDiag("Wakeup");
                    // assume there is at least one free slot in the queue
                    while(nextCnt < lastVal) {
                        testDiag("Push %u", unsigned(nextCnt));
                        auto next(prototype.cloneEmpty());
                        next["value"] = nextCnt++;
                        if(mctrl->tryPost(next)) {
                            // There are more empty slots
                        } else {
                            // queue is now (over)full
                            break;
                        }
                    }
                    if(nextCnt == lastVal) {
                        mctrl->finish();
                        testDiag("finish()");
                        nextCnt++;
                    } else if(nextCnt > lastVal) {
                        testTrue(false)<<" Excessive wakeups "<<nextCnt<<" / "<<lastVal;
                    }
                }
            };
            auto counter(std::make_shared<SpamCounter>());

            counter->prototype = ptype;
            counter->lastVal = lastVal;
            counter->mctrl = mop->connect(ptype);
            counter->mctrl->setWatermarks(0u, highMark);

            counter->mctrl->onHighMark([counter](){ counter->push(); });

            counter->push(); // initial fill
        });
    }
};

// Source which, on subscribe, fills the queue past its limit using post()
// (which squashes when full) before the subscription is started, then captures
// the server-side MonitorStat for inspection.  Used to regression test that
// stats() reports the queue depth in nQueue and the squash count in nSquash,
// rather than overwriting nQueue with the squash count.
struct StatSquash : public server::Source {
    const Value prototype;
    const uint32_t nPost;

    epicsEvent captured;
    server::MonitorStat stat{};
    std::shared_ptr<server::MonitorControlOp> keepalive;

    explicit StatSquash(uint32_t nPost)
        :prototype(nt::NTScalar{TypeCode::UInt32}.create())
        ,nPost(nPost)
    {}

    virtual void onSearch(Search &op) override final {
        for(auto& pv : op) {
            if(strcmp(pv.name(), "sq")==0)
                pv.claim();
        }
    }

    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&rop) override final {
        if(rop->name()!="sq")
            return;
        auto op(std::move(rop));
        auto ptype(prototype);
        op->onSubscribe([this, ptype](std::unique_ptr<server::MonitorSetupOp>&& mop) {
            // The subscription is created stopped, so nothing is sent and the
            // queue is never drained while this callback runs (START is
            // processed only after we return on the same acceptor loop).
            std::shared_ptr<server::MonitorControlOp> ctrl(mop->connect(ptype));
            for(uint32_t i=0; i<nPost; i++) {
                auto next(ptype.cloneEmpty());
                next["value"] = i; // distinct value each time so the update is "real"
                ctrl->post(next);
            }
            ctrl->stats(stat);
            keepalive = ctrl; // keep the subscription alive past this callback
            captured.signal();
        });
    }
};

void testStatsSquash()
{
    testShow()<<__func__;

    // queueSize 4, post 10 -> first 4 fill the queue, remaining 6 squash.
    auto src(std::make_shared<StatSquash>(10u));

    auto srv(server::Config::isolated().build()
            .addSource("dut", src)
            .start());

    auto cli(srv.clientConfig().build());

    auto mon(cli.monitor("sq")
                 .record("queueSize", 4u)
                 .maskConnected(true)
                 .maskDisconnected(true)
                 .event([](client::Subscription&){})
                 .exec());

    if(!src->captured.wait(5.0)) {
        testFail("server onSubscribe never ran");
        testSkip(3, "no stats captured");
        return;
    }

    testEq(src->stat.limitQueue, 4u)<<" negotiated queueSize";
    testEq(src->stat.nQueue, 4u)<<" nQueue must be the queue depth, not the squash count";
    testEq(src->stat.nSquash, 6u)<<" nSquash must carry the squash count";
    testEq(src->stat.maxQueue, 4u)<<" high-water queue depth";
}

void testSpam(uint32_t nQueue, uint32_t highMark, uint16_t lastVal,
              const std::string& ackAny="")
{
    testShow()<<__func__<<" nQueue="<<nQueue<<" highMark="<<highMark<<" lastVal="<<lastVal;

    auto src(std::make_shared<Spammer>());

    auto srv(server::Config::isolated().build()
            .addSource("dut", std::make_shared<Spammer>())
            .start());

    auto cli(srv.clientConfig().build());

    epicsEvent wait;
    std::shared_ptr<client::Subscription> mon;
    {
        auto b(cli.monitor("spam")
                   .record("highMark", highMark)
                   .record("queueSize", nQueue)
                   .record("lastVal", lastVal)
                   .record("pipeline", true)
                   .maskConnected(true)
                   .maskDisconnected(true)
                   .event([&wait](client::Subscription&){
                       wait.signal();
                   }));
        if(!ackAny.empty()) {
            b.record("ackAny", ackAny);
        }
        mon = b.exec();
    }

    uint16_t expected = 0u;
    while(true) {
        try {
            if(auto val = mon->pop()) {
                testEq(val["value"].as<uint16_t>(), expected++);
            } else {
                if(!wait.wait(5.0)) {
                    testFail("client timeout");
                    break;
                }
            }
        }catch(client::Finished&){
            testPass("Finished");
            break;
        }
    }
    testEq(expected, lastVal)<<" after Finish";
}

} // namespace

MAIN(testmonpipe)
{
    testPlan(115);
    testSetup();
    logger_config_env();
    testStatsSquash();
    testSpam(3u, 0u, 7u);
    testSpam(2u, 0u, 5u);
    testSpam(4u, 0u, 9u);
    testSpam(4u, 0u, 10u);
    testSpam(4u, 1u, 10u);
    testSpam(4u, 2u, 10u);
    testSpam(4u, 3u, 10u);
    testSpam(4u, 4u, 10u);
    testSpam(4u, 6u, 10u);
    testSpam(4u, 6u, 10u, "50%");
    logger_config_env();
    cleanup_for_valgrind();
    return testDone();
}
