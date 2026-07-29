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

void testSpam(uint32_t nQueue, uint32_t highMark, uint16_t lastVal)
{
    testShow()<<__func__<<" nQueue="<<nQueue<<" highMark="<<highMark<<" lastVal="<<lastVal;

    auto src(std::make_shared<Spammer>());

    auto srv(server::Config::isolated().build()
            .addSource("dut", std::make_shared<Spammer>())
            .start());

    auto cli(srv.clientConfig().build());

    epicsEvent wait;
    auto mon(cli.monitor("spam")
             .record("highMark", highMark)
             .record("queueSize", nQueue)
             .record("lastVal", lastVal)
             .record("pipeline", true)
             .maskConnected(true)
             .maskDisconnected(true)
             .event([&wait](client::Subscription&){
                 wait.signal();
             })
             .exec());

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
    testPlan(99);
    testSetup();
    logger_config_env();
    testSpam(3u, 0u, 7u);
    testSpam(2u, 0u, 5u);
    testSpam(4u, 0u, 9u);
    testSpam(4u, 0u, 10u);
    testSpam(4u, 1u, 10u);
    testSpam(4u, 2u, 10u);
    testSpam(4u, 3u, 10u);
    testSpam(4u, 4u, 10u);
    testSpam(4u, 6u, 10u);
    logger_config_env();
    cleanup_for_valgrind();
    return testDone();
}
