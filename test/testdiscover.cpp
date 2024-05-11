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
#include "evhelper.h"

namespace {
using namespace pvxs;

void testBeacon()
{
    testShow()<<__func__;

    auto serv(server::Config::isolated().build());
    auto guid(serv.config().guid);
    auto cli(serv.clientConfig().build());

    MPMCFIFO<client::Discovered> q1;
    auto op1(cli.discover([&q1](const client::Discovered& evt){
        testDiag("Event");
        q1.push(evt);
    }).pingAll(false).exec());

    serv.start();

    MPMCFIFO<client::Discovered> q2;
    auto op2(cli.discover([&q2](const client::Discovered& evt){
        testDiag("Event");
        q2.push(evt);
    }).pingAll(true).exec());

    testDiag("Waiting for discoveries");
    {
        auto evt(q1.pop());
        testEq(evt.event, client::Discovered::Online);
        testEq(evt.guid, guid);
    }
    {
        auto evt(q2.pop());
        testEq(evt.event, client::Discovered::Online);
        testEq(evt.guid, guid);
    }

    serv.stop();

    testDiag("Wait for timeouts");
    {
        auto evt(q1.pop());
        testEq(evt.event, client::Discovered::Timeout);
        testEq(evt.guid, guid);
    }
    {
        auto evt(q2.pop());
        testEq(evt.event, client::Discovered::Timeout);
        testEq(evt.guid, guid);

    }
}

} // namespace

MAIN(testdiscover)
{
    testPlan(8);
    logger_config_env();
    testSetup();
    testBeacon();
    logger_config_env();
    cleanup_for_valgrind();
    return testDone();
}
