/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

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

void testEndian(bool srvBE, bool cliBE)
{
    testDiag("%s(%c, %c)", __func__,
             srvBE ? 'B' : 'L',
             cliBE ? 'B' : 'L');

    const auto proto = nt::NTScalar{TypeCode::UInt32}
            .create()
            .update("value", 42);

    auto mbox(server::SharedPV::buildMailbox());

    mbox.open(proto);

    auto srv = server::Config::isolated()
            .overrideSendBE(srvBE)
            .build()
            .addPV("dut", mbox)
            .start();

    auto cli = srv.clientConfig()
            .overrideSendBE(cliBE)
            .build();

    try {
        auto val = cli.get("dut")
                .exec()
                ->wait(5.0);

        testEq(val["value"].as<uint32_t>(), 42u);
    }catch(std::exception& e){
        testFail("Unexpected exception: %s\n", e.what());
    }
}

} // namespace

MAIN(testendian)
{
    testPlan(4);
    testSetup();
    logger_config_env();
    testEndian(false, false);
    testEndian(false, true);
    testEndian(true, false);
    testEndian(true, true);
    cleanup_for_valgrind();
    return testDone();
}
