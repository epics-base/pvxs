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
#include "utilpvt.h"

namespace {
using namespace pvxs;

void dotest()
{
    auto proto(nt::NTScalar{}.create());

    auto server(server::Config::isolated()
                .build());

    std::vector<server::SharedPV> pvs(1000u);

    for(size_t i=0; i<pvs.size(); i++) {
        auto val(proto.cloneEmpty());
        val["value"] = uint64_t(i);

        pvs[i] = server::SharedPV::buildReadonly();
        pvs[i].open(val);

        server.addPV(SB()<<"pv"<<i, pvs[i]);
    }

    server.start();
    testDiag("Server up");

    auto client(server.clientConfig().build());

    std::vector<std::shared_ptr<client::Operation>> ops(pvs.size());

    for(size_t i=0; i<pvs.size(); i++) {
        ops[i] = client.get(SB()<<"pv"<<i)
                .exec();
    }
    testDiag("All ops started");

    client.hurryUp();

    for(size_t i=0; i<pvs.size(); i++) {
        try {
            auto val(ops[i]->wait(30.0)); // CI runner may take a loooong time
            testEq(val["value"].as<uint64_t>(), i)<<" pv"<<i;
        }catch(std::exception& e){
            testTrue(false)<<" pv"<<i<<" : "<<e.what();
        }
    }
}

} // namespace

MAIN(test1000)
{
    testPlan(1000);
    testSetup();
    logger_config_env();
    dotest();
    cleanup_for_valgrind();
    return testDone();
}
