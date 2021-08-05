/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * Serves a single PV name.
 * Any updates written (PUT) to this PV will be stored verbatim
 * and sent to any subscribers.
 */

#include <iostream>

#include <epicsTime.h>

#include <pvxs/sharedpv.h>
#include <pvxs/server.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

using namespace pvxs;

int main(int argc, char* argv[])
{
    if(argc<=1) {
        std::cerr<<"Usage: "<<argv[0]<<" <pvname> [pvname1 [...]]\n";
        return 1;
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_config_env();

    // Must provide a data type for the mailbox.
    // Use pre-canned definition of scalar with meta-data
    Value initial = nt::NTScalar{TypeCode::Float64}.create();

    // (optional) Provide an initial value
    initial["value"] = 42.0;
    initial["alarm.severity"] = 0;
    initial["alarm.status"] = 0;
    initial["alarm.message"] = "";

    std::vector<server::SharedPV> pvs(argc-1u);

    for(size_t i=0ul; i<pvs.size(); i++) {
        // Actually creating a mailbox PV.
        // buildMailbox() installs a default onPut() handler which
        // stores whatever a client sends (subject to our data type).
        server::SharedPV pv(server::SharedPV::buildMailbox());

        // (optional) Replace the default PUT handler to do a range check
        pv.onPut([](server::SharedPV& pv,
                 std::unique_ptr<server::ExecOp>&& op,
                 Value&& top)
         {

             // (optional) arbitrarily clip value to [-100.0, 100.0]
             double val(top["value"].as<double>());
             if(val<-100.0)
                 top["value"] = -100.0;
             else if(val>100.0)
                 top["value"] = 100.0;

             // (optional) Provide a timestamp if the client has not (common)
             Value ts(top["timeStamp"]);
             if(!ts.isMarked(true, true)) {
                 // use current time
                 epicsTimeStamp now;
                 if(!epicsTimeGetCurrent(&now)) {
                     ts["secondsPastEpoch"] = now.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH;
                     ts["nanoseconds"] = now.nsec;
                 }
             }

             // (optional) update the SharedPV cache and send
             // a update to any subscribers
             pv.post(top);

             // Required.  Inform client that PUT operation is complete.
             op->reply();
         });

        // Associate a data type (and maybe initial value) with this PV
        pv.open(initial);

        pvs[i] = std::move(pv);
    }

    // Build server which will serve this PV
    // Configure using process environment.
    auto serv(server::Server::fromEnv());

    for(size_t i=0ul; i<pvs.size(); i++) {
        serv.addPV(argv[i+1], pvs[i]);
    }

    // (optional) Print the configuration this server is using
    // with any auto-address list expanded.
    std::cout<<"Effective config\n"<<serv.config();

    std::cout<<"Running\n";

    // Start server and run forever, or until Ctrl+c is pressed.
    // Returns on SIGINT or SIGTERM
    serv.run();

    std::cout<<"Done\n";

    return 0;
}
