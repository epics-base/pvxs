/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * Serves a single integer PV which increments at a pre-defined rate.
 */

#include <iostream>
#include <stdexcept>
#include <string>

#include <cstring>

#include <epicsTime.h>
#include <epicsEvent.h>

#include <pvxs/sharedpv.h>
#include <pvxs/server.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>
#include <pvxs/util.h>

using namespace pvxs;

int main(int argc, char* argv[])
{
    double delay = 1.0;

    if(argc<=1) {
        std::cerr<<"Usage: "<<argv[0]<<" <pvname> [rateHz]\n";
        return 1;
    }

    if(argc>=3) {
        try {
            size_t idx=0;
            delay = 1.0/std::stod(argv[2], &idx);
            if(idx<std::strlen(argv[2]))
                throw std::invalid_argument("Extraneous charactors");
        }catch(std::exception& e){
            std::cerr<<"Error parsing rate: "<<e.what()<<"\n";
            return 1;

        }
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_config_env();

    // Must provide a data type for the mailbox.
    // Use pre-canned definition of scalar with meta-data
    Value initial = nt::NTScalar{TypeCode::UInt32}.create();

    // (optional) Provide an initial value
    initial["value"] = 0u;
    initial["alarm.severity"] = 0;
    initial["alarm.status"] = 0;
    initial["alarm.message"] = "";

    // Actually creating the mailbox PV.
    // buildMailbox() installs a default onPut() handler which
    // stores whatever a client sends (subject to our data type).
    server::SharedPV pv(server::SharedPV::buildReadonly());

    // Associate a data type (and maybe initial value) with this PV
    pv.open(initial);

    // Build server which will server this PV
    // Configure using process environment.
    server::Server serv = server::Config::from_env()
            .build()
            .addPV(argv[1], pv);

    // (optional) Print the configuration this server is using
    // with any auto-address list expanded.
    std::cout<<"Effective config\n"<<serv.config();

    // event used to signal exit, and for delay timer
    epicsEvent done;

    // connect to SIGINT/SIGTERM to break from main loop
    SigInt handle([&done]() {
        done.signal();
    });

    // Start server in background
    serv.start();

    std::cout<<"Running\n";

    uint32_t count = 0u;

    while(!done.wait(delay)) {
        auto val = initial.cloneEmpty();

        val["value"] = count++;

        pv.post(std::move(val));

        std::cout<<"Count "<<count<<"\n";
    }

    // (optional) explicitly stop server.
    // Implied when 'serv' goes out of scope
    serv.stop();

    std::cout<<"Done\n";

    return 0;
}
