/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>

#include <pvxs/sharedpv.h>
#include <pvxs/server.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

using namespace pvxs;

int main(int argc, char* argv[])
{
    if(argc<=1) {
        std::cerr<<"Usage: "<<argv[0]<<" <pvname>\n";
        return 1;
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg. PVXS_LOG=*=DEBUG makes
    // a lot of noise.
    logger_config_env();

    // Must provide a data type for the mailbox
    Value initial = nt::NTScalar{TypeCode::Float64}.create();
    // (optional) Provide an initial value
    initial["value"] = 42.0;
    initial["alarm.severity"] = 0;
    initial["alarm.status"] = 0;
    initial["alarm.message"] = "";

    // Actually creating the mailbox PV.
    // buildMailbox() includes a default PUT handler which simply
    // stores whatever a client sends (subject to our data type).
    server::SharedPV pv(server::SharedPV::buildMailbox());
    // Associate a data type (and maybe initial value) with this PV
    pv.open(initial);

    // Build server which will server this PV
    auto serv = server::Config::from_env()
            .build()
            .addPV(argv[1], pv);

    // (optional) Print the configuration this server is using
    // with any auto-address list expanded.
    std::cout<<"Effective config\n"<<serv.config();

    // Start server and run forever, or until Ctrl+c is pressed.
    // Returns on SIGINT or SIGTERM
    serv.run();

    return 0;
}
