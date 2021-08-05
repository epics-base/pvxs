/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/** The short example of a server.
 */

#include <iostream>

#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

int main(int argc, char* argv[]) {
    using namespace pvxs;

    // (Optional) configuring logging using $PVXS_LOG
    logger_config_env();

    // Use pre-defined NTScalar structure w/ double for primary value field.
    Value initial = nt::NTScalar{TypeCode::Float64}.create();
    initial["value"] = 42.0;

    // Storage and access for network visible Process Variable
    server::SharedPV pv(server::SharedPV::buildMailbox());
    pv.open(initial);

    server::Server::fromEnv()        // Configure a server using $EPICS_PVAS_* or $EPICS_PVA_*
            .addPV("my:pv:name", pv) // add (and name) one local PV
            .run();                  // run until SIGINT

    return 0;
}
