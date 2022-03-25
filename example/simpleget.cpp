/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/** The short example of a client GET operation.
 */

#include <iostream>

#include <pvxs/client.h>
#include <pvxs/log.h>

int main(int argc, char* argv[]) {
    using namespace pvxs;

    // (Optional) configuring logging using $PVXS_LOG
    logger_config_env();

    // Configure client using $EPICS_PVA_*
    auto ctxt(client::Context::fromEnv());

    // fetch PV "some:pv:name" and wait up to 5 seconds for a reply.
    // (throws an exception on error, including timeout)
    Value reply = ctxt.get("some:pv:name").exec()->wait(5.0);

    // Reply is printed to stdout.
    std::cout<<reply;

    return 0;
}
