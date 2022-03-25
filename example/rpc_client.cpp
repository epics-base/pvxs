/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * Run in conjunction with the rpc_server example
 *
 *   ./rpc_server mypv
 *
 * Then in another shell run:
 *
 *   ./rpc_client mypv 1 2
 */

#include <iostream>

#include <pvxs/client.h>
#include <pvxs/log.h>

using namespace pvxs;

int main(int argc, char* argv[])
{
    if(argc<4) {
        std::cerr<<"Usage: "<<argv[0]<<" <pvname> <lhs> <rhs>\n";
        return 1;
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_config_env();

    // Create a client context
    auto ctxt(client::Context::fromEnv());

    auto reply(ctxt.rpc(argv[1])
                   .arg("lhs", argv[2])
                   .arg("rhs", argv[3])
                   .exec()
                   ->wait(5.0));

    std::cout<<"Reply\n"<<reply;

    return 0;
}
