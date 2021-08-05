/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * Serves a single PV name.
 * Only implements an RPC operation which adds two numbers.
 *
 *   ./rpc_server mypv
 *
 * Then in another shell run:
 *
 *   pvxcall mypv lhs=1 rhs=2
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
        std::cerr<<"Usage: "<<argv[0]<<" <pvname>\n";
        return 1;
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_config_env();

    // Actually creating the PV.
    // buildReadonly() installs a default onPut() handler which
    // rejects all Put operations.
    server::SharedPV pv(server::SharedPV::buildReadonly());

    // Provide an RPC handler
    pv.onRPC([](server::SharedPV& pv,
                std::unique_ptr<server::ExecOp>&& op,
                Value&& top)
    {
        // Callback

        // assume arguments encoded NTURI
        auto rhs = top["query.rhs"].as<double>();
        auto lhs = top["query.lhs"].as<double>();

        auto reply(nt::NTScalar{TypeCode::Float64}.create());
        reply["value"] = lhs + rhs;

        op->reply(reply);
        // Scale-able applications may reply outside of this callback,
        // and from another thread.
    });

    // (Optional) Provide a data type for the PV.
    // Provides a hint to users that Get, Put, or Monitor is not
    // meaningful for this PV
    Value initial = nt::NTScalar{TypeCode::String}.create();
    initial["value"] = "RPC only";
    pv.open(initial);

    // Build server which will serve this PV
    // Configure using process environment.
    server::Server serv = server::Server::fromEnv()
            .addPV(argv[1], pv);

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
