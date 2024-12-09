/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/** The short example of a client GET operation.
 */

#include <iostream>
#include <thread>

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
    if ( !(argc == 2 || (argc == 3 && std::string(argv[2]) == "-w")) ) {
        std::cout << "Usage: " << argv[0] << " {some:pv:name} [-w]\n";
        return 1;
    }

    auto pv_name = argv[1];
    auto start = std::chrono::high_resolution_clock::now();
    Value reply = ctxt.get(pv_name).exec()->wait(5.0);
    std::cout << reply << std::endl;
    if (argc == 3) {
        while (true) {
            auto end = std::chrono::high_resolution_clock::now();
            auto remaining_time = std::chrono::seconds(3) - (end - start);
            if (remaining_time.count() > 0) {
                std::this_thread::sleep_for(remaining_time);
            }
            start = std::chrono::high_resolution_clock::now();
            reply = ctxt.get(pv_name).exec()->wait(5.0);

            // Reply is printed to stdout.
            std::cout << reply << std::endl;
        }
    }
    return 0;
}
