/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/** Meant to be run against the mailbox example.
 *  eg. in one terminal run:
 *
 *   ./mailbox some:pv:name
 *
 * And in another terminal run:
 *
 *   ./client some:pv:name
 */

#include <iostream>

#include <pvxs/client.h>
#include <pvxs/log.h>

using namespace pvxs;

int main(int argc, char* argv[])
{
    if(argc<2) {
        std::cerr<<"Usage: "<<argv[0]<<" <pvname>\n";
        return 1;
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_config_env();

    // Create a client context
    auto ctxt(client::Context::fromEnv());

    // Fetch current value
    int32_t current;
    {
        std::cout<<"Getting current value of '"<<argv[1]<<"'"<<std::endl;
        // Build and start network operation
        auto op = ctxt.get(argv[1])
                .exec();

        // wait for it to complete, for up to 5 seconds.
        Value result = op->wait(5.0);

        std::cout<<"Result is:\n"<<result<<std::endl;

        if(auto value = result["value"]) {
            // there is a .value field
            // as may still throw pvxs::NoConvert if its value can't
            // be converted to int32_t
            current = value.as<int32_t>();
        } else {
            // an example.  won't happen with mailbox server
            std::cerr<<"Server type doesn't have .value field!\n";
            return 1;
        }
    }

    {
        // attempt to change.
        // uses simple builder form to assign .value

        ctxt.put(argv[1])
                .set("value", current+1)
                .exec()
                ->wait(5.0);

        std::cout<<"First increment successful"<<std::endl;
    }

    {
        // change again.
        // use build() callback

        auto op = ctxt.put(argv[1])
                // provide present value to build() callback.
                .fetchPresent(true)
                .build([](Value&& current) -> Value {
                    // allocate an empty container
                    auto toput(current.cloneEmpty());

                    // fill in .value.
                    // Assignment implicitly marks .value as changed
                    toput["value"] = current["value"].as<int32_t>() + 1;

                    // return the container to be sent
                    return toput;
                })
                .exec();

        op->wait(5.0);

        std::cout<<"Second increment successful"<<std::endl;
    }

    // fetch final value
    {
        std::cout<<"Getting current value of '"<<argv[1]<<"'"<<std::endl;
        // Build and start network operation
        auto result = ctxt.get(argv[1])
                .exec()
                ->wait(5.0);

        std::cout<<"Result is:\n"<<result<<std::endl;
    }

    return 0;
}
