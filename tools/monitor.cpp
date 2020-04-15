/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <list>
#include <atomic>

#include <cstring>

#include <epicsVersion.h>
#include <epicsGetopt.h>
#include <epicsThread.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include "utilpvt.h"
#include "evhelper.h"

using namespace pvxs;

namespace {

DEFINE_LOGGER(app, "app");

void usage(const char* argv0)
{
    std::cerr<<"Usage: "<<argv0<<" <opts> [pvname ...]\n"
               "\n"
               "  -h        Show this message.\n"
               "  -V        Print version and exit.\n"
               "  -r <req>  pvRequest condition.\n"
               "  -v        Make more noise.\n"
               "  -d        Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make a lot of noise.\n"
               "  -# <cnt>  Maximum number of elements to print for each array field.\n"
               "            Set to zero 0 for unlimited.\n"
               "            Default: 20\n"
               "  -F <fmt>  Output format mode: delta, tree\n"
               ;
}

}

int main(int argc, char *argv[])
{
    try {
        logger_config_env(); // from $PVXS_LOG
        bool verbose = false;
        std::string request;
        Value::Fmt::format_t format = Value::Fmt::Delta;
        auto arrLimit = uint64_t(-1);

        {
            int opt;
            while ((opt = getopt(argc, argv, "hVvdr:#:F:")) != -1) {
                switch(opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                case 'V':
                    std::cout<<version_str()<<"\n";
                    std::cout<<EPICS_VERSION_STRING<<"\n";
                    std::cout<<"libevent "<<event_get_version()<<"\n";
                    return 0;
                case 'v':
                    verbose = true;
                    logger_level_set("app", Level::Debug);
                    break;
                case 'd':
                    logger_level_set("pvxs.*", Level::Debug);
                    break;
                case 'r':
                    request = optarg;
                    break;
                case '#':
                    arrLimit = parseTo<uint64_t>(optarg);
                    break;
                case 'F':
                    if(std::strcmp(optarg, "tree")==0) {
                        format = Value::Fmt::Tree;
                    } else if(std::strcmp(optarg, "delta")==0) {
                        format = Value::Fmt::Delta;
                    } else {
                        std::cerr<<"Warning: ignoring unknown format '"<<optarg<<"'\n";
                    }
                    break;
                default:
                    usage(argv[0]);
                    std::cerr<<"\nUnknown argument: "<<char(opt)<<std::endl;
                    return 1;
                }
            }
        }

        auto ctxt = client::Config::from_env().build();

        if(verbose)
            std::cout<<"Effective config\n"<<ctxt.config();

        std::list<std::shared_ptr<client::Subscription>> ops;

        std::atomic<int> remaining{argc-optind};
        epicsEvent done;

        for(auto n : range(optind, argc)) {

            ops.push_back(ctxt.monitor(argv[n])
                          .pvRequest(request)
                          .event([&argv, n, verbose, &remaining, &done, format, arrLimit](client::Subscription& mon)
            {

                try {
                    while(auto update = mon.pop()) {
                        log_info_printf(app, "%s POP data\n", argv[n]);
                        std::cout<<argv[n]<<"\n"<<update.format()
                                   .format(format)
                                   .arrayLimit(arrLimit);
                    }
                    log_info_printf(app, "%s POP empty\n", argv[n]);

                }catch(client::Finished& conn) {
                    log_info_printf(app, "%s POP Finished\n", argv[n]);
                    if(verbose)
                        std::cerr<<argv[n]<<" Finished\n";
                    if(remaining.fetch_sub(1)==1)
                        done.signal();

                }catch(client::Connected& conn) {
                    std::cerr<<argv[n]<<" Connected to "<<conn.peerName<<"\n";

                }catch(client::Disconnect& conn) {
                    std::cerr<<argv[n]<<" Disconnected\n";

                }catch(std::exception& err) {
                    std::cerr<<argv[n]<<" Error "<<typeid (err).name()<<" : "<<err.what()<<"\n";
                }

            }).exec());
        }

        // expedite search after starting all requests
        ctxt.hurryUp();

        SigInt sig([&done]() {
            done.signal();
        });

        done.wait();

        if(remaining.load()==0u) {
            return 0;

        } else {
            if(verbose)
                std::cerr<<"Interrupted\n";
            return 2;
        }
    }catch(std::exception& e){
        std::cerr<<"Error: "<<e.what()<<"\n";
        return 1;
    }
}
