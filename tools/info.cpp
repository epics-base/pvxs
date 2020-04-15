/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <list>
#include <atomic>

#include <epicsVersion.h>
#include <epicsGetopt.h>
#include <epicsThread.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include "utilpvt.h"
#include "evhelper.h"

using namespace pvxs;

namespace {

void usage(const char* argv0)
{
    std::cerr<<"Usage: "<<argv0<<" <opts> [pvname ...]\n"
               "\n"
               "  -h        Show this message.\n"
               "  -V        Print version and exit.\n"
               "  -v        Make more noise.\n"
               "  -d        Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make a lot of noise.\n"
               "  -w <sec>  Operation timeout in seconds.  default 5 sec.\n"
               ;
}

}

int main(int argc, char *argv[])
{
    try {
        logger_config_env(); // from $PVXS_LOG
        double timeout = 5.0;
        bool verbose = false;

        {
            int opt;
            while ((opt = getopt(argc, argv, "hVvdw:")) != -1) {
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
                    break;
                case 'd':
                    logger_level_set("pvxs.*", Level::Debug);
                    break;
                case 'w':
                    timeout = parseTo<double>(optarg);
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

        std::list<std::shared_ptr<client::Operation>> ops;

        std::atomic<int> remaining{argc-optind};
        epicsEvent done;

        for(auto n : range(optind, argc)) {

            ops.push_back(ctxt.info(argv[n])
                          .result([&argv, n, &remaining, &done](client::Result&& result) {
                              std::cout<<argv[n];
                              try {
                                  std::cout<<" from "<<result.peerName()<<"\n"<<result()
                                             .format()
                                             .showValue(false);
                              }catch(std::exception& e){
                                  std::cout<<" Error: "<<e.what()<<"\n";
                              }

                              if(remaining.fetch_sub(1)==1)
                                  done.signal();
                          })
                          .exec());
        }

        // expedite search after starting all requests
        ctxt.hurryUp();

        SigInt sig([&done]() {
            done.signal();
        });

        if(!done.wait(timeout)) {
            std::cerr<<"Timeout\n";
            return 1;
        } else if(remaining.load()==0u) {
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
