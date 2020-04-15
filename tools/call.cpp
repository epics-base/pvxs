/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <map>
#include <list>
#include <atomic>

#include <epicsVersion.h>
#include <epicsGetopt.h>
#include <epicsThread.h>

#include <pvxs/client.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>
#include "utilpvt.h"
#include "evhelper.h"

using namespace pvxs;

namespace {

void usage(const char* argv0)
{
    std::cerr<<"Usage: "<<argv0<<" <opts> <pvname> <fld>=<value> ...\n"
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

        if(optind==argc) {
            usage(argv[0]);
            std::cerr<<"\nExpected PV name\n";
            return 1;
        }

        std::string pvname(argv[optind++]);
        std::list<std::string> keys;
        std::map<std::string, std::string> values;

        for(auto n : range(optind, argc)) {
            std::string fv(argv[n]);
            auto sep = fv.find_first_of('=');

            if(sep==std::string::npos) {
                std::cerr<<"Error: expected <fld>=<value> not \""<<escape(fv)<<"\"\n";
                return 1;
            }

            auto key(fv.substr(0, sep));

            if(values.find(key)!=values.end()) {
                std::cerr<<"Error: duplicate argument name "<<key<<"\n";
                return 1;
            }

            values[key] = fv.substr(sep+1);
            keys.push_back(key);
        }

        auto uri = nt::NTURI({}).build();

        for(auto& key : keys) {
            using namespace pvxs::members;

            uri += {Struct("query", {String(key)})};
        }

        auto arg = uri.create();
        arg["path"] = pvname;
        auto query = arg["query"];

        for(auto& pair : values) {
            query[pair.first] = pair.second;
        }

        auto ctxt = client::Config::from_env().build();

        if(verbose)
            std::cout<<"Effective config\n"<<ctxt.config();

        epicsEvent done;
        int ret=2;

        auto op =ctxt.rpc(pvname, std::move(arg))
                     .result([&ret, &done](client::Result&& result) {
            try {
                auto val = result();
                if(val)
                    std::cout<<val;
                ret=0;
            }catch(std::exception& e){
                std::cerr<<"Error "<<typeid(e).name()<<" : "<<e.what()<<"\n";
                ret=1;
            }
            done.signal();
        })
                .exec();

        // expedite search after starting all requests
        ctxt.hurryUp();

        SigInt sig([&done]() {
            done.signal();
        });

        if(!done.wait(timeout)) {
            std::cerr<<"Timeout\n";
            return 1;
        } else {
            return ret;
        }
    }catch(std::exception& e){
        std::cerr<<"Error: "<<e.what()<<"\n";
        return 1;
    }
}
