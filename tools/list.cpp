/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <sstream>
#include <map>
#include <set>
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
    std::cerr<<
            "Usage:\n"
            "  Discover Servers:\n"
            "    "<<argv0<<" [options]\n"
            "\n"
            "  List PVs:\n"
            "    "<<argv0<<" [options] <IP[:Port] ...>\n"
            "\n"
            "  Server Info:\n"
            "    "<<argv0<<" [options] -i <IP[:Port] ...>\n"
            "\n"
            "Examples:\n"
            "  Monitor server beacons to detect servers coming online, and going offline.\n"
            "   "<<argv0<<" -w 0 -v\n"
            "\n"
            "  List all PV names.  (Warning: high network load)\n"
            "   "<<argv0<<" $("<<argv0<<" -w 5)\n"
            "\n"
            "  -h        Show this message.\n"
            "  -V        Print version and exit.\n"
            "  -A        Active discovery mode (default).  Send broadcast ping, then continue\n"
            "            listening for Beacons.\n"
            "            Warning: Active discovery pings result in a lot of network traffic.\n"
            "  -p        Passive discovery mode.  Only listen for server Beacons.\n"
            "  -i        Query server info.  Requires address(es)\n"
            "  -v        Make more noise.\n"
            "  -d        Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make a lot of noise.\n"
            "  -w <sec>  Operation timeout in seconds.  Default 5 sec.  '0' disables timeout,\n"
            "            useful in combination with '-v'.\n"
            ;
}

} // namespace

int main(int argc, char *argv[])
{
    try {
        logger_config_env(); // from $PVXS_LOG
        double timeout = 5.0;
        bool verbose = false;
        bool info = false;
        bool active = true;

        {
            int opt;
            while ((opt = getopt(argc, argv, "hVApivdw:")) != -1) {
                switch(opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                case 'V':
                    std::cout<<pvxs::version_information;
                    return 0;
                case 'A':
                    active = true;
                    break;
                case 'p':
                    active = false;
                    break;
                case 'i':
                    info = true;
                    break;
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

        if(info && optind==argc) {
            usage(argv[0]);
            std::cerr<<"\nError: -i requires at least one server"<<std::endl;
            return 1;
        }

        auto ctxt(client::Context::fromEnv());
        auto conf = ctxt.config();

        epicsEvent done;
        SigInt H([&done]() {
            done.signal();
        });

        std::vector<std::shared_ptr<client::Operation>> ops;
        ops.reserve(argc-optind);

        if(optind==argc) { // discover mode, search of all servers
            std::set<std::pair<ServerGUID, std::string>> servprotos;

            ops.push_back(ctxt.discover([servprotos, verbose](const client::Discovered& serv) mutable {
                if(verbose) { // print all events and info
                    std::cout<<serv<<std::endl;

                } else if(serv.proto=="tcp") { // print only new TCP server endpoints
                    const auto key(std::make_pair(serv.guid, serv.proto));

                    if(serv.event==client::Discovered::Timeout) {
                        servprotos.erase(key);

                    } else if(servprotos.find(key)!=servprotos.end()) {
                        /* Previously listed server and protocol, through different interface.
                         * we arbitrarily print just one interface on the theory that the list
                         * of servers is being piped back to fetch a list of PVs
                         */

                    } else {
                        servprotos.insert(key);
                        std::cout<<serv.server<<std::endl;
                    }
                }
            })
                          .pingAll(active)
                          .exec());

        } else { // query mode, fetch info from specific servers

            std::atomic<int> remaining{argc-optind};

            for(auto n : range(optind, argc)) {
                ops.push_back(ctxt.rpc("server")
                              .server(argv[n])
                              .arg("op", info ? "info" : "channels")
                              .result([argv, n, info, verbose, &remaining, &done](client::Result&& r)
                      {
                          try {
                              auto top(r());

                              if(info) {
                                  std::cout<<argv[n];
                                  std::string temp;
                                  if(top["version"].as(temp)) {
                                      std::cout<<" version=\""<<escape(temp)<<"\"";
                                  };
                                  if(top["implLang"].as(temp)) {
                                      std::cout<<" lang=\""<<escape(temp)<<"\"";
                                  };
                                  std::cout<<"\n";

                              } else { // channels
                                  if(verbose)
                                      std::cout<<"# From "<<argv[n]<<"\n";

                                  auto channels(top["value"].as<shared_array<const std::string>>());
                                  for(auto& name : channels) {
                                      std::cout<<name<<"\n";
                                  }
                              }
                              std::cout.flush();
                          }catch(std::exception& e){
                              std::cerr<<"From "<<argv[n]<<" : "<<e.what()<<std::endl;
                          }

                          if(0==--remaining) {
                              done.signal();
                          }
                      })
                              .exec());
            }
        }

        if(timeout>0.0)
            done.wait(timeout);
        else
            done.wait();

        return 0;

    }catch(std::exception& e){
        std::cerr<<"Error: "<<e.what()<<"\n";
        return 1;
    }
}
