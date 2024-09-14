/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <list>
#include <atomic>

#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>

#include <pvxs/client.h>
#include <pvxs/log.h>

#include "certfactory.h"
#include "certstatusmanager.h"
#include "p12filefactory.h"

using namespace pvxs;

namespace {

DEFINE_LOGGER(certslog, "pvxs.certs.tool");

void usage(const char* argv0)
{
    std::cerr<<"Usage: "<<argv0<<" <opts> <certid ...>\n       " <<argv0<<" <opts> -f <cert-file> [-p]\n"
               "\n"
               "  -h        Show this message.\n"
               "  -V        Print version and exit.\n"
               "  -v        Make more noise.\n"
               "  -d        Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make a lot of noise.\n"
               "  -w <sec>  Operation timeout in seconds.  default 5 sec.\n"
               "  -# <cnt>  Maximum number of elements to print for each array field.\n"
               "            Set to zero 0 for unlimited.\n"
               "            Default: 20\n"
               "  -f <file> The certificate file to read\n"
               "  -p        Prompt for password\n"
               "  -F <fmt>  Output format mode: delta, tree\n"
               ;
}

}  // namespace

int main(int argc, char *argv[])
{
    try {
        logger_config_env(); // from $PVXS_LOG
        double timeout = 5.0;
        bool verbose = false;
        std::string cert_file, password;
        Value::Fmt::format_t format = Value::Fmt::Delta;
        auto arrLimit = uint64_t(20);

        std::string options;
        options = "hVvdw:f:p:#:F:";
        {
            int opt;
            while ((opt = getopt(argc, argv, options.c_str())) != -1) {
                switch(opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                case 'V':
                    std::cout<<pvxs::version_information;
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
                case 'f':
                    cert_file = optarg;
                    break;
                case 'p':
                    std::getline(std::cin, password);
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
                        log_warn_printf(certslog, "Warning: ignoring unknown format: %s\n", optarg);
                    }
                    break;
                default:
                    usage(argv[0]);
                    log_err_printf(certslog, "\nUnknown argument: `-%c`\n", optopt);
                    return 1;
                }
            }
        }

        client::Context ctxt;
        ctxt = client::Context::fromEnv();

        if(verbose)
            std::cout<<"Effective config\n"<<ctxt.config();

        std::list<std::shared_ptr<client::Operation>> ops;

        std::atomic<int> remaining{argc-optind};
        epicsEvent done;

        if ( !cert_file.empty()) {
            auto cert_data = certs::P12FileFactory::getCertDataFromFile(cert_file, password);
            auto cert_id = certs::CertStatusManager::getStatusPvFromCert(cert_data.cert);
            ops.push_back(ctxt.get(cert_id)
                            .result([cert_id, &done, format, arrLimit](client::Result&& result) {
                                std::cout<<cert_id<<"\n";
                                Indented I(std::cout);
                                std::cout<<result()
                                  .format()
                                  .format(format)
                                  .arrayLimit(arrLimit);
                                done.signal();
                            })
                            .exec());
        } else {
            for(auto n : range(optind, argc)) {
                std::string cert_id = SB() << "CERT:STATUS:" << argv[n];
                ops.push_back(ctxt.get(cert_id)
                                .result([cert_id, &remaining, &done, format, arrLimit](client::Result&& result) {
                                    std::cout<<cert_id<<"\n";
                                    Indented I(std::cout);
                                    std::cout<<result()
                                      .format()
                                      .format(format)
                                      .arrayLimit(arrLimit);

                                    if(remaining.fetch_sub(1)==1)
                                        done.signal();
                                })
                                .exec());
            }
        }

        // expedite search after starting all requests
        ctxt.hurryUp();

        SigInt sig([&done]() {
            done.signal();
        });

        bool waited = done.wait(timeout);
        ops.clear(); // implied cancel

        if(!waited) {
            std::cerr<<"Timeout with "<<remaining.load()<<" outstanding\n";
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
