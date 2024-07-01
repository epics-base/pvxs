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
    std::cerr<<"Usage: "<<argv0
              <<" <opts> [pvname ...]\n"
                "\n"
                "  -h        Show this message.\n"
                "  -V        Print version and exit.\n"
                "  -r <request>  pvRequest condition.\n"
                "  -v        Make more noise.\n"
                "  -d        Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\".  Make "
                "a lot of noise.\n"
                "  -w <sec>  Operation timeout in seconds.  default 5 sec.\n"
                "  -# <cnt>  Maximum number of elements to print for each "
                "array field.\n"
                "            Set to zero 0 for unlimited.\n"
                "            Default: 20\n"
                "  -F <fmt>  Output format mode: delta, tree\n"
#ifdef PVXS_ENABLE_JWT_AUTH
                 "  -t <token_file>  JWT token file e.g. ~/.jwt/token\n"
#endif
        ;
}

#ifdef PVXS_ENABLE_JWT_AUTH
std::string getFileContents(const std::string& filename) {
    std::ifstream fileStream(filename);
    if (!fileStream) {
        std::cerr << "Token file could not be opened: " << filename << std::endl;
        return std::string();
    }

    std::stringstream stringStream;
    stringStream << fileStream.rdbuf();

    std::string str = stringStream.str();
    str.erase(std::remove_if(str.begin(), str.end(), [](unsigned char c) { return std::isspace(c); }), str.end());

    return str;
}
#endif

}  // namespace

int main(int argc, char* argv[]) {
    try {
        logger_config_env();  // from $PVXS_LOG
        double timeout = 5.0;
        bool verbose = false;
        std::string request;
        Value::Fmt::format_t format = Value::Fmt::Delta;
        auto arrLimit = uint64_t(-1);

        std::string options;
#ifdef PVXS_ENABLE_JWT_AUTH
        std::string jwt_token;
        options = "hVvdw:r:#:F:t:";
#else
        options = "hVvdw:r:#:F:";
#endif
        {
            int opt;
            while ((opt = getopt(argc, argv, options.c_str())) != -1) {
                switch (opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                case 'V':
                    std::cout << pvxs::version_information;
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
                case 'r':
                    request = optarg;
                    break;
                case '#':
                    arrLimit = parseTo<uint64_t>(optarg);
                    break;
                case 'F':
                    if (std::strcmp(optarg, "tree") == 0) {
                        format = Value::Fmt::Tree;
                    } else if (std::strcmp(optarg, "delta") == 0) {
                        format = Value::Fmt::Delta;
                    } else {
                        std::cerr << "Warning: ignoring unknown format '" << optarg << "'\n";
                    }
                    break;
#ifdef PVXS_ENABLE_JWT_AUTH
                case 't':
                    jwt_token = getFileContents(optarg);
                    if (jwt_token.empty()) {
                        return 2;
                    }
                    break;
#endif
                default:
                    usage(argv[0]);
                    std::cerr<<"\nUnknown argument: "<<char(opt)<<std::endl;
                    return 1;
                }
            }
        }

        client::Context ctxt;
#ifdef PVXS_ENABLE_JWT_AUTH
        if (!jwt_token.empty())
            ctxt = client::Context::fromEnvWithJwt(jwt_token);
        else
#endif
            ctxt = client::Context::fromEnv();

        if(verbose)
            std::cout<<"Effective config\n"<<ctxt.config();

        std::list<std::shared_ptr<client::Operation>> ops;

        std::atomic<int> remaining{argc-optind};
        epicsEvent done;

        for(auto n : range(optind, argc)) {

            ops.push_back(ctxt.get(argv[n])
                          .pvRequest(request)
                          .result([&argv, n, &remaining, &done, format, arrLimit](client::Result&& result) {
                              std::cout<<argv[n]<<"\n";
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
