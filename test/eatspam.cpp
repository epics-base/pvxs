/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <sstream>
#include <vector>
#include <atomic>

#include <epicsTime.h>
#include <epicsGetopt.h>
#include <epicsEvent.h>
#include <epicsTime.h>

#define PVXS_ENABLE_EXPERT_API

#include <pvxs/client.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

#if EPICS_VERSION_INT < VERSION_INT(7,0,1,0)
#define epicsMonotonicGet epicsTime::getCurrent
#endif

using namespace pvxs;

DEFINE_LOGGER(app, "eatspam");

namespace {

template<typename T>
bool parse_as(T& out, const char *s)
{
    std::istringstream strm(s);
    return (strm>>out).fail() || !strm.eof();
}

struct Counter {
    std::string name;
    std::vector<Value> scratch;
    std::shared_ptr<client::Subscription> sub;
    uint32_t prev;
    size_t nwake = 0;
    size_t nupdate = 0;
    size_t nskip = 0;
    bool first = true;
};

} // namespace

int main(int argc, char* argv[])
{
    logger_level_set(app.name, Level::Warn);
    logger_config_env();
    size_t queueSize = 0;
    int pipeline = 0; // tri-bool

    int opt;
    {
        while((opt = getopt(argc, argv, "hpPQ:")) != -1) {
            switch (opt) {
            case 'h':
                std::cerr<<"Usage: "<<argv[0]<<" [-w <sec>] pvname..."<<std::endl;
                return 0;
            default:
                std::cerr<<"Unknown argument -"<<char(opt)<<std::endl;
                return 1;
            case 'p':
                pipeline = -1;
                break;
            case 'P':
                pipeline = 1;
                break;
            case 'Q':
                if(parse_as<size_t>(queueSize, optarg)) {
                    std::cerr<<"Invalid queueSize: "<<optarg<<std::endl;
                    return 1;
                }
                break;
            }
        }
    }

    std::string pvRequest;
    {
        std::ostringstream strm;
        strm<<"record[";
        if(pipeline==1)
            strm<<"pipeline=true";
        if(pipeline==-1)
            strm<<"pipeline=false";
        if(queueSize) {
            if(pipeline!=0)
                strm<<',';
            strm<<"queueSize="<<queueSize;
        }
        strm<<']';
        pvRequest = strm.str();
    }

    auto ctxt(client::Context::fromEnv());

    std::vector<Counter> ctrs(argc - optind);

    MPMCFIFO<size_t> todo(ctrs.size()+1);

    auto t0(epicsMonotonicGet());

    for(int i=0; i<argc-optind; i++) {

        auto ctr = &ctrs[i];
        ctr->name = argv[optind+i];
        ctr->sub = ctxt.monitor(ctr->name)
                .pvRequest(pvRequest.c_str())
                .event([i, &todo](client::Subscription&) {
                    todo.emplace(1+i);
                })
                .exec();
    }

    SigInt sig([&todo](){
        todo.emplace(0);
    });

    while(auto i = todo.pop()) {
        auto& ctr = ctrs[i-1];

        ctr.nwake++;
        try {
            bool notdone;
            if(!!(notdone = ctr.sub->pop(ctr.scratch, queueSize))) {
                todo.emplace(i);
            }
            if(ctr.scratch.empty() && notdone)
                log_warn_printf(app, "%s pointless wakeup. %c\n", ctr.name.c_str(),
                                notdone ? 'N' : 'D');
            else
                log_debug_printf(app, "%s wake with %zu, %c\n", ctr.name.c_str(), ctr.scratch.size(),
                                 notdone ? 'N' : 'D');
        }  catch (client::Disconnect&) {
            ctr.first = true;
            continue;
        }

        for(auto& v : ctr.scratch) {
            bool gotit = false;
            uint32_t sval;

            auto val(v["value"]);
            if(!val.isMarked()) {
                continue;

            } else if(val.type()==TypeCode::UInt32A) {
                auto aval(val.as<shared_array<const uint32_t>>());
                if(!aval.empty()) {
                    sval = aval[0];
                    gotit = true;
                } else {
                    continue;
                }

            } else if(val.type().code <= TypeCode::Float64 && !val.type().isarray()) {
                sval = val.as<uint32_t>();
                gotit = true;
            }

            if(gotit) {
                if(!ctr.first) {
                    auto diff = sval-ctr.prev;
                    if(diff != 1) {
                        log_info_printf(app, "%s skip %u -> %u, %u\n",
                                        ctr.name.c_str(), ctr.prev, sval, diff);
                        ctr.nskip++;
                    }

                } else {
                    ctr.first = false;
                    log_info_printf(app, "%s initial %u\n", ctr.name.c_str(), sval);
                }
                ctr.nupdate++;
                ctr.prev = sval;

            } else {
                std::cerr<<ctr.name<<": "<<val.format().arrayLimit(10)<<"\n"
                        "Error: no compatible \".value\" "<<val.type()<<std::endl;
                ctr.sub->cancel();
            }
        }
        ctr.scratch.clear();
    }

    // cancel subscriptions
    for(auto& ctr : ctrs) {
        ctr.sub->cancel();
    }

    // final stats and cleanup
    for(auto& ctr : ctrs) {
        client::SubscriptionStat stats;
        ctr.sub->stats(stats);
        std::cout<<' '<<ctr.name<<" Q used "
                <<stats.maxQueue<<'/'<<stats.limitQueue<<" w/ "
                <<stats.nSrvSquash<<" server overflows "
                <<stats.nCliSquash<<" client overflows for "
                <<ctr.nupdate<<" updates"
                "\n";
        ctr.sub.reset();
    }

    auto t1(epicsMonotonicGet());
    double dT = (t1-t0) * 1e-9;
    std::cout<<"# run time "<<dT<<" sec.\n";

    for(const auto& ctr : ctrs) {
        std::cout<<ctr.name<<" "
                 <<(ctr.nwake/dT)<<" wakes/s "
                 <<(ctr.nupdate/dT)<<" update/s "
                 <<(ctr.nskip/dT)<<" skips/s "
                 <<(double(ctr.nupdate)/ctr.nwake)<<" updates/wake "
                 <<(double(ctr.nskip) / (ctr.nskip + ctr.nupdate) * 100.0)<<" % skip"
                 "\n";
    }

    ctrs.clear();
    ctxt.close();
    ctxt = client::Context();

    bool header=false;
    int ret = 0;
    for(const auto& p : instanceSnapshot()) {
        if(p.second!=0) {
            if(!header) {
                header = true;
                std::cout<<"Trailing refs...\n";
                ret = 1;
            }
            std::cout<<" #"<<p.first<<" = "<<p.second<<"\n";
        }
    }

    std::cout<<std::endl;

    return ret;
}
