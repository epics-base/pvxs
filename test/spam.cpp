/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <sstream>

#include <epicsTime.h>
#include <epicsGetopt.h>
#include <epicsEvent.h>

#include <pvxs/source.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

using namespace pvxs;

DEFINE_LOGGER(app, "spam");

namespace {

struct SpamSource : public server::Source
{
    std::shared_ptr<std::set<std::string>> names;
    Value initial;
    size_t nelem = 1u;

    SpamSource()
        :names(std::make_shared<decltype (names)::element_type>())
        ,initial(nt::NTScalar{TypeCode::UInt32}.create())
    {}

    void set_nelem(size_t n)
    {
        initial = nt::NTScalar{TypeCode::UInt32A}.create();
        nelem = n;
    }

    // Source interface
    virtual void onSearch(Search &op) override final
    {
        for(auto& pv :op) {
            if(names->find(pv.name())!=names->end())
                pv.claim();
        }
    }
    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&chan) override final
    {
        chan->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
            cop->onGet([](std::unique_ptr<server::ExecOp>&& op) {
                op->error("Only monitor implemented");
            });
            cop->connect(initial);
        });

        chan->onSubscribe([this](std::unique_ptr<server::MonitorSetupOp>&& setup) {

            std::shared_ptr<server::MonitorControlOp> sub(setup->connect(initial));

            auto counter(std::make_shared<uint32_t>(0u));

            auto fill = [this, sub, counter]() {
                Value update;
                size_t nposted = 0;
                server::MonitorStat stats{};

                sub->stats(stats);

                do {
                    auto cnt = (*counter)++;
                    update = initial.cloneEmpty();
                    auto value = update["value"];
                    if(value.type().isarray()) {
                        shared_array<uint32_t> arr(nelem, cnt);

                        value = arr.freeze();

                    } else {
                        value = cnt;
                    }

                    nposted++;

                }while(sub->tryPost(update));

                log_debug_printf(app, "%s %s counted %zu, %zu, %zu/%zu -> %u\n",
                                 sub->peerName().c_str(), sub->name().c_str(),
                                 nposted, stats.window, stats.nQueue, stats.limitQueue,
                                 unsigned(*counter));
            };

            server::MonitorStat stats;
            sub->stats(stats);
            sub->setWatermarks(0, stats.limitQueue);
            sub->onHighMark(fill);

            sub->onStart([fill](bool start) {
                if(start)
                    fill();
            });

            log_info_printf(app, "%s Subscribing\n", setup->peerName().c_str());
        });
    }
    virtual List onList() override final
    {
        return List{names, false};
    }
};

template<typename T>
bool parse_as(T& out, const char *s)
{
    std::istringstream strm(s);
    return (strm>>out).fail() || !strm.eof();
}

int help(int ret, const char* argv0)
{
    std::cerr<<
    "Usage: "<<argv0<<" [-h] [-T <period>] [-# <count>] [-S <spam:pv:name>] ... [-H <ham:pv:name>] ...\n"
    "\n"
    "    -h \n"
    ;
    std::cerr.flush();
    return ret;
}

} // namespace

int main(int argc, char* argv[])
{
    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_level_set(app.name, Level::Info);
    logger_config_env();

    auto spamsrc = std::make_shared<SpamSource>();
    auto hamsrc = server::StaticSource::build();

    auto hampv(server::SharedPV::buildReadonly());
    auto hamval(nt::NTScalar{TypeCode::UInt32}.create());
    hampv.open(hamval);

    double ham_period = 1.0;
    size_t nelem = 1;

    int opt;
    {
        while((opt = getopt(argc, argv, "hS:H:T:#:")) != -1) {
            switch (opt) {
            case 'h':
                return help(0, argv[0]);
            default:
                std::cerr<<"Unknown argument -"<<char(opt)<<std::endl;
                return 1;
            case 'S':
                spamsrc->names->insert(optarg);
                break;
            case 'H':
                hamsrc.add(optarg, hampv);
                break;
            case 'T':
                if(parse_as(ham_period, optarg)) {
                    std::cerr<<"Unable to parse period: "<<optarg<<std::endl;
                    return 1;
                }
                break;
            case '#':
                if(parse_as(nelem, optarg)) {
                    std::cerr<<"Unable to parse array count: "<<optarg<<std::endl;
                    return 1;
                }
                break;
            }
        }
    }

    if(ham_period <= 0.0)
        ham_period = 1.0;

    if(nelem==0)
        nelem = 1;

    spamsrc->set_nelem(nelem);

    // Build server which will serve this PV
    // Configure using process environment.
    server::Server serv = server::Server::fromEnv()
            .addSource("spamsrc", spamsrc)
            .addSource("hamsrc", hamsrc.source());

    // (optional) Print the configuration this server is using
    // with any auto-address list expanded.
    {
        Detailed d(std::cout, 1);
        std::cout<<serv;
    }

    serv.start();
    std::cout<<"Running\n";

    bool run = true;
    epicsEvent evt;

    SigInt sig([&run, &evt]{
        run = false;
        evt.signal();
    });

    uint32_t ham_count = 0;
    while(run) {
        hamval["value"] = ham_count++;
        hampv.post(hamval);

        evt.wait(ham_period);
    }

    std::cout<<"Done\n";

    return 0;
}
