/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>

#include <epicsTime.h>

#include <pvxs/source.h>
#include <pvxs/server.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

using namespace pvxs;

DEFINE_LOGGER(app, "spam");

namespace {

struct SpamSource : public server::Source
{
    std::shared_ptr<std::set<std::string>> names;
    Value initial;

    SpamSource()
        :names(std::make_shared<decltype (names)::element_type>())
        ,initial(nt::NTScalar{TypeCode::UInt32}.create())
    {}

    // Source interface
public:
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

            auto counter = std::make_shared<uint32_t>(0u);

            auto fill = [this, sub, counter]() mutable {
                Value update;
                do {
                    auto cnt = (*counter)++;
                    update = initial.cloneEmpty();
                    update["value"] = cnt;

                    log_debug_printf(app, "%s count %u\n", sub->peerName().c_str(), unsigned(cnt));

                }while(sub->tryPost(update));
            };

            sub->onHighMark(fill);

            sub->onStart([fill](bool start) mutable {
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

} // namespace

int main(int argc, char* argv[])
{
    if(argc<=1) {
        std::cerr<<"Usage: "<<argv[0]<<" <pvname>\n";
        return 1;
    }

    // Read $PVXS_LOG from process environment and update
    // logging configuration.  eg.
    //    export PVXS_LOG=*=DEBUG
    // makes a lot of noise.
    logger_level_set(app.name, Level::Info);
    logger_config_env();

    auto src = std::make_shared<SpamSource>();
    src->names->insert(argv[1]);

    // Build server which will serve this PV
    // Configure using process environment.
    server::Server serv = server::Config::fromEnv()
            .build()
            .addSource("spamsrc", src);

    // (optional) Print the configuration this server is using
    // with any auto-address list expanded.
    std::cout<<"Effective config\n"<<serv.config();

    std::cout<<"Running\n";

    // Start server and run forever, or until Ctrl+c is pressed.
    // Returns on SIGINT or SIGTERM
    serv.run();

    std::cout<<"Done\n";

    return 0;
}
