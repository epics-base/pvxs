/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>

#include <epicsTime.h>

#include <pvxs/server.h>
#include <pvxs/source.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

#include <evhelper.h>

namespace {
using namespace pvxs;
using namespace pvxs::server;

DEFINE_LOGGER(app, "countdown");

auto def = nt::NTScalar{TypeCode::UInt32}.build();

struct CountdownSrc : public Source
{
    const std::string name;

    pvxs::impl::evbase loop;

    CountdownSrc(const std::string& name)
        :name(name)
        ,loop("counter")
    {}

    virtual void onSearch(Search &search) override final
    {
        for(auto& op : search) {
            if(op.name()==name) {
                log_printf(app, Info, "Claiming '%s'\n", op.name());
                op.claim();
            } else {
                log_printf(app, Debug, "Ignoring '%s'\n", op.name());
            }
        }
    }
    virtual void onCreate(std::unique_ptr<ChannelControl> &&op) override final
    {
        if(op->name()!=name)
            return;

        std::shared_ptr<ChannelControl> chan(std::move(op));

        log_printf(app, Info, "Create chan '%s'\n", chan->name().c_str());

        chan->onSubscribe([this, chan](std::unique_ptr<MonitorSetupOp>&& setup) {

            log_printf(app, Info, "Create mon '%s'\n", chan->name().c_str());

            std::shared_ptr<MonitorControlOp> op(setup->connect(def.create())); // unique_ptr becomes shared_ptr

            loop.later(1.0, std::bind(&CountdownSrc::tick, this, op, 5u));
        });

        // return a dummy value for info/get
        chan->onOp([](std::unique_ptr<ConnectOp>&& conn) {
            conn->connect(def.create());

            conn->onGet([](std::unique_ptr<ExecOp>&& op){
                auto val = def.create();
                val["value"] = 0u;
                op->reply(val);
            });
        });
    }

    virtual List onList() override final
    {
        auto names(std::make_shared<std::set<std::string>>());
        names->insert(name);
        return List{names};
    }

    void tick(const std::shared_ptr<MonitorControlOp>& op, uint32_t count)
    {
        log_printf(app, Info, "tick %u\n", unsigned(count));

        auto val = def.create();
        val["value"].from(count);
        {
            epicsTimeStamp now;
            epicsTimeGetCurrent(&now);
            val["value"] = count;
            val["timeStamp.secondsPastEpoch"] = now.secPastEpoch+POSIX_TIME_AT_EPICS_EPOCH;
            val["timeStamp.nanoseconds"] = now.nsec;
        }

        op->post(std::move(val));

        if(count)
            loop.later(1.0, std::bind(&CountdownSrc::tick, this, op, count-1u));
        else
            op->finish();
    }
};

} // namespace

int main(int argc, char *argv[])
{
    int ret = 0;
    try {
        pvxs::logger_level_set(app.name, pvxs::Level::Info);
        pvxs::logger_config_env();

        auto src = std::make_shared<CountdownSrc>("countdown");

        auto serv = Server::Config::from_env()
                .build()
                .addSource("countdown", src);

        auto& conf = serv.config();

        std::cout<<"Serving from :\n";
        for(auto& iface : conf.interfaces) {
            std::cout<<"  "<<iface<<"\n";
        }

        log_printf(app, Info, "Running\n%s", "");
        serv.run();

    }catch(std::exception& e){
        std::cerr<<"Error "<<typeid(&e).name()<<" : "<<e.what()<<std::endl;
        ret = 1;
    }
    pvxs::cleanup_for_valgrind();
    return ret;
}
