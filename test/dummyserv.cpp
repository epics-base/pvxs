/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <typeinfo>
#include <set>
#include <string>

#include <epicsEvent.h>

#include <pvxs/server.h>
#include <pvxs/log.h>


namespace {
using namespace pvxs::server;

DEFINE_LOGGER(dummy,"dummyserv");

struct DummySource : public Source
{
    std::set<std::string> names;
    virtual ~DummySource() {}

    // Source interface
public:
    virtual void onSearch(Search &op) override
    {
        for(auto& name : op) {
            if(names.find(name.name())!=names.end()) {
                log_printf(dummy, PLVL_INFO, "Claiming '%s'\n", name.name());
                name.claim();
            } else {
                log_printf(dummy, PLVL_DEBUG, "Ignoring '%s'\n", name.name());
            }
        }
    }
    virtual std::unique_ptr<Handler> onCreate(const Create &op) override
    {
        return nullptr;
    }
};

} // namespace

int main(int argc, char *argv[])
{
    int ret = 0;
    try {
        pvxs::logger_level_set("dummy", PLVL_INFO);
        pvxs::logger_config_env();

        std::shared_ptr<DummySource> src(new DummySource);
        src->names.emplace("blah");

        auto serv = std::move(Server::Config::from_env()
                .build()
                .addSource("dummy", src));

        auto& conf = serv.config();

        std::cout<<"Serving from :\n";
        for(auto& iface : conf.interfaces) {
            std::cout<<"  "<<iface<<"\n";
        }

        serv.run();

    }catch(std::exception& e){
        std::cerr<<"Error "<<typeid(&e).name()<<" : "<<e.what()<<std::endl;
        ret = 1;
    }
    pvxs::cleanup_for_valgrind();
    return ret;
}
