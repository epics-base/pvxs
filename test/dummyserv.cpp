/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <typeinfo>
#include <set>
#include <string>
#include <atomic>

#include <epicsEvent.h>
#include <epicsTime.h>

#include <pvxs/server.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>


namespace {
using namespace pvxs;
using namespace pvxs::server;

DEFINE_LOGGER(dummy,"dummyserv");

struct DummyHandler : public Handler
{
    static const Value mytype;
    static std::atomic<unsigned> count;

    Value current;

    DummyHandler()
        :current(mytype.cloneEmpty())
    {
        epicsTimeStamp now;
        epicsTimeGetCurrent(&now);
        current["value"] = count.fetch_add(1);
        current["timeStamp.secondsPastEpoch"] = now.secPastEpoch+POSIX_TIME_AT_EPICS_EPOCH;
        current["timeStamp.nanoseconds"] = now.nsec;
    }
    virtual ~DummyHandler() {}

    virtual void onIntrospect(std::unique_ptr<Introspect> &&op) override final
    {
        log_printf(dummy, PLVL_INFO, "GET_FIELD\n");
        op->reply(mytype);
    }

    virtual void onGet(std::unique_ptr<Get>&& op) override final
    {
        log_printf(dummy, PLVL_INFO, "Create GET\n");
        std::shared_ptr<Get> sop(std::move(op));
        sop->connect(current, [this, sop]()
        {
            log_printf(dummy, PLVL_INFO, "Execute GET\n");
            // executing
            sop->reply(current); // "current" never changes for us, so no locking
        });
    }
};


const Value DummyHandler::mytype = nt::NTScalar{TypeCode::Int32}.build().create();
std::atomic<unsigned> DummyHandler::count{};

struct DummySource : public Source
{
    std::set<std::string> names;
    virtual ~DummySource() {}

    // Source interface
public:
    virtual void onSearch(Search &search) override final
    {
        for(auto& op : search) {
            if(names.find(op.name())!=names.end()) {
                log_printf(dummy, PLVL_INFO, "Claiming '%s'\n", op.name());
                op.claim();
            } else {
                log_printf(dummy, PLVL_DEBUG, "Ignoring '%s'\n", op.name());
            }
        }
    }
    virtual void onCreate(std::unique_ptr<ChannelControl>&& op) override final
    {
        log_printf(dummy, PLVL_INFO, "Create '%s'\n", op->name.c_str());
        op->setHandler(std::unique_ptr<Handler>{new DummyHandler});
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

        auto serv = Server::Config::from_env()
                .build()
                .addSource("dummy", src);

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
