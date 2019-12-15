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
#include <epicsMutex.h>
#include <epicsGuard.h>
#include <epicsTime.h>

#include <pvxs/server.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

#include "utilpvt.h"

namespace {
using namespace pvxs;
using namespace pvxs::server;

DEFINE_LOGGER(dummy,"dummyserv");

struct DummySource : public Source
{
    const std::string name;
    epicsMutex lock;
    Value current;

    explicit DummySource(const std::string& name)
        :name(name)
        ,current(nt::NTScalar{TypeCode::Int32}.build().create())
    {
        epicsTimeStamp now;
        epicsTimeGetCurrent(&now);
        current["value"] = 0u;
        current["timeStamp.secondsPastEpoch"] = now.secPastEpoch+POSIX_TIME_AT_EPICS_EPOCH;
        current["timeStamp.nanoseconds"] = now.nsec;
    }
    virtual ~DummySource() {}

    // Source interface
public:
    virtual void onSearch(Search &search) override final
    {
        for(auto& op : search) {
            if(op.name()==name) {
                log_printf(dummy, PLVL_INFO, "Claiming '%s'\n", op.name());
                op.claim();
            } else {
                log_printf(dummy, PLVL_DEBUG, "Ignoring '%s'\n", op.name());
            }
        }
    }
    virtual void onCreate(std::unique_ptr<ChannelControl>&& raw) override final
    {
        if(raw->name()!=name)
            return;

        std::shared_ptr<ChannelControl> chan(std::move(raw));

        log_printf(dummy, PLVL_INFO, "Create '%s'\n", chan->name().c_str());

        // callback when client creating Get/Put
        chan->onOp([this, chan](std::shared_ptr<ConnectOp>&& raw){
            std::shared_ptr<ConnectOp> conn(std::move(raw));

            log_printf(dummy, PLVL_INFO, "Begin Operation on '%s'\n", chan->name().c_str());

            conn->onGet([this, chan](std::unique_ptr<ExecOp>&& raw) {
                // client executing Get or Put
                log_printf(dummy, PLVL_INFO, "Exec Get on '%s'\n", chan->name().c_str());

                {
                    epicsGuard<epicsMutex> G(lock);
                    raw->reply(current);
                }
            });

            conn->onPut([this, chan](std::unique_ptr<ExecOp>&& raw, Value&& top) {
                log_printf(dummy, PLVL_INFO, "Exec Put on '%s'\n", chan->name().c_str());

                {
                    epicsTimeStamp now;
                    epicsTimeGetCurrent(&now);

                    epicsGuard<epicsMutex> G(lock);

                    current["value"] = top["value"].as<uint32_t>();
                    current["timeStamp.secondsPastEpoch"] = now.secPastEpoch+POSIX_TIME_AT_EPICS_EPOCH;
                    current["timeStamp.nanoseconds"] = now.nsec;
                }

                raw->reply(); // inform client that Put was successful
            });

            epicsGuard<epicsMutex> G(lock);
            conn->connect(current); // only type is used
        });

        // callback when client executing RPC
        chan->onRPC([this, chan](std::unique_ptr<ExecOp>&& raw, Value&& top) {
            log_printf(dummy, PLVL_INFO, "Begin RPC on '%s' with %s\n", chan->name().c_str(),
                       std::string(SB()<<top).c_str());

            auto ret = nt::NTScalar{TypeCode::String}.build().create();

            ret["value"] = "RPC test";

            raw->reply(ret);
        });
    }
};

} // namespace

int main(int argc, char *argv[])
{
    int ret = 0;
    try {
        pvxs::logger_level_set("dummyserv", PLVL_INFO);
        pvxs::logger_config_env();

        auto src = std::make_shared<DummySource>("blah");

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
