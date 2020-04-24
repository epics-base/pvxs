/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <memory>
#include <stdexcept>

#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/source.h>
#include <pvxs/iochooks.h>

#include <iocsh.h>
#include <initHooks.h>
#include <epicsStdio.h>
#include <epicsExit.h>
#include <epicsExport.h>

using namespace pvxs;

namespace {
std::atomic<server::Server*> instance{};

DEFINE_LOGGER(log, "pvxs.ioc");

void pvxsl(int detail)
{
    try {
        if(auto serv = instance.load()) {
            for(auto& pair : serv->listSource()) {
                auto src = serv->getSource(pair.first);
                if(!src)
                    continue; // race?

                auto list = src->onList();

                if(detail>0)
                    printf("# Source %s@%d%s\n",
                           pair.first.c_str(), pair.second,
                           list.dynamic ? " [dynamic]":"");

                if(!list.names) {
                    if(detail>0)
                        printf("# no PVs\n");
                } else {
                    for(auto& name : *list.names) {
                        printf("%s\n", name.c_str());
                    }
                }
            }
        }
    } catch(std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

void pvxsr(int detail)
{
    try {
        if(auto serv = instance.load()) {
            // TODO
            (void)serv;
        }
    } catch(std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

template <size_t... Ns>
struct index_sequence {};

template<typename Tag>
struct next_index_sequence {};

template<size_t... Ns>
struct next_index_sequence<index_sequence<Ns...>>
{
    typedef index_sequence<Ns..., sizeof...(Ns)> type;
};

template<size_t I, size_t Cnt, size_t... Idxs>
struct build_index_sequence
{
    typedef typename build_index_sequence<I+1, Cnt, Idxs..., I+1>::type type;
};

template<size_t Cnt, size_t... Idxs>
struct build_index_sequence<Cnt, Cnt, Idxs...>
{
    typedef index_sequence<Idxs...> type;
};

template<typename ...Args>
using make_index_sequence = typename build_index_sequence<0, sizeof...(Args)>::type;

template<typename E>
struct Arg;

template<>
struct Arg<int> {
    static constexpr iocshArgType code = iocshArgInt;
    static int get(const iocshArgBuf& buf) { return buf.ival; }
};

template<>
struct Arg<double> {
    static constexpr iocshArgType code = iocshArgDouble;
    static double get(const iocshArgBuf& buf) { return buf.dval; }
};

template<>
struct Arg<const char*> {
    static constexpr iocshArgType code = iocshArgString;
    static const char* get(const iocshArgBuf& buf) { return buf.sval; }
};

template<typename T>
struct ToStr { typedef const char* type; };

template<typename ...Args>
struct Reg {
    const char* const name;
    const char* const argnames[sizeof...(Args)];

    constexpr explicit Reg(const char* name, typename ToStr<Args>::type... descs)
        :name(name)
        ,argnames{descs...}
    {}

    template<void (*fn)(Args...), size_t... Idxs>
    static
    void call(const iocshArgBuf* args)
    {
        (*fn)(Arg<Args>::get(args[Idxs])...);
    }

    template<void (*fn)(Args...), size_t... Idxs>
    void doit(index_sequence<Idxs...>)
    {
        static const iocshArg args[sizeof...(Args)] = {{argnames[Idxs], Arg<Args>::code}...};
        static const iocshFuncDef def = {name, sizeof...(Args), (const iocshArg* const*)&args};

        iocshRegister(&def, &call<fn, Idxs...>);
    }

    template<void (*fn)(Args...)>
    void ister()
    {
        doit<fn>(make_index_sequence<Args...>{});
    }
};

void pvxsAtExit(void* unused)
{
    try {
        if(auto serv = instance.load()) {
            if(instance.compare_exchange_strong(serv, nullptr)) {
                // take ownership
                std::unique_ptr<server::Server> trash(serv);
                trash->stop();
                log_debug_printf(log, "Stopped Server?%s", "\n");
            }
        }
    } catch(std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

void pvxsInitHook(initHookState state)
{
    try {
        // iocBuild()
        if(state==initHookAfterInitDatabase) {
            // we want to run before exitDatabase
            epicsAtExit(&pvxsAtExit, nullptr);
        }
        // iocRun()/iocPause()
        if(state==initHookAfterCaServerRunning) {
            if(auto serv = instance.load()) {
                serv->start();
                log_debug_printf(log, "Started Server %p", serv);
            }
        }
        if(state==initHookAfterCaServerPaused) {
            if(auto serv = instance.load()) {
                serv->stop();
                log_debug_printf(log, "Stopped Server %p", serv);
            }
        }
    } catch(std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

void pvxsRegistrar()
{
    try {
        pvxs::logger_config_env();

        Reg<int>("pvxsl", "detail").ister<&pvxsl>();
        Reg<int>("pvxsr", "detail").ister<&pvxsr>();

        auto serv = instance.load();
        if(!serv) {
            std::unique_ptr<server::Server> temp(new server::Server(server::Config::from_env()));

            if(instance.compare_exchange_strong(serv, temp.get())) {
                log_debug_printf(log, "Installing Server %p\n", temp.get());
                temp.release();
            } else {
                log_crit_printf(log, "Race installing Server? %p\n", serv);
            }
        } else {
            log_err_printf(log, "Stale Server? %p\n", serv);
        }

        initHookRegister(&pvxsInitHook);
    } catch(std::exception& e) {
        fprintf(stderr, "Error in %s : %s\n", __func__, e.what());
    }
}

} // namesapce

namespace pvxs {
namespace ioc {

server::Server server()
{
    if(auto serv = instance.load()) {
        return *serv;
    } else {
        throw std::logic_error("No Instance");
    }
}

}} // namespace pvxs::ioc

extern "C" {
epicsExportRegistrar(pvxsRegistrar);
}
