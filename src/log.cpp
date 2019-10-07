/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <map>
#include <set>
#include <string>

#include <pvxs/log.h>

#include <envDefs.h>
#include <epicsAssert.h>
#include <epicsStdio.h>
#include <epicsThread.h>
#include <epicsMutex.h>
#include <epicsGuard.h>

typedef epicsGuard<epicsMutex> Guard;

namespace {
using namespace pvxs;

epicsThreadOnceId logger_once = EPICS_THREAD_ONCE_INIT;

int name2lvl(const std::string& name)
{
#define CASE(LVL) if(name==#LVL) return PLVL_##LVL
    CASE(DEBUG);
    CASE(INFO);
    CASE(WARN);
    CASE(ERR);
    CASE(CRIT);
#undef CASE
    return 0;
}

struct logger_gbl_t {
    epicsMutex lock;
    std::map<std::string, int> config;
    std::multimap<std::string, logger*> loggers;

    int init(logger *logger)
    {
        std::string name(logger->name);

        loggers.emplace(name, logger);

        auto it = config.find(name);
        if(it!=config.end()) {
            epics::atomic::set(logger->lvl, it->second);
            return it->second;
        }

        return PLVL_ERR;
    }

    void set(const char *name, int lvl)
    {
        if(lvl<=0)
            lvl = 1;

        // update config for loggers added later
        config[name] = lvl;

        // apply to existing loggers
        auto iters = loggers.equal_range(name);
        for(; iters.first!=iters.second; ++iters.first) {
            epics::atomic::set(iters.first->second->lvl, lvl);
        }
    }
} *logger_gbl;

void logger_prepare(void *unused)
{
    logger_gbl = new logger_gbl_t;
}

}

namespace pvxs {

int logger_init(logger *logger)
{
    assert(logger->name);

    if(epics::atomic::compareAndSwap(logger->lvl, -1, PLVL_ERR)!=-1) {
        // raced concurrent init and lost
        return epics::atomic::get(logger->lvl);
    }
    // logger now has default config of PLVL_ERR

    epicsThreadOnce(&logger_once, &logger_prepare, nullptr);
    assert(logger_gbl);

    Guard G(logger_gbl->lock);
    return logger_gbl->init(logger);
}

void logger_level_set(const char *name, int lvl)
{
    epicsThreadOnce(&logger_once, &logger_prepare, nullptr);
    assert(logger_gbl);

    Guard G(logger_gbl->lock);
    logger_gbl->set(name, lvl);
}

void logger_config_env()
{
    const char *env = getenv("PVXS_LOG");
    if(!env || !*env)
        return;

    epicsThreadOnce(&logger_once, &logger_prepare, nullptr);

    Guard G(logger_gbl->lock);

    while(*env) {
        const char *sep = env;
        const char *eq = env;

        while(*sep && *sep!=',')
            sep++;

        while(*eq && *eq!='=')
            eq++;

        if(env==sep) {
            // empty
        } else if(eq < sep) {
            // key=VAL

            std::string key(env, eq-env),
                        val(eq+1, sep-eq-1);


            if(key.empty() || val.empty()) {
                fprintf(stderr, "PVXS_LOG ignore invalid: '%s=%s'\n", key.c_str(), val.c_str());

            } else if(auto lvl = name2lvl(val)) {
                logger_gbl->set(key.c_str(), lvl);

            } else {
                fprintf(stderr, "PVXS_LOG ignore invalid level: '%s=%s'\n", key.c_str(), val.c_str());
            }

        }

        env = sep;
        if(*env==',')
            ++env;
    }
}

} // namespace pvxs
