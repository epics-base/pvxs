/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <map>
#include <set>
#include <string>

// must include before epicsStdio.h to avoid clash with printf macro
#include <event2/util.h>
#include <event2/buffer.h>

#include <pvxs/log.h>

#include <envDefs.h>
#include <osiSock.h>
#include <epicsAssert.h>
#include <epicsStdio.h>
#include <epicsThread.h>
#include <epicsMutex.h>
#include <epicsGuard.h>

#include "evhelper.h"

typedef epicsGuard<epicsMutex> Guard;

namespace {
using namespace pvxs;

DEFINE_LOGGER(logerr, "evlog");

epicsThreadOnceId logger_once = EPICS_THREAD_ONCE_INIT;

void evlog_handler(int severity, const char *msg)
{
    const char *sevr = "<\?\?\?>";
    int lvl = PLVL_CRIT;
    switch(severity) {
#define CASE(EVLVL, PLVL) case EVENT_LOG_##EVLVL : lvl = PLVL_##PLVL; sevr = #PLVL; break
    CASE(DEBUG, DEBUG);
    CASE(MSG, INFO);
    CASE(WARN, WARN);
    CASE(ERR, ERR);
#undef CASE
    }
    log_printf(logerr, lvl, "libevent %s: %s\n", sevr, msg);
}


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

    logger_gbl_t()
    {
        event_set_log_callback(&evlog_handler);
    }

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

void xerrlogHexPrintf(const void *buf, size_t buflen,
                      const char *fmt, ...)
{
    const uint8_t* const cbuf = static_cast<const uint8_t*>(buf);
    va_list args;

    // whole buffer
    for(size_t pos=0; pos<buflen;)
    {
        // printed line (4 groups of 4 bytes)
        // addr : AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
        char buf[4][9];
        const unsigned addr = pos;

        for(unsigned grp=0; grp<4 && pos<buflen ; grp++)
        {
            // group of 4 hex chars
            unsigned chr=0;
            for(; chr<8 && pos<buflen; pos++, chr+=2)
            {
                static const char hex[17]="0123456789ABCDEF";
                uint8_t v = cbuf[pos];
                buf[grp][chr+0] = hex[(v>>4)&0xf];
                buf[grp][chr+1] = hex[(v>>0)&0xf];
            }
            for(; chr<8; chr+=2)
            {
                buf[grp][chr+0] = '\0';
                buf[grp][chr+1] = '\0';
            }
            buf[grp][8] = '\0';
        }

        errlogPrintf("%04x : %s %s %s %s\n", addr, buf[0], buf[1], buf[2], buf[3]);
    }

    va_start(args, fmt);
    errlogVprintf(fmt, args);
    va_end(args);
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
