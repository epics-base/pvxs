/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <map>
#include <tuple>
#include <string>
#include <list>
#include <regex>

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
#include "utilpvt.h"

typedef epicsGuard<epicsMutex> Guard;

namespace pvxs {

namespace {

DEFINE_LOGGER(logerr, "pvxs.ev");

epicsThreadOnceId logger_once = EPICS_THREAD_ONCE_INIT;

void evlog_handler(int severity, const char *msg)
{
    const char *sevr = "<\?\?\?>";
    Level lvl = Level::Crit;
    switch(severity) {
#define CASE(EVLVL, PLVL) case EVENT_LOG_##EVLVL : lvl = Level::PLVL; sevr = #PLVL; break
    CASE(DEBUG, Debug);
    CASE(MSG, Info);
    CASE(WARN, Warn);
    CASE(ERR, Err);
#undef CASE
    }
    if(logerr.test(lvl))
        errlogPrintf("libevent %s: %s\n", sevr, msg);
}


int name2lvl(const std::string& name)
{
#define CASE(LVL, Lvl) if(name==#LVL) return int(Level::Lvl)
    CASE(DEBUG, Debug);
    CASE(INFO, Info);
    CASE(WARN, Warn);
    CASE(ERR, Err);
    CASE(CRIT, Crit);
#undef CASE
    return 0;
}

struct logger_gbl_t {
    epicsMutex lock;
    std::list<std::tuple<std::regex, std::string, int>> config;
    std::multimap<std::string, logger*> loggers;

    logger_gbl_t()
    {
        event_set_log_callback(&evlog_handler);
    }

    int init(logger *logger)
    {
        std::string name(logger->name);

        int lvl = int(Level::Err);

        // see if this logger name has already been configured.
        auto it = loggers.find(logger->name);
        if(it!=loggers.end()) {
            lvl = it->second->lvl.load(std::memory_order_relaxed);

        } else {
            // nope

            for(auto& tup : config) {
                if(std::regex_match(name, std::get<0>(tup))) {
                    lvl = std::get<2>(tup);
                    break;
                }
            }
        }


        loggers.emplace(name, logger);

        logger->lvl.store(lvl, std::memory_order_relaxed);

        return lvl;
    }

    void set(const char *name, int lvl)
    {
        if(lvl<=0)
            lvl = 1;

        // convert name, with wildcards to a regexp
        std::string exp("^");
        for(char c = *name; c!='\0'; c=*++name) {
            if((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_')
                exp += c;
            else if(c=='.')
                exp += "\\.";
            else if(c=='?')
                exp += '.';
            else if(c=='*')
                exp += ".*";
        }
        exp+='$';

        for(auto& tup : config) {
            if(std::get<1>(tup)==exp) {
                // update of existing config
                if(std::get<2>(tup)!=lvl) {
                    std::get<2>(tup) = lvl;

                    for(auto& pair : loggers) {
                        if(std::regex_match(pair.first, std::get<0>(tup))) {
                            pair.second->lvl.store(lvl, std::memory_order_relaxed);
                        }
                    }
                }
                return;
            }
        }
        // new config

        std::regex re(exp);

        config.emplace_back(std::move(re), exp, lvl);
    }
} *logger_gbl;

void logger_prepare(void *unused)
{
    logger_gbl = new logger_gbl_t;
}

} // namespace

int logger::init()
{
    assert(name);

    int lvl = this->lvl.load();
    if(lvl==-1) {
        // maybe we initialize
        if(this->lvl.compare_exchange_strong(lvl, int(Level::Err))) {
            // logger now has default config of Level::Err
            // we will fully initialize
            epicsThreadOnce(&logger_once, &logger_prepare, nullptr);
            assert(logger_gbl);

            Guard G(logger_gbl->lock);
            lvl = logger_gbl->init(this);
        }
    }
    return lvl;
}

void xerrlogHexPrintf(const void *buf, size_t buflen)
{
    const uint8_t* const cbuf = static_cast<const uint8_t*>(buf);

    // whole buffer
    for(size_t pos=0; pos<buflen;)
    {
        // printed line (4 groups of 4 bytes)
        // addr : AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
        char buf[4][9] = {"","","",""};
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
}

void logger_level_set(const char *name, int lvl)
{
    epicsThreadOnce(&logger_once, &logger_prepare, nullptr);
    assert(logger_gbl);

    Guard G(logger_gbl->lock);
    logger_gbl->set(name, lvl);
}

void logger_level_clear()
{
    epicsThreadOnce(&logger_once, &logger_prepare, nullptr);
    assert(logger_gbl);

    Guard G(logger_gbl->lock);
    logger_gbl->config.clear();
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

namespace pvxs {namespace impl {

void logger_shutdown()
{
    epicsThreadOnce(&logger_once, &logger_prepare, nullptr);

    errlogFlush();

    delete logger_gbl;
    logger_gbl = nullptr;
    // no resetting logger_once
}

}} // namespace pvxs::impl
