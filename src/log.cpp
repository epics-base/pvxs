/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <map>
#include <string>
#include <list>

#include <assert.h>
#include <stdlib.h>

// must include before epicsStdio.h to avoid clash with printf macro
#include <event2/util.h>
#include <event2/buffer.h>

#include <pvxs/log.h>

#include <envDefs.h>
#include <dbDefs.h>
#include <osiSock.h>
#include <epicsString.h>
#include <cantProceed.h>
#include <epicsStdio.h>
#include <epicsThread.h>
#include <epicsMutex.h>
#include <epicsGuard.h>
#include <epicsTime.h>

#include "evhelper.h"
#include "utilpvt.h"

#if EPICS_VERSION_INT>=VERSION_INT(3,15,0,0)
#    include <epicsStackTrace.h>
#else
static void epicsStackTrace() {}
#endif

typedef epicsGuard<epicsMutex> Guard;

namespace pvxs {

DEFINE_LOGGER(logerr, "pvxs.ev");

namespace detail {

static
unsigned char abortOnCrit;

const char* log_prep(logger& log, unsigned rawlvl)
{
    auto lvl = (Level)(rawlvl&0xff);
    if(!log.test(lvl))
        return nullptr; // don't log

    thread_local char prefix[80];

    epicsTimeStamp now;
    size_t N;
    if(epicsTimeGetCurrent(&now)) {
        strcpy(prefix, "<notime>");
        N = strlen(prefix);

    } else {
        N = epicsTimeToStrftime(prefix, sizeof(prefix), "%Y-%m-%dT%H:%M:%S.%9f", &now);
    }

    const char *lname;
    switch(lvl) {
    case Level::Crit:  lname = "CRIT"; break;
    case Level::Err:   lname = "ERR"; break;
    case Level::Warn:  lname = "WARN"; break;
    case Level::Info:  lname = "INFO"; break;
    case Level::Debug: lname = "DEBUG"; break;
    default:           lname = "<\?\?\?>"; break;
    }

    int ret = epicsSnprintf(prefix+N, sizeof(prefix)-N, " %s %s", lname, log.name);
    if(ret >=0 ) {
        N += size_t(ret);
        if(N>60) {
            // prefix is too long (arbitrary), so move message content to next line
            epicsSnprintf(prefix+N, sizeof(prefix)-N, "\n    ");
        }
    }

    return prefix;
}

static
void _log_vprintf(unsigned rawlvl, const char *fmt, va_list args)
{
    errlogVprintf(fmt, args);

    if(Level(rawlvl&0xff)==Level::Crit && abortOnCrit!=0) {
        errlogFlush();
        if(abortOnCrit==1) {
            // C abort, end process
            epicsStackTrace();
            errlogFlush();
            abort();
        } else {
            // EPICS "abort" halt
            cantProceed("CRITICAL ERROR\n");
        }

    } else if(rawlvl&0x1000) {
        errlogFlush();
        epicsStackTrace();
        errlogFlush();
    }
}

void _log_printf(unsigned rawlvl, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    _log_vprintf(rawlvl, fmt, args);
    va_end(args);
}

void _log_printf_hex(unsigned rawlvl, const void *buf, size_t buflen, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    xerrlogHexPrintf(buf, buflen);
    _log_vprintf(rawlvl, fmt, args);
    va_end(args);
}

} // namespace detail

namespace {

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
    // [(pattern, level)]
    std::list<std::pair<std::string, Level>> config;
    std::multimap<std::string, logger*> loggers;

    logger_gbl_t()
    {
        event_set_log_callback(&evlog_handler);
    }

    Level init(logger *logger)
    {
        std::string name(logger->name);

        auto lvl = Level::Warn;

        // see if this logger name has already been configured.
        auto it = loggers.find(logger->name);
        if(it!=loggers.end()) {
            lvl = it->second->lvl.load(std::memory_order_relaxed);

        } else {
            // nope

            for(auto& tup : config) {
                if(epicsStrGlobMatch(name.c_str(), tup.first.c_str())) {
                    lvl = tup.second;
                }
            }
        }


        loggers.emplace(name, logger);

        logger->lvl.store(lvl, std::memory_order_relaxed);

        return lvl;
    }

    void set(const char *exp, Level lvl)
    {
        if(lvl<=Level(0))
            lvl = Level(1);

        decltype (config)::value_type* conf = nullptr;

        for(auto& tup : config) {
            if(tup.first==exp) {
                // update of existing config
                conf = &tup;
                break;
            }
        }
        // new config

        if(!conf) {
            config.emplace_back(exp, Level(-1));
            conf = &config.back();
        }

        if(conf->second!=lvl) {
            conf->second = lvl;

            for(auto& pair : loggers) {
                if(epicsStrGlobMatch(pair.first.c_str(), conf->first.c_str())) {
                    pair.second->lvl.store(lvl, std::memory_order_relaxed);
                }
            }
        }
    }
} *logger_gbl;

void logger_prepare(void *unused)
{
    logger_gbl = new logger_gbl_t;

    if(auto env = getenv("_PVXS_ABORT_ON_CRIT")) {
        if(epicsStrCaseCmp(env, "YES")==0 || strcmp(env, "1")==0) {
            detail::abortOnCrit = 1;
        } else if(epicsStrCaseCmp(env, "EPICS")==0) {
            detail::abortOnCrit = 2;
        }
    }
}

epicsThreadOnceId logger_once = EPICS_THREAD_ONCE_INIT;

} // namespace

Level logger::init()
{
    assert(name);

    auto lvl = this->lvl.load();
    if(lvl==Level(-1)) {
        // maybe we initialize
        if(this->lvl.compare_exchange_strong(lvl, Level::Warn)) {
            // logger now has default config of Level::Err
            // we will fully initialize
            threadOnce(&logger_once, &logger_prepare, nullptr);
            assert(logger_gbl);

            Guard G(logger_gbl->lock);
            lvl = logger_gbl->init(this);
        }
    }
    return lvl;
}

void xerrlogHexPrintf(const void *buf, size_t buflen)
{
    const auto cbuf = static_cast<const uint8_t*>(buf);
    bool elipsis = buflen > 64u;
    if(elipsis)
        buflen = 64u;

    // whole buffer
    for(size_t pos=0; pos<buflen;)
    {
        // printed line (4 groups of 4 bytes)
        // addr : AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
        char buf[4][9] = {"","","",""};
        const unsigned addr = unsigned(pos);

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
    if(elipsis)
        errlogPrintf("...\n");
}

void logger_level_set(const char *name, int lvl)
{
    threadOnce(&logger_once, &logger_prepare, nullptr);
    assert(logger_gbl);

    Guard G(logger_gbl->lock);
    logger_gbl->set(name, Level(lvl));
}

void logger_level_clear()
{
    threadOnce(&logger_once, &logger_prepare, nullptr);
    assert(logger_gbl);

    Guard G(logger_gbl->lock);
    logger_gbl->config.clear();
}

void logger_config_env()
{
    const char *env = getenv("PVXS_LOG");
    if(!env || !*env)
        return;

    threadOnce(&logger_once, &logger_prepare, nullptr);

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
                errlogPrintf("PVXS_LOG ignore invalid: '%s=%s'\n", key.c_str(), val.c_str());

            } else if(auto lvl = name2lvl(val)) {
                logger_gbl->set(key.c_str(), Level(lvl));

            } else {
                errlogPrintf("PVXS_LOG ignore invalid level: '%s=%s'\n", key.c_str(), val.c_str());
            }

        }

        env = sep;
        if(*env==',')
            ++env;
    }

    errlogFlush();
}

} // namespace pvxs

namespace pvxs {namespace impl {

void logger_shutdown()
{
    threadOnce(&logger_once, &logger_prepare, nullptr);

    errlogFlush();

    delete logger_gbl;
    logger_gbl = nullptr;
    // no resetting logger_once
}

}} // namespace pvxs::impl
