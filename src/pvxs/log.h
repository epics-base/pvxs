/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

#include <compilerDependencies.h>
#include <epicsAtomic.h>
#include <errlog.h>

#include <pvxs/version.h>

namespace pvxs {

#define PLVL_DEBUG 50
#define PLVL_INFO  40
#define PLVL_WARN  30
#define PLVL_ERR   20
#define PLVL_CRIT  10

struct logger {
    const char *name;
    // atomic using epicsAtomic (std::atomic<> may not be statically initializable)
    int lvl;
};

#define LOGGER_INIT(NAME) {NAME, -1}

#define DEFINE_LOGGER(VAR, NAME) static ::pvxs::logger VAR = LOGGER_INIT(NAME)

PVXS_API int logger_init(logger *logger);

static inline
bool log_test(logger& logger, int lvl)
{
    int cur = ::epics::atomic::get(logger.lvl);
    if(cur==-1) cur = logger_init(&logger);
    return cur>=lvl;
}

#define log_printf(LOGGER, LVL, ...) do{ if(log_test(LOGGER, LVL)) errlogPrintf(__VA_ARGS__); }while(0)

#define log_vprintf(LOGGER, LVL, FMT, ARGS) do{ if(log_test(LOGGER, LVL)) errlogVprintf(FMT, ARGS); }while(0)

//! Set level for a specific logger
PVXS_API void logger_level_set(const char *name, int lvl);

/** Configure logging from environment variable $PVXS_LOG
 *
 * Value of the form "key=VAL,..."
 */
PVXS_API void logger_config_env();

} // namespace pvxs

#endif // LOG_H
