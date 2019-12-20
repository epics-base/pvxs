/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_LOG_H
#define PVXS_LOG_H

#include <atomic>

#include <stdarg.h>

#include <compilerDependencies.h>
#include <errlog.h>

#include <pvxs/version.h>

namespace pvxs {

enum struct Level {
    Debug = 50,
    Info  = 40,
    Warn  = 30,
    Err   = 20,
    Crit  = 10,
};

struct logger {
    const char *name;
    // atomic using epicsAtomic (std::atomic<> may not be statically initializable)
    std::atomic<int> lvl;
    constexpr logger(const char *name) :name(name), lvl{-1} {}

private:
    PVXS_API int init();
public:

    inline bool test(int lvl) {
        int cur = this->lvl.load(std::memory_order_relaxed);
        if(cur==-1) cur = init();
        return cur>=lvl;
    }
    inline bool test(Level lvl) {
        return test(int(lvl));
    }
};

#define DEFINE_LOGGER(VAR, NAME) static ::pvxs::logger VAR{NAME}

PVXS_API
void xerrlogHexPrintf(const void *buf, size_t buflen,
                      const char *fmt, ...) EPICS_PRINTF_STYLE(3,4);

#define log_test(LOGGER, LVL) (LOGGER).test(::pvxs::Level::LVL)

#define log_printf(LOGGER, LVL, ...) do{ if(log_test(LOGGER, LVL)) errlogPrintf(__VA_ARGS__); }while(0)

#define log_vprintf(LOGGER, LVL, FMT, ARGS) do{ if(log_test(LOGGER, LVL)) errlogVprintf(FMT, ARGS); }while(0)

#define log_hex_printf(LOGGER, LVL, BUF, BUFLEN, ...) do{ if(log_test(LOGGER, LVL)) xerrlogHexPrintf(BUF, BUFLEN, __VA_ARGS__); }while(0)

//! Set level for a specific logger
PVXS_API void logger_level_set(const char *name, int lvl);
inline void logger_level_set(const char *name, Level lvl) {
    logger_level_set(name, int(lvl));
}

/** Configure logging from environment variable $PVXS_LOG
 *
 * Value of the form "key=VAL,..."
 */
PVXS_API void logger_config_env();

} // namespace pvxs

#endif // PVXS_LOG_H
