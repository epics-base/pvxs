/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_LOG_H
#define PVXS_LOG_H

#include <atomic>

#include <cstddef>
#include <stdarg.h>

#include <compilerDependencies.h>
#include <errlog.h>

#include <pvxs/version.h>

namespace pvxs {

//! Importance of message
enum struct Level {
    Debug = 50,
    Info  = 40,
    Warn  = 30,
    Err   = 20,
    Crit  = 10,
};

//! A logger
struct logger {
    //! global name of this logger.  Need not be unique
    const char * const name;
    //! Current logging level.  See logger_level_set().
    std::atomic<Level> lvl;
    constexpr logger(const char *name) :name(name), lvl{Level(-1)} {}

private:
    PVXS_API Level init();
public:

    //! @returns true if the logger currently allows a message at level LVL.
    inline bool test(Level lvl) {
        Level cur = this->lvl.load(std::memory_order_relaxed);
        if(cur==Level(-1)) cur = init();
        return cur>=lvl;
    }
};

namespace detail {

PVXS_API
const char* log_prefix(const char* name, Level lvl);

PVXS_API
void _log_printf(unsigned lvl, const char* fmt, ...) EPICS_PRINTF_STYLE(2,3);

} // namespace detail

//! Define a new logger global.
//! @param VAR The (static) variable name passed to log_printf() and friends.
//! @param NAME A name string in "A.B.C" form.
#define DEFINE_LOGGER(VAR, NAME) static ::pvxs::logger VAR{NAME}

PVXS_API
void xerrlogHexPrintf(const void *buf, size_t buflen);

/** Try to log a message at the defined level.
 *
 * Due to portability issues with MSVC, log formats must have at least one argument.
 *
 *  @code
 *      DEFINE_LOGGER(blah, "myapp.blah");
 *      void blahfn(int x) {
 *          log_info_printf(blah, "blah happened with %d\n", x);
 *  @endcode
 */
#define log_printf(LOGGER, LVL, FMT, ...) do{ \
    if((LOGGER).test(LVL)) \
       ::pvxs::detail:: _log_printf(unsigned(LVL), "%s " FMT, ::pvxs::detail::log_prefix((LOGGER).name, LVL), __VA_ARGS__); \
}while(0)

#define log_crit_printf(LOGGER, FMT, ...)  log_printf(LOGGER, ::pvxs::Level::Crit, FMT, __VA_ARGS__)
#define log_err_printf(LOGGER, FMT, ...)   log_printf(LOGGER, ::pvxs::Level::Err, FMT, __VA_ARGS__)
#define log_warn_printf(LOGGER, FMT, ...)  log_printf(LOGGER, ::pvxs::Level::Warn, FMT, __VA_ARGS__)
#define log_info_printf(LOGGER, FMT, ...)  log_printf(LOGGER, ::pvxs::Level::Info, FMT, __VA_ARGS__)
#define log_debug_printf(LOGGER, FMT, ...) log_printf(LOGGER, ::pvxs::Level::Debug, FMT, __VA_ARGS__)
#define log_exc_printf(LOGGER, FMT, ...)   do{ \
    if((LOGGER).test(::pvxs::Level::Crit)) \
       ::pvxs::detail:: _log_printf(unsigned(::pvxs::Level::Crit)|0x1000, "%s " FMT, ::pvxs::detail::log_prefix((LOGGER).name, ::pvxs::Level::Crit), __VA_ARGS__); \
}while(0)

#define log_hex_printf(LOGGER, LVL, BUF, BUFLEN, FMT, ...) do{ if((LOGGER).test(LVL)) { \
        xerrlogHexPrintf(BUF, BUFLEN); \
        errlogPrintf("%s " FMT, ::pvxs::detail::log_prefix((LOGGER).name, LVL), __VA_ARGS__); } \
    }while(0)

//! Set level for a specific logger
PVXS_API void logger_level_set(const char *name, int lvl);
inline void logger_level_set(const char *name, Level lvl) {
    logger_level_set(name, int(lvl));
}
//! Remove any previously logger configurations.
//! Does _not_ change any logger::lvl
//! Use prior to re-applying new configuration.
PVXS_API void logger_level_clear();

/** Configure logging from environment variable **$PVXS_LOG**
 *
 * Value of the form "key=VAL,..."
 *
 * Keys may be literal logger names, or may include '*' wildcards
 * to match multiple loggers.  eg. "pvxs.*=DEBUG" will enable
 * all internal log messages.
 *
 * VAL may be one of "CRIT", "ERR", "WARN", "INFO", or "DEBUG"
 */
PVXS_API void logger_config_env();

} // namespace pvxs

#endif // PVXS_LOG_H
