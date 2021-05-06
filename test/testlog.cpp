/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <ostream>

#include <testMain.h>
#include <epicsUnitTest.h>
#include <envDefs.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>

namespace pvxs {

std::ostream& operator<<(std::ostream& strm, Level lvl)
{
    switch (lvl) {
#define CASE(NAME) case Level::NAME: strm<<#NAME; break
    CASE(Crit);
    CASE(Err);
    CASE(Warn);
    CASE(Info);
    CASE(Debug);
#undef CASE
    default:
        strm<<"Level("<<int(lvl)<<")";
    }
    return strm;
}

} // namespace pvxs

using namespace pvxs;

namespace {

DEFINE_LOGGER(loggera, "test.a");
DEFINE_LOGGER(loggerb, "test.b");

void testLog()
{
    testDiag("%s", __func__);

    testTrue(loggera.test(Level::Warn));
    testEq(loggera.lvl.load(), Level::Warn);

    logger_level_set("test.*", Level::Err);

    testEq(loggera.lvl.load(), Level::Err);

    testTrue(loggerb.test(Level::Err));
    testEq(loggerb.lvl.load(), Level::Err);

    logger_level_set("test.*", Level::Info);

    testEq(loggera.lvl.load(), Level::Info);
    testEq(loggerb.lvl.load(), Level::Info);

    logger_level_set("test.a", Level::Err);

    testEq(loggera.lvl.load(), Level::Err);
    testEq(loggerb.lvl.load(), Level::Info);

    logger_level_set("test.*", Level::Warn);

    testEq(loggera.lvl.load(), Level::Warn);
    testEq(loggerb.lvl.load(), Level::Warn);

    logger_level_clear();
    logger_level_set("test.*", Level::Err);

    testEq(loggera.lvl.load(), Level::Err);
    testEq(loggerb.lvl.load(), Level::Err);
}

DEFINE_LOGGER(enva, "env.a");
DEFINE_LOGGER(envb, "env.b");
DEFINE_LOGGER(envc, "env.other.c");

void testEnv()
{
    testDiag("%s", __func__);

    logger_level_clear();

    epicsEnvSet("PVXS_LOG", "foo,env.*=INFO,env.other.c=DEBUG,bar=FAKELEVEL");
    eltc(0);
    logger_config_env();
    eltc(1);

    (void)enva.test(Level::Info);
    (void)envb.test(Level::Info);
    (void)envc.test(Level::Info);

    testEq(enva.lvl.load(), Level::Info);
    testEq(envb.lvl.load(), Level::Info);
    testEq(envc.lvl.load(), Level::Debug);
}

} // namespace

MAIN(testlog)
{
    testPlan(16);
    testSetup();
    testLog();
    testEnv();
    return testDone();
}
