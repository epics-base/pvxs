/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>

#include <testMain.h>

#include <epicsUnitTest.h>

#include <epicsEvent.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>
#include "utilpvt.h"

namespace {
using namespace pvxs;

struct TestBuilder : client::detail::CommonBuilder<TestBuilder>
{
    TestBuilder()
        :client::detail::CommonBuilder<TestBuilder>(nullptr, "")
    {}

    IValue makeReq() const {
        return _build();
    }
};

void testEmpty()
{
    testShow()<<__func__;

    auto req = TestBuilder().makeReq();

    testShow()<<req;
    testEq(std::string(SB()<<"\n"<<req), R"out(
struct {
    struct {
    } field
}
)out");
}

void testAssemble()
{
    testShow()<<__func__;

    auto req = TestBuilder()
            .field("foo")
            .field("bar.baz")
            .record("abc", "xyz")
            .record("pipeline", true)
            .makeReq();

    testShow()<<req;
    testEq(std::string(SB()<<"\n"<<req), R"out(
struct {
    struct {
        struct {
        } foo
        struct {
            struct {
            } baz
        } bar
    } fields
    struct {
        struct {
            string abc = "xyz"
            bool pipeline = true
        } _options
    } record
}
)out");
}

void testParse1()
{
    testShow()<<__func__;

    auto req = TestBuilder()
            .pvRequest("field(foo)field(bar.baz)record[abc=xyz]record[pipeline=true]")
            .makeReq();

    testShow()<<req;
    testEq(std::string(SB()<<"\n"<<req), R"out(
struct {
    struct {
        struct {
        } foo
        struct {
            struct {
            } baz
        } bar
    } fields
    struct {
        struct {
            string abc = "xyz"
            string pipeline = "true"
        } _options
    } record
}
)out");
}

void testParse2()
{
    testShow()<<__func__;

    auto req = TestBuilder()
            .pvRequest("field(foo,bar.baz)record[abc=xyz,pipeline=true]")
            .makeReq();

    testShow()<<req;
    testEq(std::string(SB()<<"\n"<<req), R"out(
struct {
    struct {
        struct {
        } foo
        struct {
            struct {
            } baz
        } bar
    } fields
    struct {
        struct {
            string abc = "xyz"
            string pipeline = "true"
        } _options
    } record
}
)out");
}

void testValid()
{
    testShow()<<__func__;

    std::vector<std::string> valid({
                                       "field()",
                                       "field(a,b,a.b)field(x)",
                                       "a", // short-hand
                                       "field(a,b,a.b)field(x)",
                                       // should these be valid?
                                       "field(,)",
                                       "field(foo,)",
                                       "record[foo=bar,]",
                                   });

    for(auto& pvr : valid) {
        try {
            testCase(true)<<pvr<<"\n"<<TestBuilder().pvRequest(pvr).makeReq();
        }catch(std::exception& e){
            testCase(false)<<pvr<<" : "<<typeid(e).name()<<" : "<<e.what();
        }
    }
}

void testError()
{
    testShow()<<__func__;

    std::vector<std::string> errors({
                                        "field(",
                                        "field(value",
                                        "field(value,alarm",
                                        "field[]",
                                        "record()",
                                        "field(!@#)",
                                        "record[",
                                        "record[key",
                                        "record[key=",
                                        "record[key=]",
                                        "record[,]",
                                    });

    for(auto& pvr : errors) {

        testThrows<std::runtime_error>([&pvr](){
            auto req = TestBuilder()
                    .pvRequest(pvr)
                    .makeReq();
            testShow()<<req;
        })<<pvr;
    }
}

} // namespace

MAIN(testpvreq)
{
    testPlan(22);
    logger_config_env();
    testEmpty();
    testAssemble();
    testParse1();
    testParse2();
    testValid();
    testError();
    cleanup_for_valgrind();
    return testDone();
}
