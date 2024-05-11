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
#include <pvxs/sharedArray.h>
#include <pvxs/client.h>
#include <pvxs/nt.h>
#include "dataimpl.h"
#include "pvrequest.h"

namespace {
using namespace pvxs;

void testPvRequest()
{
    namespace M = members;

    testDiag("%s", __func__);

    auto def = nt::NTScalar{TypeCode::String}.build();
    auto val = def.create();
    testShow()<<val;

    {
        auto rdef = TypeDef(TypeCode::Struct, {
                                M::Struct("field", {})
                            });

        auto mask = request2mask(Value::Helper::desc(val), rdef.create());

        testEq(mask, BitMask({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 10u));
    }

    {
        auto rdef = TypeDef(TypeCode::Struct, {
                                M::Struct("field", {
                                    M::Struct("value", {}),
                                })
                            });

        auto mask = request2mask(Value::Helper::desc(val), rdef.create());

        testEq(mask, BitMask({0, 1}, 10u));
    }

    {
        auto rdef = TypeDef(TypeCode::Struct, {
                                M::Struct("field", {
                                    M::Struct("timeStamp", {}),
                                    M::Struct("alarm", {
                                        M::Struct("status", {}),
                                    }),
                                })
                            });

        auto mask = request2mask(Value::Helper::desc(val), rdef.create());

        testEq(mask, BitMask({0, 2, 4, 6, 7, 8, 9}, 10u));
    }

    {
        auto rdef = TypeDef(TypeCode::Struct, {
                                M::Struct("field", {
                                    M::Struct("timeStamp", {}),
                                    M::Struct("nonexistent", {}),
                                    M::Struct("alarm", {
                                        M::Struct("status", {}),
                                    }),
                                })
                            });

        auto mask = request2mask(Value::Helper::desc(val), rdef.create());

        testEq(mask, BitMask({0, 2, 4, 6, 7, 8, 9}, 10u))<<" include including non-existent";
    }

    {
        auto rdef = TypeDef(TypeCode::Struct, {
                                M::Struct("field", {
                                    M::Struct("nonexistent", {}),
                                })
                            });

        testThrows<std::runtime_error>([&val, &rdef](){
            (void)request2mask(Value::Helper::desc(val), rdef.create());
        })<<" empty mask";
    }
}

void testPvMask()
{
    auto val = nt::NTScalar{TypeCode::String}.create();

    auto rdef = TypeDef(TypeCode::Struct, {
                            members::Struct("field", {
                                members::Struct("value", {}),
                            })
                        });

    auto mask = request2mask(Value::Helper::desc(val), rdef.create());

    testFalse(testmask(val, mask));

    val["alarm.status"].mark();
    testFalse(testmask(val, mask));

    val["value"].mark();
    testTrue(testmask(val, mask));

    val["alarm.status"].unmark();
    testTrue(testmask(val, mask));

    val.unmark();
    testFalse(testmask(val, mask));

    val.mark();
    testTrue(testmask(val, mask));
}

struct TestBuilder : client::detail::CommonBuilder<TestBuilder, client::detail::PRBase>
{
    TestBuilder()
        :client::detail::CommonBuilder<TestBuilder, client::detail::PRBase>(nullptr, "")
    {}

    template<typename T>
    TestBuilder& set(const std::string& name, const T& val, bool required=true) {
        const typename impl::StoreAs<T>::store_t& norm(impl::StoreTransform<T>::in(val));
        _set(name, &norm, impl::StoreAs<T>::code, required);
        return *this;
    }

    Value builder(Value&& prototype) {
        return _builder(std::move(prototype));
    }

    Value uriArgs() {
        return _uriArgs();
    }
};

void testEmpty()
{
    testShow()<<__func__;

    auto req = client::Context::request().build();

    testShow()<<req;
    testStrEq(std::string(SB()<<req),
        "struct {\n"
        "    struct {} field\n"
        "}\n"
    );
}

void testAssemble()
{
    testShow()<<__func__;

    auto req = client::Context::request()
            .field("foo")
            .field("bar.baz")
            .record("abc", "xyz")
            .record("pipeline", true)
            .build();

    testShow()<<req;
    testStrEq(std::string(SB()<<req),
        "struct {\n"
        "    struct {\n"
        "        struct {} foo\n"
        "        struct {\n"
        "            struct {} baz\n"
        "        } bar\n"
        "    } field\n"
        "    struct {\n"
        "        struct {\n"
        "            string abc = \"xyz\"\n"
        "            bool pipeline = true\n"
        "        } _options\n"
        "    } record\n"
        "}\n"
    );
}

void testParseEmpty()
{
    testShow()<<__func__;

    auto req = client::Context::request()
            .pvRequest("")
            .build();

    testShow()<<req;
    testStrEq(std::string(SB()<<req),
        "struct {\n"
        "    struct {} field\n"
        "}\n"
    );
}

void testParseValue()
{
    testShow()<<__func__;

    auto req = client::Context::request()
            .pvRequest("field(value)")
            .build();

    testShow()<<req;
    testStrEq(std::string(SB()<<req),
        "struct {\n"
        "    struct {\n"
        "        struct {} value\n"
        "    } field\n"
        "}\n"
    );
}

void testParse1()
{
    testShow()<<__func__;

    auto req = client::Context::request()
            .pvRequest("field(foo)field(bar.baz)record[abc=xyz]record[pipeline=true]")
            .build();

    testShow()<<req;
    testStrEq(std::string(SB()<<req),
        "struct {\n"
        "    struct {\n"
        "        struct {} foo\n"
        "        struct {\n"
        "            struct {} baz\n"
        "        } bar\n"
        "    } field\n"
        "    struct {\n"
        "        struct {\n"
        "            string abc = \"xyz\"\n"
        "            string pipeline = \"true\"\n"
        "        } _options\n"
        "    } record\n"
        "}\n"
    );
}

void testParse2()
{
    testShow()<<__func__;

    auto req = client::Context::request()
            .pvRequest("field(foo,bar.baz)record[abc=xyz,pipeline=true]")
            .build();

    testShow()<<req;
    testStrEq(std::string(SB()<<req),
        "struct {\n"
        "    struct {\n"
        "        struct {} foo\n"
        "        struct {\n"
        "            struct {} baz\n"
        "        } bar\n"
        "    } field\n"
        "    struct {\n"
        "        struct {\n"
        "            string abc = \"xyz\"\n"
        "            string pipeline = \"true\"\n"
        "        } _options\n"
        "    } record\n"
        "}\n"
    );
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
            testCase(true)<<pvr<<"\n"<<client::Context::request().pvRequest(pvr).build();
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
            auto req = client::Context::request()
                    .pvRequest(pvr)
                    .build();
            testShow()<<req;
        })<<pvr;
    }
}

void testBuilder()
{
    testShow()<<__func__;

    auto builder = TestBuilder()
            .set("value", "14")
            .set("alarm.severity", 3)
            .set("alarm", 42, false)
            .set("nonexistent", 42, false);

    auto built = builder.builder(nt::NTScalar{TypeCode::UInt32}.create());

    testEq(built["value"].as<uint32_t>(), 14u);
    testEq(built["alarm.severity"].as<uint32_t>(), 3u);
}

void testArgs()
{
    using namespace pvxs::members;

    testShow()<<__func__;

    shared_array<int32_t> iarr({1,2,3});

    auto sub = TypeDef(TypeCode::Struct, {
                           Int32("ival")
                       }).create();

    sub["ival"] = 123;

    auto args = TestBuilder()
            .set("a", "14")
            .set("b", 3)
            .set("c", iarr.freeze().castTo<const void>())
            .set("d", sub)
            .uriArgs();

    testStrEq(std::string(SB()<<args),
         "struct \"epics:nt/NTURI:1.0\" {\n"
         "    string scheme = \"\"\n"
         "    string authority = \"\"\n"
         "    string path = \"\"\n"
         "    struct {\n"
         "        string a = \"14\"\n"
         "        int64_t b = 3\n"
         "        int32_t[] c = {3}[1, 2, 3]\n"
         "        struct {\n"
         "            int32_t ival = 123\n"
         "        } d\n"
         "    } query\n"
         "}\n"
    );
}

} // namespace

MAIN(testpvreq)
{
    testPlan(38);
    testSetup();
    logger_config_env();
    testPvRequest();
    testPvMask();
    testEmpty();
    testAssemble();
    testParseEmpty();
    testParseValue();
    testParse1();
    testParse2();
    testValid();
    testError();
    testBuilder();
    testArgs();
    cleanup_for_valgrind();
    return testDone();
}
