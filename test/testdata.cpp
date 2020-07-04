/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <epicsUnitTest.h>

#include <pvxs/unittest.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>
#include "utilpvt.h"
#include "pvaproto.h"
#include "dataimpl.h"
#include "pvrequest.h"

using namespace pvxs;
namespace  {

void testTraverse()
{
    testDiag("%s", __func__);

    auto top = nt::NTScalar{TypeCode::Int32, true}.create();

    testOk1(!top["<"].valid());

    {
        auto top2 = top["value<"];
        testOk1(top.equalType(top2));
        testOk1(top.equalInst(top2));
    }
    {
        auto sevr1 = top["alarm.severity"];
        auto sevr2 = top["value<alarm.status<severity"];
        testOk1(sevr1.equalType(sevr2));
        testOk1(sevr1.equalInst(sevr2));
    }

    testFalse(top.equalType(top["alarm"]));
    testFalse(top.equalType(top["value"]));
}

void testAssign()
{
    testDiag("%s", __func__);

    auto def = nt::NTScalar{TypeCode::String}.build();
    auto val = def.create();

    val["value"] = "Testing";
    val["timeStamp"].mark();
    val["alarm.severity"] = 3u;

    auto val2 = def.create();

    val2.assign(val);

    testOk1(!val["alarm.status"].isMarked(true, true));
    testOk1(!!val["alarm"].isMarked(true, true));
    testOk1(!val["alarm"].isMarked(true, false));
}

void testName()
{
    testDiag("%s", __func__);

    auto def = nt::NTScalar{TypeCode::String}.build();
    auto val = def.create();

    testEq(val.nameOf(val["value"]), "value");
    testEq(val.nameOf(val["alarm.status"]), "alarm.status");

    testThrows<std::logic_error>([&val]() {
        val.nameOf(val);
    });
}

void testIter()
{
    testDiag("%s", __func__);

    auto def = nt::NTScalar{TypeCode::String}.build();
    auto val = def.create();

    unsigned i=0;
    for(auto fld : val.iall()) {
        testDiag("field %s", val.nameOf(fld).c_str());
        i++;
    }
    testEq(i, 9u)<<"# of descendant fields";

    i=0;
    for(auto fld : val.ichildren()) {
        testDiag("field %s", val.nameOf(fld).c_str());
        i++;
    }
    testEq(i, 3u)<<"# of child fields";

    auto testMarked = [&val](unsigned expect) -> testCase {
        unsigned i=0;
        for(auto fld : val.imarked()) {
            testDiag("field %s", val.nameOf(fld).c_str());
            i++;
        }
        return testEq(i, expect);
    };

    testMarked(0u)<<"no descendant fields";

    val["alarm.status"].mark();

    testMarked(1u)<<"mark one field";

    val.unmark();
    val["alarm"].mark();

    testMarked(4u)<<"mark sub-struct";

    val.unmark();
    val["value"].mark();
    val["alarm.status"].mark();
    val["timeStamp"].mark();

    testMarked(6u)<<"mark sub-struct";
}

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
}

template<typename Store, typename Inout>
void testConvertScalar(const Store& store, const Inout& inout)
{
    testShow()<<__func__<<"("<<store<<","<<inout<<")";

    typedef impl::ScalarMap<Store> store_t;

    auto cont = TypeDef(store_t::code).create();

    try {
        cont.from(inout);
    }catch(std::exception& e){
        testCase(false)<<"Error storing as "<<typeid (Store).name()<<" "<<inout<<" : "<<e.what();
    }

    testEq(store, cont.as<Store>())<<typeid(Store).name();

    testEq(inout, cont.as<Inout>())<<typeid(Store).name()<<"->"<<typeid(Inout).name();
}

void testAssignSimilar()
{
    testShow()<<__func__;

    auto def1 = nt::NTScalar{TypeCode::UInt32}.build();
    {
        auto def2 = nt::NTScalar{TypeCode::UInt32}.build();

        auto val1 = def1.create();
        auto val2 = def2.create();

        // succeeds as no fields are marked.
        val1.assign(val2);
        testFalse(val1.isMarked(false, true));

        val2["value"] = 4;
        val2["alarm.severity"] = 1;

        val1.assign(val2);
        testTrue(val1.isMarked(false, true));
        testTrue(val1["value"].isMarked());
        testFalse(val1["alarm"].isMarked());
        testTrue(val1["alarm.severity"].isMarked());
        testFalse(val1["alarm.status"].isMarked());

        val1.unmark();

        val2["alarm"].mark();

        val1.assign(val2);
        testTrue(val1.isMarked(false, true));
        testTrue(val1["value"].isMarked());
        testTrue(val1["alarm"].isMarked());
        testTrue(val1["alarm.severity"].isMarked());
        testTrue(val1["alarm.status"].isMarked());
    }

    {
        auto def2 = nt::NTScalar{TypeCode::Float64, true}.build();

        auto val1 = def1.create();
        auto val2 = def2.create();

        // succeeds as no fields are marked.
        val1.assign(val2);
        testFalse(val1.isMarked(false, true));

        val2["value"] = 4;
        val2["alarm.severity"] = 1;

        val1.assign(val2);
        testTrue(val1.isMarked(false, true));
        testTrue(val1["value"].isMarked());
        testEq(val1["value"].as<double>(), 4.0);

        val1.unmark();

        val2["display.description"] = "blah";

        testThrows<NoField>([&val1, &val2]() {
            val1.assign(val2);
        });
    }
}

} // namespace

MAIN(testdata)
{
    testPlan(80);
    testSetup();
    testTraverse();
    testAssign();
    testName();
    testIter();
    testPvRequest();
    testConvertScalar<double, bool>(1.0, true);
    testConvertScalar<double, bool>(0.0, false);
    testConvertScalar<double, uint32_t>(5.0, 5);
    testConvertScalar<double, int32_t>(5.0, 5);
    testConvertScalar<double, int32_t>(-5.0, -5);
    testConvertScalar<double, double>(-5.0, -5.0);
    testConvertScalar<double, std::string>(-5.0, "-5");
    testConvertScalar<int32_t, bool>(1, true);
    testConvertScalar<int32_t, bool>(0, false);
    testConvertScalar<int32_t, uint32_t>(5, 5);
    testConvertScalar<int32_t, int32_t>(5, 5);
    testConvertScalar<int32_t, int32_t>(-5, -5);
    testConvertScalar<int32_t, double>(-5, -5.0);
    testConvertScalar<int32_t, std::string>(-5, "-5");
    testConvertScalar<std::string, bool>("true", true);
    testConvertScalar<std::string, bool>("false", false);
    testConvertScalar<std::string, uint32_t>("5", 5);
    testConvertScalar<std::string, int32_t>("5", 5);
    testConvertScalar<std::string, int32_t>("-5", -5);
    testConvertScalar<std::string, double>("-5", -5.0);
    testConvertScalar<std::string, std::string>("-5", "-5");
    testAssignSimilar();
    cleanup_for_valgrind();
    return testDone();
}
