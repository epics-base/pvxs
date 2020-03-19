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
        testOk1(top.compareType(top2));
        testOk1(top.compareInst(top2));
    }
    {
        auto sevr1 = top["alarm.severity"];
        auto sevr2 = top["value<alarm.status<severity"];
        testOk1(sevr1.compareType(sevr2));
        testOk1(sevr1.compareInst(sevr2));
    }
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
    testEq(i, 9u)<<"# of decendent fields";

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

    testMarked(0u)<<"no decendent fields";

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

} // namespace

MAIN(testdata)
{
    testPlan(20);
    testTraverse();
    testAssign();
    testName();
    testIter();
    testPvRequest();
    cleanup_for_valgrind();
    return testDone();
}
