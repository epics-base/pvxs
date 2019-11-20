/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <epicsUnitTest.h>

#include <pvxs/unittest.h>
#include <pvxs/data.h>
#include "utilpvt.h"
#include "dataimpl.h"

using namespace pvxs;
namespace  {

void showSize()
{
    testDiag("%s()", __func__);
#define CASE(TYPE) testDiag("sizeof(" #TYPE ") = %u", unsigned(sizeof(TYPE)))
    CASE(Value);
    CASE(impl::FieldDesc);
    CASE(impl::FieldStorage);
    CASE(impl::StructTop);
#undef CASE
}

void testBasic()
{
    testDiag("%s()", __func__);

    auto top = TypeDef(TypeCode::Struct, "simple_t")
            .begin()
            .insert("value", nullptr, TypeCode::Float64)
            .create();

    testOk1(top.valid());
    testEq(top.type(), TypeCode::Struct);

    {
        auto val = top["missing"];
        testOk1(!val.valid());
        testOk1(!val.isMarked());

        testThrows<NoConvert>([&val]() {
            val.from(4.2);
        });
    }

    {
        auto val = top["value"];
        testOk1(!!val.valid());
        testOk1(!val.isMarked());
        val.from(4.2);
        testEq(val.as<double>(), 4.2);
        testOk1(!!val.isMarked());
    }

    testEq(std::string(SB()<<top),
           "struct \"simple_t\" {\n"
           "    double value = 4.2\n"
           "}\n");
}

void testTypeDef()
{
    testDiag("%s()", __func__);

    testEq(std::string(SB()<<TypeDef()),
           "<Empty>\n");

    testEq(std::string(SB()<<TypeDef(TypeCode::Struct, "simple_t")),
           "struct \"simple_t\"\n");

    TypeDef def(TypeCode::Struct, "simple_t");

    def.begin()
    .insert("value", nullptr, TypeCode::Float64A)
    .insert("timeStamp", "time_t", TypeCode::Struct)
    .seek("timeStamp")
        .insert("secondsPastEpoch", TypeCode::UInt64)
        .insert("nanoseconds", TypeCode::UInt32)
    .up() // up one level
    .insert("arbitrary", TypeCode::Struct)
    .seek("arbitrary")
        .insert("sarr", TypeCode::StructA)
        .seek("sarr")
            .insert("value", TypeCode::Float64)
    .reset() // back to top
    .insert("any", TypeCode::Any)
    .insert("anya", TypeCode::AnyA)
    .insert("choice", TypeCode::Union)
    .seek("choice")
        .insert("a", TypeCode::Float32)
        .insert("b", TypeCode::String)
    .reset()
    .insert("achoice", TypeCode::UnionA)
    .seek("achoice")
        .insert("x", TypeCode::Float32)
        .insert("y", TypeCode::Float32)
    ;

    testShow()<<def;

    testEq(std::string(SB()<<def),
           "struct \"simple_t\" {\n"
           "    double[] value\n"
           "    struct \"time_t\" {\n"
           "        uint64_t secondsPastEpoch\n"
           "        uint32_t nanoseconds\n"
           "    } timeStamp\n"
           "    struct {\n"
           "        struct[] {\n"
           "            double value\n"
           "        } sarr\n"
           "    } arbitrary\n"
           "    any any\n"
           "    any[] anya\n"
           "    union {\n"
           "        float a\n"
           "        string b\n"
           "    } choice\n"
           "    union[] {\n"
           "        float x\n"
           "        float y\n"
           "    } achoice\n"
           "}\n"
           );

    auto val = def.create();

    testOk1(!!val.valid());
    testShow()<<val._desc();
    testEq(std::string(SB()<<val._desc()),
           "[0] struct simple_t <0:11>  [0:18)\n"
           "  achoice -> 14 [14]\n"
           "  any -> 9 [9]\n"
           "  anya -> 10 [10]\n"
           "  arbitrary -> 5 [5]\n"
           "  arbitrary.sarr -> 6 [6]\n"
           "  choice -> 11 [11]\n"
           "  timeStamp -> 2 [2]\n"
           "  timeStamp.nanoseconds -> 4 [4]\n"
           "  timeStamp.secondsPastEpoch -> 3 [3]\n"
           "  value -> 1 [1]\n"
           "  value :  1 [1]\n"
           "  timeStamp :  2 [2]\n"
           "  arbitrary :  5 [5]\n"
           "  any :  9 [9]\n"
           "  anya :  10 [10]\n"
           "  choice :  11 [11]\n"
           "  achoice :  14 [14]\n"
           "[1] double[]  <1:2>  [1:2)\n"
           "[2] struct time_t <2:3>  [2:5)\n"
           "  nanoseconds -> 2 [4]\n"
           "  secondsPastEpoch -> 1 [3]\n"
           "  secondsPastEpoch :  1 [3]\n"
           "  nanoseconds :  2 [4]\n"
           "[3] uint64_t  <3:4>  [3:4)\n"
           "[4] uint32_t  <4:5>  [4:5)\n"
           "[5] struct  <5:6>  [5:9)\n"
           "  sarr -> 1 [6]\n"
           "  sarr :  1 [6]\n"
           "[6] struct[]  <6:7>  [6:9)\n"
           "[7] struct  <0:2>  [7:9)\n"
           "  value -> 1 [8]\n"
           "  value :  1 [8]\n"
           "[8] double  <1:2>  [8:9)\n"
           "[9] any  <7:8>  [9:10)\n"
           "[10] any[]  <8:9>  [10:11)\n"
           "[11] union  <9:10>  [11:14)\n"
           "  a -> 1 [12]\n"
           "  b -> 2 [13]\n"
           "  a :  1 [12]\n"
           "  b :  2 [13]\n"
           "[12] float  <0:1>  [12:13)\n"
           "[13] string  <0:1>  [13:14)\n"
           "[14] union[]  <10:11>  [14:18)\n"
           "[15] union  <0:3>  [15:18)\n"
           "  x -> 1 [16]\n"
           "  y -> 2 [17]\n"
           "  x :  1 [16]\n"
           "  y :  2 [17]\n"
           "[16] float  <1:2>  [16:17)\n"
           "[17] float  <2:3>  [17:18)\n"
           "");

    // try to access all field Kinds

    // sub-struct and scalar
    val["timeStamp.secondsPastEpoch"] = 0x123456789abcdef0ull;
    // array of scalar
    {
        shared_array<double> arr({1.0, 2.0});

        val["value"].from(shared_array_static_cast<const void>(freeze(std::move(arr))));
    }
    // Struct[]
    {
        auto fld = val["arbitrary.sarr"];
        shared_array<Value> arr(3);
        arr[0] = fld.allocMember();
        arr[1] = fld.allocMember();
        // leave [2] as null
        arr[0]["value"] = 1.0;
        arr[1]["value"] = 2.0;

//        auto frozen = freeze(std::move(arr));
//        auto varr = shared_array_static_cast<const void>(frozen);
//        fld.from(varr);
        fld.from(shared_array_static_cast<const void>(freeze(std::move(arr))));

        testEq(val["arbitrary.sarr[1]value"].as<double>(), 2.0);
    }

    // Union
    val["choice->b"] = "test";
    // Union[]
    {
        auto fld = val["achoice"];
        shared_array<Value> arr(3);
        arr[0] = fld.allocMember();
        arr[1] = fld.allocMember();
        // leave [2] as null
        arr[0]["->x"] = 4.0;
        arr[1]["->y"] = 5.0;

        fld.from(shared_array_static_cast<const void>(freeze(std::move(arr))));

        testEq(fld["[1]"].as<double>(), 5.0);
        testEq(val["achoice[1]"].as<double>(), 5.0);
        testEq(val["achoice[1]->y"].as<double>(), 5.0);
    }

    // Any
    {
        auto v = TypeDef(TypeCode::UInt32).create();
        v = 42u;

        val["any"].from(v);

        testEq(v.as<uint64_t>(), 42u);
    }

    // Any[]
    {
        auto fld = val["anya"];
        shared_array<Value> arr(3);
        arr[0] = TypeDef(TypeCode::UInt32).create();
        arr[1] = TypeDef(TypeCode::Struct)
                .begin()
                .insert("q", TypeCode::String)
                .create();
        // leave [2] as null

        arr[0] = 123;
        arr[1]["q"] = "theq";

        fld.from(shared_array_static_cast<const void>(freeze(std::move(arr))));

        testEq(fld["[0]"].as<uint64_t>(), 123u);
        testEq(fld["[1]q"].as<std::string>(), "theq");
    }

    testShow()<<val;
    testEq(std::string(SB()<<val),
           "struct \"simple_t\" {\n"
           "    double[] value = {2}[1, 2]\n"
           "    struct \"time_t\" {\n"
           "        uint64_t secondsPastEpoch = 1311768467463790320\n"
           "        uint32_t nanoseconds = 0\n"
           "    } timeStamp\n"
           "    struct {\n"
           "        struct[] sarr [\n"
           "            struct {\n"
           "                double value = 1\n"
           "            }\n"
           "            struct {\n"
           "                double value = 2\n"
           "            }\n"
           "            null\n"
           "        ]\n"
           "    } arbitrary\n"
           "    any any        uint32_t = 42\n"
           "    any[] anya [\n"
           "        uint32_t = 123\n"
           "        struct {\n"
           "            string q = \"theq\"\n"
           "        }\n"
           "        null\n"
           "    ]\n"
           "    union choice.b        string = \"test\"\n"
           "    union[] achoice [\n"
           "        union.x            float = 4\n"
           "        union.y            float = 5\n"
           "        null\n"
           "    ]\n"
           "}\n");
}

} // namespace

MAIN(testdata)
{
    testPlan(23);
    showSize();
    testBasic();
    testTypeDef();
    cleanup_for_valgrind();
    return testDone();
}
