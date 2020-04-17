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
    CASE(BitMask);
#undef CASE
}

void testBasic()
{
    testDiag("%s()", __func__);

    auto top = TypeDef(TypeCode::Struct, "simple_t", {
                           Member(TypeCode::Float64, "value"),
                       }).create();

    testOk1(top.valid());
    testEq(top.type(), TypeCode::Struct);

    {
        auto val = top["missing"];
        testOk1(!val.valid());
        testOk1(!val.isMarked());

        testThrows<NoField>([&val]() {
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

    testEq(std::string(SB()<<TypeDef(TypeCode::Struct, "simple_t", {})),
           "struct \"simple_t\"\n");

    TypeDef def(TypeCode::Struct, "simple_t", {
                    Member(TypeCode::Float64A, "value"),
                    Member(TypeCode::Struct, "timeStamp", "time_t", {
                        Member(TypeCode::UInt64, "secondsPastEpoch"),
                        Member(TypeCode::UInt32, "nanoseconds"),
                    }),
                    Member(TypeCode::Struct, "arbitrary", {
                        Member(TypeCode::StructA, "sarr", {
                            Member(TypeCode::Float64, "value"),
                        }),
                    }),
                    Member(TypeCode::Any, "any"),
                    Member(TypeCode::AnyA, "anya"),
                    Member(TypeCode::Union, "choice", {
                        Member(TypeCode::Float32, "a"),
                        Member(TypeCode::String, "b"),
                    }),
                    Member(TypeCode::UnionA, "achoice", {
                        Member(TypeCode::Float32, "x"),
                        Member(TypeCode::Float32, "y"),
                    }),
                });


    testShow()<<def;

    testStrEq(std::string(SB()<<def),
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
    testStrEq(std::string(SB()<<Value::Helper::desc(val)),
        "[0] struct simple_t parent=[0]  [0:11)\n"
        "    achoice -> 10 [10]\n"
        "    any -> 7 [7]\n"
        "    anya -> 8 [8]\n"
        "    arbitrary -> 5 [5]\n"
        "    arbitrary.sarr -> 6 [6]\n"
        "    choice -> 9 [9]\n"
        "    timeStamp -> 2 [2]\n"
        "    timeStamp.nanoseconds -> 4 [4]\n"
        "    timeStamp.secondsPastEpoch -> 3 [3]\n"
        "    value -> 1 [1]\n"
        "    value :  1 [1]\n"
        "    timeStamp :  2 [2]\n"
        "    arbitrary :  5 [5]\n"
        "    any :  7 [7]\n"
        "    anya :  8 [8]\n"
        "    choice :  9 [9]\n"
        "    achoice :  10 [10]\n"
        "[1] double[]  parent=[0]  [1:2)\n"
        "[2] struct time_t parent=[0]  [2:5)\n"
        "    nanoseconds -> 2 [4]\n"
        "    secondsPastEpoch -> 1 [3]\n"
        "    secondsPastEpoch :  1 [3]\n"
        "    nanoseconds :  2 [4]\n"
        "[3] uint64_t  parent=[2]  [3:4)\n"
        "[4] uint32_t  parent=[2]  [4:5)\n"
        "[5] struct  parent=[0]  [5:7)\n"
        "    sarr -> 1 [6]\n"
        "    sarr :  1 [6]\n"
        "[6] struct[]  parent=[5]  [6:7)\n"
        "    [0] struct  parent=[0]  [0:2)\n"
        "        value -> 1 [1]\n"
        "        value :  1 [1]\n"
        "    [1] double  parent=[0]  [1:2)\n"
        "[7] any  parent=[0]  [7:8)\n"
        "[8] any[]  parent=[0]  [8:9)\n"
        "[9] union  parent=[0]  [9:10)\n"
        "    a -> 0 [0]\n"
        "    b -> 1 [1]\n"
        "    a :  0 [0]\n"
        "    [0] float  parent=[0]  [0:1)\n"
        "    b :  1 [1]\n"
        "    [0] string  parent=[0]  [0:1)\n"
        "[10] union[]  parent=[0]  [10:11)\n"
        "    [0] union  parent=[0]  [0:1)\n"
        "        x -> 0 [0]\n"
        "        y -> 1 [1]\n"
        "        x :  0 [0]\n"
        "        [0] float  parent=[0]  [0:1)\n"
        "        y :  1 [1]\n"
        "        [0] float  parent=[0]  [0:1)\n"
    );

    // try to access all field Kinds

    // sub-struct and scalar
    val["timeStamp.secondsPastEpoch"] = 0x123456789abcdef0ull;
    // array of scalar
    {
        shared_array<double> arr({1.0, 2.0});

        val["value"] = arr.freeze().castTo<const void>();
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

        fld = arr.freeze().castTo<const void>();

        testEq(val["arbitrary.sarr[1].value"].as<double>(), 2.0);
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

        fld = arr.freeze().castTo<const void>();

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
        arr[1] = TypeDef(TypeCode::Struct, {Member(TypeCode::String, "q")}).create();
        // leave [2] as null

        arr[0] = 123;
        arr[1]["q"] = "theq";

        fld = arr.freeze().castTo<const void>();

        testEq(fld["[0]"].as<uint64_t>(), 123u);
        testEq(fld["[1].q"].as<std::string>(), "theq");
    }

    testStrEq(std::string(SB()<<val),
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

//! Returns the frankenstruct
Value neckBolt()
{
    using namespace pvxs::members;
    return TypeDef(TypeCode::Struct, "top_t", {
                       Struct("scalar", {
                           Int32("i32"),
                           UInt32("u32"),
                           Bool("b"),
                           Float64("f64"),
                           String("s"),
                           Any("wildcard"),
                           Union("choice", {
                               Int32("one"),
                               Struct("two", {
                                   Int32("ahalf"),
                               }),
                           }),
                       }),
                       Struct("array", {
                           Int32A("i32"),
                           StringA("s"),
                           AnyA("wildcard"),
                           UnionA("choice", {
                               Int32("one"),
                               Struct("two", {
                                   Int32("ahalf"),
                               }),
                           }),
                           StructA("more", {
                               Int32("one"),
                               Struct("two", {
                                   Int32("ahalf"),
                               }),
                           }),
                       }),
                   }).create();
}

void testFormat()
{
    testDiag("%s()", __func__);

    Value top(neckBolt());

    top["scalar.i32"] = -42;
    top["scalar.u32"] = 42;
    top["scalar.b"] = true;
    top["scalar.f64"] = 123.5;
    top["scalar.s"] = "a \"test\"";
    top["scalar.wildcard"] = "simple";
    top["scalar.choice->one"] = 1024;

    top["array.i32"] = shared_array<int32_t>({1,-1,2,-3}).freeze().castTo<const void>();
    top["array.s"] = shared_array<std::string>({"one", "two", "three"}).freeze().castTo<const void>();
    {
        auto fld = top["array.wildcard"];
        shared_array<Value> arr(2);
        auto temp = arr[0] = TypeDef(TypeCode::String).create();
        // arr[1] left null
        temp = "simple";
        fld = arr.freeze().castTo<const void>();
    }
    {
        auto fld = top["array.choice"];
        shared_array<Value> arr(3);
        (arr[0] = fld.allocMember())["->one"] = 1357;
        // arr[1] left null
        (arr[2] = fld.allocMember())["->two.ahalf"] = 2468;
        fld = arr.freeze().castTo<const void>();

    }

    testStrEq(std::string(SB()<<top.format()),
        "struct \"top_t\" {\n"
        "    struct {\n"
        "        int32_t i32 = -42\n"
        "        uint32_t u32 = 42\n"
        "        bool b = true\n"
        "        double f64 = 123.5\n"
        "        string s = \"a \\\"test\\\"\"\n"
        "        any wildcard            string = \"simple\"\n"
        "        union choice.one            int32_t = 1024\n"
        "    } scalar\n"
        "    struct {\n"
        "        int32_t[] i32 = {4}[1, -1, 2, -3]\n"
        "        string[] s = {3}[one, two, three]\n"
        "        any[] wildcard [\n"
        "            string = \"simple\"\n"
        "            null\n"
        "        ]\n"
        "        union[] choice [\n"
        "            union.one                int32_t = 1357\n"
        "            null\n"
        "            union.two                struct {\n"
        "                    int32_t ahalf = 2468\n"
        "                }\n"
        "        ]\n"
        "        struct[] more = {\?}[]\n"
        "    } array\n"
        "}\n"
    );

    top.mark();

    testStrEq(std::string(SB()<<top.format().delta()),
        "struct \"top_t\"\n"
        "scalar struct\n"
        "scalar.i32 int32_t = -42\n"
        "scalar.u32 uint32_t = 42\n"
        "scalar.b bool = true\n"
        "scalar.f64 double = 123.5\n"
        "scalar.s string = \"a \\\"test\\\"\"\n"
        "scalar.wildcard any\n"
        "scalar.wildcard-> string = \"simple\"\n"
        "scalar.choice union\n"
        "scalar.choice->one int32_t = 1024\n"
        "array struct\n"
        "array.i32 int32_t[] = {4}[1, -1, 2, -3]\n"
        "array.s string[] = {3}[one, two, three]\n"
        "array.wildcard any[]\n"
        "array.wildcard[0] string = \"simple\"\n"
        "array.wildcard[1] null\n"
        "array.choice union[]\n"
        "array.choice[0] union\n"
        "array.choice[0]->one int32_t = 1357\n"
        "array.choice[1] null\n"
        "array.choice[2] union\n"
        "array.choice[2]->two struct\n"
        "array.choice[2]->two.ahalf int32_t = 2468\n"
        "array.more struct[] = {\?}[]\n"
    );
}

} // namespace

MAIN(testtype)
{
    testPlan(25);
    showSize();
    testBasic();
    testTypeDef();
    testFormat();
    cleanup_for_valgrind();
    return testDone();
}
