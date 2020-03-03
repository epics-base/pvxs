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
    CASE(IValue);
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
    testEq(std::string(SB()<<"\n"<<ValueBase::Helper::desc(val)),
R"out(
[0] struct simple_t parent=[0]  [0:11)
    achoice -> 10 [10]
    any -> 7 [7]
    anya -> 8 [8]
    arbitrary -> 5 [5]
    arbitrary.sarr -> 6 [6]
    choice -> 9 [9]
    timeStamp -> 2 [2]
    timeStamp.nanoseconds -> 4 [4]
    timeStamp.secondsPastEpoch -> 3 [3]
    value -> 1 [1]
    value :  1 [1]
    timeStamp :  2 [2]
    arbitrary :  5 [5]
    any :  7 [7]
    anya :  8 [8]
    choice :  9 [9]
    achoice :  10 [10]
[1] double[]  parent=[0]  [1:2)
[2] struct time_t parent=[0]  [2:5)
    nanoseconds -> 2 [4]
    secondsPastEpoch -> 1 [3]
    secondsPastEpoch :  1 [3]
    nanoseconds :  2 [4]
[3] uint64_t  parent=[2]  [3:4)
[4] uint32_t  parent=[2]  [4:5)
[5] struct  parent=[0]  [5:7)
    sarr -> 1 [6]
    sarr :  1 [6]
[6] struct[]  parent=[5]  [6:7)
    [0] struct  parent=[0]  [0:2)
        value -> 1 [1]
        value :  1 [1]
    [1] double  parent=[0]  [1:2)
[7] any  parent=[0]  [7:8)
[8] any[]  parent=[0]  [8:9)
[9] union  parent=[0]  [9:10)
    a -> 0 [0]
    b -> 1 [1]
    a :  0 [0]
    [0] float  parent=[0]  [0:1)
    b :  1 [1]
    [0] string  parent=[0]  [0:1)
[10] union[]  parent=[0]  [10:11)
    [0] union  parent=[0]  [0:1)
        x -> 0 [0]
        y -> 1 [1]
        x :  0 [0]
        [0] float  parent=[0]  [0:1)
        y :  1 [1]
        [0] float  parent=[0]  [0:1)
)out")<<"Actual:\n"<<ValueBase::Helper::desc(val);

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
        shared_array<IValue> arr(3);
        auto temp = fld.allocMember();
        temp["value"] = 1.0;
        arr[0] = temp.freeze();
        temp = fld.allocMember();
                temp["value"] = 2.0;
        arr[1] = temp.freeze();
        // leave [2] as null

        fld = arr.freeze().castTo<const void>();

        auto snap = val.clone().freeze();

        testEq(snap["arbitrary.sarr[1]value"].as<double>(), 2.0);
    }

    // Union
    val["choice->b"] = "test";
    // Union[]
    {
        auto fld = val["achoice"];
        shared_array<IValue> arr(3);
        auto temp = fld.allocMember();
        temp["->x"] = 4.0;
        arr[0] = temp.freeze();
        temp = fld.allocMember();
        temp["->y"] = 5.0;
        arr[1] = temp.freeze();
        // leave [2] as null

        fld = arr.freeze().castTo<const void>();

        auto snap = val.clone().freeze();

        testEq(snap["achoice"]["[1]"].as<double>(), 5.0);
        testEq(snap["achoice[1]"].as<double>(), 5.0);
        testEq(snap["achoice[1]->y"].as<double>(), 5.0);
    }

    // Any
    {
        auto v = TypeDef(TypeCode::UInt32).create();
        v = 42u;

        val["any"].from(v.freeze());

        auto snap = val.clone().freeze();

        testEq(snap["any"].as<uint64_t>(), 42u);
    }

    // Any[]
    {
        auto fld = val["anya"];
        shared_array<IValue> arr(3);
        auto temp = TypeDef(TypeCode::UInt32).create();
        temp = 123;
        arr[0] = temp.freeze();
        temp = TypeDef(TypeCode::Struct, {Member(TypeCode::String, "q")}).create();
        temp["q"] = "theq";
        arr[1] = temp.freeze();
        // leave [2] as null

        fld = arr.freeze().castTo<const void>();

        auto snap = val.clone().freeze();

        testEq(snap["anya"]["[0]"].as<uint64_t>(), 123u);
        testEq(snap["anya[1]q"].as<std::string>(), "theq");
    }

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
           "}\n")<<"Actual:\n"<<val;
}

} // namespace

MAIN(testtype)
{
    testPlan(23);
    showSize();
    testBasic();
    testTypeDef();
    cleanup_for_valgrind();
    return testDone();
}
