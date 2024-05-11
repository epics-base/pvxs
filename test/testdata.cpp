/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <epicsUnitTest.h>
#include <alarm.h>

#include <pvxs/unittest.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>
#include "utilpvt.h"
#include "pvaproto.h"
#include "dataimpl.h"

using namespace pvxs;
namespace  {

void testTraverse()
{
    testDiag("%s", __func__);

    auto top = nt::NTScalar{TypeCode::Int32, true}.create();

    testOk1(!top["<"].valid());

    testThrows<std::runtime_error>([&top](){
        top.lookup("<");
    });

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

    val["alarm.severity"] = INVALID_ALARM;
    testEq(val["alarm.severity"].as<epicsAlarmSeverity>(), INVALID_ALARM);
}

void testAssignArray()
{
    testDiag("%s", __func__);

    auto val = TypeDef(TypeCode::Int32A).create();

    val = shared_array<const int32_t>({1, 2, 3});

    val = shared_array<const int16_t>({4, 5, 6}); // with implied conversion
}

void testAssignUnion()
{
    testDiag("%s", __func__);

    auto val = TypeDef(TypeCode::Union, {
                           members::UInt16("u16"),
                           members::String("s"),
                       }).create();

    val["->u16"] = 42;
    testEq(val.as<std::string>(), "42");
    val["->s"] = "test";
    testEq(val.as<std::string>(), "test");

    testEq(val.nameOf(val["->"]), "s");

    val = unselect;

    testFalse(val["->"].valid());

    testThrows<NoConvert>([&val](){
        val["->u16"] = "hello";
    });

    // previous selection succeeds, but assignment fails
    testTrue(val["->"].valid());
}

void testAssignAny()
{
    testDiag("%s", __func__);

    auto val = TypeDef(TypeCode::Any).create();

    // check the simple self assignment is an error.
    testThrows<std::logic_error>([&val](){
        val.from(val);
    });

    val = 42;

    testThrows<std::logic_error>([&val](){
        val.from(val);
    });
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

void testIterStruct()
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

    testMarked(4u)<<"mark alarm sub-struct";

    val.unmark();
    val["value"].mark(); // 1 field
    val["alarm.status"].mark(); // 1 field
    val["timeStamp"].mark(); // 4 fields (struct node and 3x leaves)

    testMarked(6u)<<"mark multiple sub-struct";

    val["timeStamp.nanoseconds"].unmark(true);

    testMarked(2u)<<"mark multiple sub-struct";
}

void testIterUnion()
{
    testDiag("%s", __func__);

    auto top = TypeDef(TypeCode::Union, {
                           members::UInt32("A"),
                           members::String("B"),
                       }).create();

    {
        auto it = top.iall().begin();
        auto end = top.iall().end();
        if(testOk1(it!=end))
            testEq(top.nameOf(*it), "A");
        ++it;
        if(testOk1(it!=end))
            testEq(top.nameOf(*it), "B");
        ++it;
        testOk1(it==end);
    }

    {
        auto it = top.ichildren().begin();
        auto end = top.ichildren().end();
        if(testOk1(it!=end))
            testEq(top.nameOf(*it), "A");
        ++it;
        if(testOk1(it!=end))
            testEq(top.nameOf(*it), "B");
        ++it;
        testOk1(it==end);
    }

    testOk(top.imarked().begin()==top.imarked().end(), "imarked() empty");

    top["->A"] = 42;

    {
        auto it = top.imarked().begin();
        auto end = top.imarked().end();
        if(testOk1(it!=end))
            testEq(top.nameOf(*it), "A");
        ++it;
        testOk1(it==end);
    }

    top["->B"] = "test";

    {
        auto it = top.imarked().begin();
        auto end = top.imarked().end();
        if(testOk1(it!=end))
            testEq(top.nameOf(*it), "B");
        ++it;
        testOk1(it==end);
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

template<typename Store, typename In, typename Out>
void testConvertScalar2(const Store& store, const In& in, const Out& out)
{
    testShow()<<__func__<<"("<<store<<","<<in<<","<<out<<")";

    typedef impl::ScalarMap<Store> store_t;

    auto cont = TypeDef(store_t::code).create();

    try {
        cont.from(in);
    }catch(std::exception& e){
        testCase(false)<<"Error storing as "<<typeid (Store).name()<<" "<<in<<" : "<<e.what();
    }

    testEq(store, cont.as<Store>())<<typeid(Store).name();

    testEq(out, cont.as<Out>())<<typeid(Store).name()<<"->"<<typeid(Out).name();
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

void testAssignSimilarNDArray()
{
    testShow()<<__func__;

    Value val1, val2;
    using namespace pvxs::members;
    {
        auto def(nt::NTNDArray{}.build());
        def += {
                StructA("dimensions", {
                            Int32("val1"),
                        }),
        };
        val1 = def.create();
    }
    {
        auto def(nt::NTNDArray{}.build());
        def += {
                StructA("dimensions", {
                            Int32("val2"),
                        }),
        };
        val2 = def.create();
    }

    testFalse(val1.equalType(val2));
    testTrue(val1["dimension"].equalType(val2["dimension"]));

    val1.from(val2); // nothing marked, so a no-op

    shared_array<const uint8_t> pixels({1,2,3,4,5,6});
    val1["value->ubyteValue"] = pixels;
    shared_array<Value> dims;//(2);
    dims.resize(2);
    dims[0] = val1["dimension"].allocMember()
            .update("size", 12);
    dims[1] = dims[0].cloneEmpty()
            .update("size", 34);
    val1["dimension"] = dims.freeze();

    val2.from(val1);

    testTrue(val2["value"].isMarked(false,false));
    testTrue(val2["dimension"].isMarked(false,false));
    testFalse(val2["timeStamp"].isMarked(true, true));
    testArrEq(pixels, val2["value"].as<shared_array<const uint8_t>>());
    testEq(val2["dimension[0].size"].as<uint32_t>(), 12u);
    testEq(val2["dimension[1].size"].as<uint32_t>(), 34u);
}

void testUnionMagicAssign()
{
    testShow()<<__func__;

    using namespace members;
    auto val(TypeDef(TypeCode::Union, {
                         UInt16("x"),
                         Float64("y"),
                     }).create());

    val = 5;
    testEq(val.nameOf(val["->"]), "x");
    testEq(val.as<std::string>(), "5");

    val = unselect;

    testThrows<NoConvert>([&val](){
        val = "invalid";
    });
}

void testExtract()
{
    testShow()<<__func__;

    auto top = nt::NTScalar{TypeCode::Int32}.create();

    top["value"] = 42;

    testEq(top["value"].as<int32_t>(), 42);
    {
        int32_t val = -1;
        testTrue(top["value"].as(val));
        testEq(val, 42);
    }
    {
        std::string val("canary");
        testTrue(top["value"].as(val));
        testEq(val, "42");
    }
    {
        bool ran = false;
        top["value"].as<int32_t>([&ran](const int32_t& v) {
            testEq(v, 42);
            ran = true;
        });
        testTrue(ran);
    }
}

void testClear()
{
    testShow()<<__func__;

    auto val = TypeDef(TypeCode::Struct, {
                           members::UInt32("int"),
                           members::String("string"),
                           members::UInt32A("arr"),
                           members::Any("any"),
                       }).create();

    val["int"] = 0x12345678;
    val["string"] = "testing";
    val["arr"] = shared_array<const uint32_t>({1,2,3});
    val["any"].assign(nt::NTScalar{TypeCode::UInt32}.create());
    val["any->value"] = 0x01020304;

    testEq(val["int"].as<uint32_t>(), 0x12345678u);
    testEq(val["string"].as<std::string>(), std::string("testing"));
    testEq(val["arr"].as<shared_array<const void>>().size(), 3u);
    testTrue(!!val["any->"]);
    testEq(val["any->value"].as<uint32_t>(), 0x01020304u);
    testTrue(val.isMarked(true, true));

    val.clear();

    testEq(val["int"].as<uint32_t>(), 0u);
    testEq(val["string"].as<std::string>(), std::string(""));
    testEq(val["arr"].as<shared_array<const void>>().size(), 0u);
    testFalse(val["any->"]);
    testFalse(val.isMarked(true, true));
}

} // namespace

MAIN(testdata)
{
    testPlan(156);
    testSetup();
    testTraverse();
    testAssign();
    testAssignArray();
    testAssignUnion();
    testAssignAny();
    testName();
    testIterStruct();
    testIterUnion();

    testConvertScalar<bool, bool>(true, true);
    testConvertScalar<bool, uint32_t>(true, 1u);
    testConvertScalar<bool, int32_t>(true, 1);
    //testConvertScalar<bool, double>(true, 1.0); // TODO: define double -> bool
    testConvertScalar<bool, std::string>(true, "true");
    testConvertScalar<bool, std::string>(false, "false");
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
    testConvertScalar<uint32_t, int32_t>(0xffffffff, -1);
    testConvertScalar<uint32_t, int16_t>(0xffffffff, -1);
    testConvertScalar<uint16_t, int32_t>(0xffff, 0xffff);
    testConvertScalar<uint32_t, int32_t>(0x80000000, -2147483648);
    testConvertScalar<std::string, bool>("true", true);
    testConvertScalar<std::string, bool>("false", false);
    testConvertScalar<std::string, uint32_t>("5", 5);
    testConvertScalar<std::string, int32_t>("5", 5);
    testConvertScalar<std::string, int32_t>("-5", -5);
    testConvertScalar<std::string, double>("-5", -5.0);
    testConvertScalar<std::string, std::string>("-5", "-5");
#ifdef _MSC_VER
    // MSVC reads back 2147483648
    testTodoBegin("MSVC differs");
#endif
    testConvertScalar2<int32_t, uint64_t, int64_t>(-2147483648, 0x80000000, -2147483648);
    testTodoEnd();
    testConvertScalar2<int32_t, uint64_t, int64_t>(0, 0x100000000llu, -0);

    testAssignSimilar();
    testAssignSimilarNDArray();
    testUnionMagicAssign();
    testExtract();
    testClear();
    cleanup_for_valgrind();
    return testDone();
}
