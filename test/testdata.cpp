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

template<size_t N>
testCase
testBytes(const std::vector<uint8_t>& actual, const char(&buf)[N])
{
    bool ok = actual.size()==(N-1) && std::equal(actual.begin(),
                                                 actual.end(),
                                                 (const uint8_t*)buf);

    testCase ret(ok);
    ret<<"Expect: \""<<escape(std::string((const char*)buf, N-1))<<"\"\n"
       <<"Actual: \""<<escape(std::string((const char*)actual.data(), actual.size()))<<"\"\n";
    return ret;
}

template<typename Fn, size_t N>
void testToBytes(bool be, Fn&& fn, const char(&expect)[N])
{
    std::vector<uint8_t> buf;
    VectorOutBuf S(be, buf);
    fn(S);
    buf.resize(buf.size()-S.size());
    testBytes(buf, expect);
}

template<typename Fn, size_t N>
void testFromBytes(bool be, const char(&input)[N], Fn&& fn)
{
    std::vector<uint8_t> buf(input, input+N-1);
    FixedBuf S(be, buf);
    fn(S);
    testCase(S.good() && S.empty())<<"Deserialize \""<<escape(std::string((const char*)input, N-1))<<"\" leaves "<<S.good()<<" "<<S.size();
}

void testSerialize1()
{
    testDiag("%s", __func__);

    auto val = nt::NTScalar{TypeCode::UInt32}.build().create();

    testToBytes(true, [&val](Buffer& buf) {
        to_wire_full(buf, val);
    }, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

    testToBytes(true, [&val](Buffer& buf) {
        to_wire_valid(buf, val);
    }, "\x00");

    val["value"] = 0xdeadbeef;

    testToBytes(true, [&val](Buffer& buf) {
        to_wire_valid(buf, val);
    }, "\x01\x02\xde\xad\xbe\xef");

    val["value"].unmark();

    testToBytes(true, [&val](Buffer& buf) {
        to_wire_valid(buf, val);
    }, "\x00");

    val["timeStamp.nanoseconds"] = 0xab;
    val["alarm.message"] = "hello world";

    testToBytes(true, [&val](Buffer& buf) {
        to_wire_valid(buf, val);
    }, "\x02 \x01\x0bhello world\x00\x00\x00\xab");
}

void testDeserialize1()
{
    testDiag("%s", __func__);

    {
        TypeStore ctxt;
        auto val = nt::NTScalar{TypeCode::UInt32}.build().create();
        testFromBytes(true, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_full(buf, ctxt, val);
        });
    }

    {
        TypeStore ctxt;
        auto val = nt::NTScalar{TypeCode::UInt32}.build().create();
        testFromBytes(true, "\x00",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
    }

    {
        TypeStore ctxt;
        auto val = nt::NTScalar{TypeCode::UInt32}.build().create();
        testFromBytes(true, "\x01\x02\xde\xad\xbe\xef",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!!val["value"].isMarked());
        testOk1(!val["timeStamp.nanoseconds"].isMarked());
        testEq(val["value"].as<uint32_t>(), 0xdeadbeef);
    }

    {
        TypeStore ctxt;
        auto val = nt::NTScalar{TypeCode::UInt32}.build().create();
        testFromBytes(true, "\x02 \x01\x0bhello world\x00\x00\x00\xab",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["timeStamp.nanoseconds"].isMarked());
        testOk1(!!val["alarm.message"].isMarked());
        testEq(val["value"].as<uint32_t>(), 0u);
        testEq(val["timeStamp.nanoseconds"].as<uint32_t>(), 0xabu);
        testEq(val["alarm.message"].as<std::string>(), "hello world");
    }

}

TypeDef simpledef(TypeCode::Struct, "simple_t", {
                Member(TypeCode::Float64A, "value"),
                Member(TypeCode::Struct, "timeStamp", "time_t", {
                    Member(TypeCode::UInt64, "secondsPastEpoch"),
                    Member(TypeCode::UInt32, "nanoseconds"),
                }),
                Member(TypeCode::Struct, "arbitrary", {
                    Member(TypeCode::StructA, "sarr", {
                        Member(TypeCode::UInt32, "value"),
                    }),
                }),
                Member(TypeCode::Any, "any"),
                Member(TypeCode::AnyA, "anya"),
                Member(TypeCode::Union, "choice", {
                    Member(TypeCode::Float32, "a"),
                    Member(TypeCode::String, "b"),
                }),
                Member(TypeCode::UnionA, "achoice", {
                    Member(TypeCode::String, "x"),
                    Member(TypeCode::String, "y"),
                }),
            });

void testSimpleDef()
{
    testDiag("%s", __func__);

    auto val = simpledef.create();

    testEq(std::string(SB()<<"\n"<<Value::Helper::desc(val)),
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
    [1] uint32_t  parent=[0]  [1:2)
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
        [0] string  parent=[0]  [0:1)
        y :  1 [1]
        [0] string  parent=[0]  [0:1)
)out")<<"Actual:\n"<<Value::Helper::desc(val);
}

void testSerialize2()
{
    testDiag("%s", __func__);

    {
        auto val = simpledef.create();

        auto fld = val["arbitrary.sarr"];
        shared_array<Value> arr(3);
        arr[0] = fld.allocMember();
        arr[1] = fld.allocMember();
        // leave [2] as null
        arr[0]["value"] = 0xdeadbeef;
        arr[1]["value"] = 0x1badface;

        fld = arr.freeze().castTo<const void>();

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x01@\x03\x01\xde\xad\xbe\xef\x01\x1b\xad\xfa\xce\x00");
    }

    {
        auto val = simpledef.create();

        val["choice->b"] = "test";
        testOk1(!!val["choice"].isMarked());

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x02\x00\x02\x01\x04test");
    }

    {
        auto val = simpledef.create();

        auto fld = val["achoice"];
        shared_array<Value> arr(3);
        arr[0] = fld.allocMember();
        arr[1] = fld.allocMember();
        // leave [2] as null
        arr[0]["->x"] = "theX";
        arr[1]["->y"] = "theY";

        fld = arr.freeze().castTo<const void>();

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x02\x00\x04\x03\x01\x00\x04theX\x01\x01\x04theY\x00");
    }

    // Any
    {
        auto val = simpledef.create();

        auto v = TypeDef(TypeCode::UInt32).create();
        v = 0x600df00d;

        val["any"].from(v);

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x01\x80\x26\x60\x0d\xf0\x0d");
    }

    // Any
    {
        auto val = simpledef.create();
        val["any"].mark();

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x01\x80\xff");
    }

    // Any[]
    {
        auto val = simpledef.create();

        auto fld = val["anya"];
        shared_array<Value> arr(3);
        arr[0] = TypeDef(TypeCode::UInt32).create();
        arr[1] = TypeDef(TypeCode::Struct, {Member(TypeCode::String, "q")}).create();
        // leave [2] as null

        arr[0] = 0x7b;
        arr[1]["q"] = "theq";

        fld = arr.freeze().castTo<const void>();

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x02\x00\x01\x03\x01\x26\x00\x00\x00\x7b\x01\x80\x00\x01\x01q\x60\x04theq\x00");
    }
}

void testDeserialize2()
{
    testDiag("%s", __func__);

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x01@\x03\x01\xde\xad\xbe\xef\x01\x1b\xad\xfa\xce\x00",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["arbitrary.sarr"].isMarked());
        testEq(val["arbitrary.sarr"].as<shared_array<const void>>().size(), 3u*sizeof(Value));
        testEq(val["arbitrary.sarr[0]value"].as<uint32_t>(), 0xdeadbeef);
        testEq(val["arbitrary.sarr[1]value"].as<uint32_t>(), 0x1badfaceu);
        testEq(val["arbitrary.sarr[2]value"].type(), TypeCode::Null);
    }

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x02\x00\x02\x01\x04test",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["choice"].isMarked());
        testEq(val["choice"].as<std::string>(), "test");
    }

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x02\x00\x04\x03\x01\x00\x04theX\x01\x01\x04theY\x00",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["achoice"].isMarked());
        testEq(val["achoice"].as<shared_array<const void>>().size(), 3u*sizeof(Value));
        testEq(val["achoice[0]"].as<std::string>(), "theX");
        testEq(val["achoice[1]"].as<std::string>(), "theY");
        testEq(val["achoice[2]"].type(), TypeCode::Null);
    }

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x01\x80\x26\x60\x0d\xf0\x0d",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["any"].isMarked());
        testEq(val["any"].as<uint32_t>(), 0x600df00du);
    }

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x01\x80\xff",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["any"].isMarked());
        //testEq(val["any"].type(), TypeCode::Null); determine type _inside_ Any?
    }

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x02\x00\x01\x03\x01\x26\x00\x00\x00\x7b\x01\x80\x00\x01\x01q\x60\x04theq\x00",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["anya"].isMarked());
        testEq(val["anya"].as<shared_array<const void>>().size(), 3u*sizeof(Value));
        testEq(val["anya[0]"].as<uint32_t>(), 0x7bu);
        testEq(val["anya[1]q"].as<std::string>(), "theq");
        testEq(val["anya[2]"].type(), TypeCode::Null);
    }
}

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
    testPlan(79);
    testSerialize1();
    testDeserialize1();
    testSimpleDef();
    testSerialize2();
    testDeserialize2();
    testTraverse();
    testAssign();
    testName();
    testIter();
    testPvRequest();
    cleanup_for_valgrind();
    return testDone();
}
