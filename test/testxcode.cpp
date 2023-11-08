/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsUnitTest.h>
#include <testMain.h>

#include <string>

#include <pvxs/util.h>
#include <pvxs/unittest.h>
#include <pvxs/nt.h>
#include "dataimpl.h"
#include "pvaproto.h"

namespace {
using namespace pvxs;
using namespace pvxs::impl;


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

void testDeserializeString()
{
    testDiag("%s", __func__);

    {
        std::string dut("canary");
        testFromBytes(true, "\x00", [&dut](Buffer& buf) {
            from_wire(buf, dut);
        });
        testEq(dut, "");
    }

    {
        std::string dut("canary");
        testFromBytes(true, "\xff", [&dut](Buffer& buf) {
            from_wire(buf, dut);
        });
        testEq(dut, "");
    }

    {
        std::string dut("canary");
        testFromBytes(true, "\x0bhello world", [&dut](Buffer& buf) {
            from_wire(buf, dut);
        });
        testEq(dut, "hello world");
    }
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
                Member(TypeCode::UInt64A, "value"),
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
        "[1] uint64_t[]  parent=[0]  [1:2)\n"
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
        "    [1] uint32_t  parent=[0]  [1:2)\n"
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
        "        [0] string  parent=[0]  [0:1)\n"
        "        y :  1 [1]\n"
        "        [0] string  parent=[0]  [0:1)\n"
    );
}

void testSerialize2()
{
    testDiag("%s", __func__);

    {
        auto val = simpledef.create();

        val["value"] = shared_array<const uint64_t>({1u, 0xdeadbeef, 2u}).castTo<const void>();

        testToBytes(true, [&val](Buffer& buf) {
            to_wire_valid(buf, val);
        }, "\x01\x02\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x02");
    }

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
        testFromBytes(true, "\x01\x02\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x02",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!!val["value"].isMarked());
        testOk1(!val["arbitrary.sarr"].isMarked());
        testArrEq(val["value"].as<shared_array<const uint64_t>>(),
                  shared_array<const uint64_t>({1u, 0xdeadbeef, 2u}));
    }

    {
        TypeStore ctxt;
        auto val = simpledef.create();
        testFromBytes(true, "\x01@\x03\x01\xde\xad\xbe\xef\x01\x1b\xad\xfa\xce\x00",
                      [&val, &ctxt](Buffer& buf) {
            from_wire_valid(buf, ctxt, val);
        });
        testOk1(!val["value"].isMarked());
        testOk1(!!val["arbitrary.sarr"].isMarked());
        testEq(val["arbitrary.sarr"].as<shared_array<const void>>().size(), 3u);
        testEq(val["arbitrary.sarr[0].value"].as<uint32_t>(), 0xdeadbeef);
        testEq(val["arbitrary.sarr[1]"]["value"].as<uint32_t>(), 0x1badfaceu);
        testEq(val["arbitrary.sarr[2].value"].type(), TypeCode::Null);
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
        testEq(val["achoice"].as<shared_array<const void>>().size(), 3u);
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
        testEq(val["anya"].as<shared_array<const void>>().size(), 3u);
        testEq(val["anya[0]"].as<uint32_t>(), 0x7bu);
        testEq(val["anya[1].q"].as<std::string>(), "theq");
        testEq(val["anya[2]"].type(), TypeCode::Null);
    }
}

void testDeserialize3()
{
    testDiag("%s", __func__);

    {
        TypeStore ctxt;
        Value val;
        testFromBytes(false, "\xfd\x02\x00\x80\x00\x01\x06\x72\x65\x63\x6f\x72\x64\xfd\x03\x00\x80\x00"
                             "\x01\x08\x5f\x6f\x70\x74\x69\x6f\x6e\x73\xfd\x04\x00\x80\x00\x02\x09\x71"
                             "\x75\x65\x75\x65\x53\x69\x7a\x65\x60\x08\x70\x69\x70\x65\x6c\x69\x6e\x65"
                             "\x60\x01\x34\x04\x74\x72\x75\x65"
,
                      [&val, &ctxt](Buffer& buf) {
            from_wire_type_value(buf, ctxt, val);
        });
        testShow()<<val;
        testEq(val["record._options.pipeline"].as<std::string>(), "true");
        testEq(val["record._options.queueSize"].as<std::string>(), "4");
    }
}

void testDecode1()
{
    testDiag("%s", __func__);
    /*  From PVA proto doc
     *
     * timeStamp_t
     *   long secondsPastEpoch
     *   int nanoSeconds
     *   int userTag
     */
    std::vector<uint8_t> msg({
        // update cache with key 1
        0xFD, 0x00, 0x01,
        // structure
        0x80,
            // ID "timeStamp_t"
            0x0B, 0x74, 0x69, 0x6D, 0x65, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x5F, 0x74,
            // 3 members
            0x03,
                // "secondsPastEpoch"
                0x10, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73, 0x50, 0x61, 0x73, 0x74, 0x45, 0x70, 0x6F, 0x63, 0x68,
                    // integer signed 8 bytes
                    0x23,
                // "nanoSeconds"
                0x0B, 0x6E, 0x61, 0x6E, 0x6F, 0x53, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73,
                    // integer signed 4 bytes
                    0x22,
                // "userTag"
                0x07, 0x75, 0x73, 0x65, 0x72, 0x54, 0x61, 0x67,
                    // integer signed 4 bytes
                    0x22
    });

    auto descs(std::make_shared<std::vector<FieldDesc>>());
    TypeStore cache;

    {
        FixedBuf buf(true, msg);
        from_wire(buf, *descs, cache);
        testOk1(buf.good());
        testEq(buf.size(), 0u)<<"Of "<<msg.size();
    }

    testEq(cache.size(), 1u);
    {
        auto it = cache.find(1);
        if(testOk1(it!=cache.end())) {
            testEq(it->second.size(), 4u);
        }
    }

    if(testOk1(!descs->empty())) {
        testEq(descs->size(), descs->front().size());
    }

    //   cat <<EOF | sed -e 's|"|\\"|g' -e 's|^# |    "|' -e 's|$|\\n"|g'
    // paste in Actual
    testStrEq(std::string(SB()<<descs->data()),
           "[0] struct timeStamp_t parent=[0]  [0:4)\n"
           "    nanoSeconds -> 2 [2]\n"
           "    secondsPastEpoch -> 1 [1]\n"
           "    userTag -> 3 [3]\n"
           "    secondsPastEpoch :  1 [1]\n"
           "    nanoSeconds :  2 [2]\n"
           "    userTag :  3 [3]\n"
           "[1] int64_t  parent=[0]  [1:2)\n"
           "[2] int32_t  parent=[0]  [2:3)\n"
           "[3] int32_t  parent=[0]  [3:4)\n"
     );

    auto descs2(std::make_shared<std::vector<FieldDesc>>());
    {
        std::vector<uint8_t> msg({
            // Pull from cache with key 1
            0xFE, 0x00, 0x01});
        FixedBuf buf(true, msg);
        from_wire(buf, *descs2, cache);
        testOk1(buf.good());
        testEq(buf.size(), 0u)<<"Of "<<msg.size();
    }

    auto A(Value::Helper::build(std::shared_ptr<const FieldDesc>(descs, descs->data())));
    auto B(Value::Helper::build(std::shared_ptr<const FieldDesc>(descs2, descs2->data())));

    testTrue(A.equalType(B));
}

template<typename E, size_t N>
void testArrayXCodeT(const char(&encoded)[N], std::initializer_list<E> values)
{
    shared_array<const E> expected(values);

    auto code = TypeCode(ScalarMap<E>::code).arrayOf();
    TypeDef def(TypeCode::Struct, {Member(code, "value")});

    testToBytes(true, [&expected, &def](Buffer& buf) {
        auto val = def.create();
        val["value"] = expected;
        to_wire_valid(buf, val);
    }, encoded);

    TypeStore ctxt;
    auto val2 = def.create();

    testFromBytes(true, encoded,
                  [&ctxt, &val2](Buffer& buf) {
        from_wire_valid(buf, ctxt, val2);
    });

    testArrEq(expected, val2["value"].as<shared_array<const E>>());
}

void testArrayXCode()
{
    testDiag("%s", __func__);

    testArrayXCodeT<uint32_t>("\x01\x02\x00", {});
    testArrayXCodeT<uint32_t>("\x01\x02\x01\x12\x34\x56\x78", {0x12345678});
    testArrayXCodeT<uint16_t>("\x01\x02\x02\x00\x01\xff\xff", {1u, 0xffff});
    testArrayXCodeT<double>("\x01\x02\x01?\xf0\x00\x00\x00\x00\x00\x00", {1.0});
    testArrayXCodeT<std::string>("\x01\x02\x02\x05hello\x05world", {"hello", "world"});
}

/*  epics:nt/NTScalarArray:1.0
 *      double[] value
 *      alarm_t alarm
 *          int severity
 *          int status
 *          string message
 *      time_t timeStamp
 *          long secondsPastEpoch
 *          int nanoseconds
 *          int userTag
 */
const uint8_t NTScalar[] = "\x80\x1a""epics:nt/NTScalarArray:1.0\x03"
                            "\x05""valueK"
                            "\x05""alarm\x80\x07""alarm_t\x03"
                                "\x08""severity\""
                                "\x06""status\""
                                "\x07""message`"
                            "\ttimeStamp\x80\x06""time_t\x03"
                                "\x10""secondsPastEpoch#"
                                "\x0b""nanoseconds\""
                                "\x07""userTag\"";

void testXCodeNTScalar()
{
    testDiag("%s", __func__);

    std::vector<uint8_t> msg(NTScalar, NTScalar+sizeof(NTScalar)-1);
    std::vector<FieldDesc> descs;
    TypeStore cache;
    {
        FixedBuf buf(true, msg);
        from_wire(buf, descs, cache);
        testOk1(buf.good());
        testEq(buf.size(), 0u)<<"remaining of "<<msg.size();
    }

    if(testOk1(!descs.empty())) {
        testEq(descs.size(), descs.front().size());
    }

    testStrEq(std::string(SB()<<descs.data()),
           "[0] struct epics:nt/NTScalarArray:1.0 parent=[0]  [0:10)\n"
           "    alarm -> 2 [2]\n"
           "    alarm.message -> 5 [5]\n"
           "    alarm.severity -> 3 [3]\n"
           "    alarm.status -> 4 [4]\n"
           "    timeStamp -> 6 [6]\n"
           "    timeStamp.nanoseconds -> 8 [8]\n"
           "    timeStamp.secondsPastEpoch -> 7 [7]\n"
           "    timeStamp.userTag -> 9 [9]\n"
           "    value -> 1 [1]\n"
           "    value :  1 [1]\n"
           "    alarm :  2 [2]\n"
           "    timeStamp :  6 [6]\n"
           "[1] double[]  parent=[0]  [1:2)\n"
           "[2] struct alarm_t parent=[0]  [2:6)\n"
           "    message -> 3 [5]\n"
           "    severity -> 1 [3]\n"
           "    status -> 2 [4]\n"
           "    severity :  1 [3]\n"
           "    status :  2 [4]\n"
           "    message :  3 [5]\n"
           "[3] int32_t  parent=[2]  [3:4)\n"
           "[4] int32_t  parent=[2]  [4:5)\n"
           "[5] string  parent=[2]  [5:6)\n"
           "[6] struct time_t parent=[0]  [6:10)\n"
           "    nanoseconds -> 2 [8]\n"
           "    secondsPastEpoch -> 1 [7]\n"
           "    userTag -> 3 [9]\n"
           "    secondsPastEpoch :  1 [7]\n"
           "    nanoseconds :  2 [8]\n"
           "    userTag :  3 [9]\n"
           "[7] int64_t  parent=[6]  [7:8)\n"
           "[8] int32_t  parent=[6]  [8:9)\n"
           "[9] int32_t  parent=[6]  [9:10)\n"
    );

    testDiag("Round trip back to bytes");
    std::vector<uint8_t> out;
    out.reserve(msg.size());

    {
        VectorOutBuf buf(true, out);
        to_wire(buf, descs.data());
        testOk1(buf.good());
        out.resize(out.size()-buf.size());
    }

    testEq(msg.size(), out.size());
    testEq(msg, out);
}

// has a bit of everything...  (except array of union)
const uint8_t NTNDArray[] = "\x80\x16""epics:nt/NTNDArray:1.0\n"
                                "\x05value\x81\x00\x0b"
                                    "\x0c""booleanValue\x08"
                                    "\tbyteValue("
                                    "\nshortValue)"
                                    "\x08intValue*"
                                    "\tlongValue+"
                                    "\nubyteValue,"
                                    "\x0bushortValue-"
                                    "\tuintValue."
                                    "\nulongValue/"
                                    "\nfloatValueJ"
                                    "\x0b""doubleValueK"
                            "\x05""codec\x80\x07""codec_t\x02"
                                "\x04name`"
                                "\nparameters\x82"
                            "\x0e""compressedSize#"
                            "\x10uncompressedSize#"
                            "\x08uniqueId\""
                            "\rdataTimeStamp\x80\x06time_t\x03"
                                "\x10secondsPastEpoch#"
                                "\x0bnanoseconds\""
                                "\x07userTag\""
                            "\x05""alarm\x80\x07""alarm_t\x03"
                                "\x08severity\""
                                "\x06status\""
                                "\x07message`"
                            "\ttimeStamp\x80\x06time_t\x03"
                                "\x10secondsPastEpoch#"
                                "\x0bnanoseconds\""
                                "\x07userTag\""
                            "\tdimension\x88\x80\x0b""dimension_t\x05"
                                "\x04size\""
                                "\x06offset\""
                                "\x08""fullSize\""
                                "\x07""binning\""
                                "\x07reverse\x00"
                            "\tattribute\x88\x80\x18""epics:nt/NTAttribute:1.0\x08"
                                "\x04name`"
                                "\x05value\x82"
                                "\x04tagsh"
                                "\ndescriptor`"
                                "\x05""alarm\x80\x07""alarm_t\x03"
                                    "\x08severity\""
                                    "\x06status\""
                                    "\x07message`"
                                "\ttimestamp\x80\x06time_t\x03"
                                    "\x10secondsPastEpoch#"
                                    "\x0bnanoseconds\""
                                    "\x07userTag\""
                                "\nsourceType\""
                                "\x06source`";

void testXCodeNTNDArray()
{
    testDiag("%s", __func__);

    std::vector<uint8_t> msg(NTNDArray, NTNDArray+sizeof(NTNDArray)-1);
    std::vector<FieldDesc> descs;
    TypeStore cache;
    {
        FixedBuf buf(true, msg);
        from_wire(buf, descs, cache);
        testOk1(buf.good());
        testEq(buf.size(), 0u)<<"remaining of "<<msg.size();
    }

    if(testOk1(!descs.empty())) {
        testEq(descs.size(), descs.front().size());
    }

    testStrEq(std::string(SB()<<descs.data()),
        "[0] struct epics:nt/NTNDArray:1.0 parent=[0]  [0:22)\n"
        "    alarm -> 12 [12]\n"
        "    alarm.message -> 15 [15]\n"
        "    alarm.severity -> 13 [13]\n"
        "    alarm.status -> 14 [14]\n"
        "    attribute -> 21 [21]\n"
        "    codec -> 2 [2]\n"
        "    codec.name -> 3 [3]\n"
        "    codec.parameters -> 4 [4]\n"
        "    compressedSize -> 5 [5]\n"
        "    dataTimeStamp -> 8 [8]\n"
        "    dataTimeStamp.nanoseconds -> 10 [10]\n"
        "    dataTimeStamp.secondsPastEpoch -> 9 [9]\n"
        "    dataTimeStamp.userTag -> 11 [11]\n"
        "    dimension -> 20 [20]\n"
        "    timeStamp -> 16 [16]\n"
        "    timeStamp.nanoseconds -> 18 [18]\n"
        "    timeStamp.secondsPastEpoch -> 17 [17]\n"
        "    timeStamp.userTag -> 19 [19]\n"
        "    uncompressedSize -> 6 [6]\n"
        "    uniqueId -> 7 [7]\n"
        "    value -> 1 [1]\n"
        "    value :  1 [1]\n"
        "    codec :  2 [2]\n"
        "    compressedSize :  5 [5]\n"
        "    uncompressedSize :  6 [6]\n"
        "    uniqueId :  7 [7]\n"
        "    dataTimeStamp :  8 [8]\n"
        "    alarm :  12 [12]\n"
        "    timeStamp :  16 [16]\n"
        "    dimension :  20 [20]\n"
        "    attribute :  21 [21]\n"
        "[1] union  parent=[0]  [1:2)\n"
        "    booleanValue -> 0 [0]\n"
        "    byteValue -> 1 [1]\n"
        "    doubleValue -> 10 [10]\n"
        "    floatValue -> 9 [9]\n"
        "    intValue -> 3 [3]\n"
        "    longValue -> 4 [4]\n"
        "    shortValue -> 2 [2]\n"
        "    ubyteValue -> 5 [5]\n"
        "    uintValue -> 7 [7]\n"
        "    ulongValue -> 8 [8]\n"
        "    ushortValue -> 6 [6]\n"
        "    booleanValue :  0 [0]\n"
        "    [0] bool[]  parent=[0]  [0:1)\n"
        "    byteValue :  1 [1]\n"
        "    [0] int8_t[]  parent=[0]  [0:1)\n"
        "    shortValue :  2 [2]\n"
        "    [0] int16_t[]  parent=[0]  [0:1)\n"
        "    intValue :  3 [3]\n"
        "    [0] int32_t[]  parent=[0]  [0:1)\n"
        "    longValue :  4 [4]\n"
        "    [0] int64_t[]  parent=[0]  [0:1)\n"
        "    ubyteValue :  5 [5]\n"
        "    [0] uint8_t[]  parent=[0]  [0:1)\n"
        "    ushortValue :  6 [6]\n"
        "    [0] uint16_t[]  parent=[0]  [0:1)\n"
        "    uintValue :  7 [7]\n"
        "    [0] uint32_t[]  parent=[0]  [0:1)\n"
        "    ulongValue :  8 [8]\n"
        "    [0] uint64_t[]  parent=[0]  [0:1)\n"
        "    floatValue :  9 [9]\n"
        "    [0] float[]  parent=[0]  [0:1)\n"
        "    doubleValue :  10 [10]\n"
        "    [0] double[]  parent=[0]  [0:1)\n"
        "[2] struct codec_t parent=[0]  [2:5)\n"
        "    name -> 1 [3]\n"
        "    parameters -> 2 [4]\n"
        "    name :  1 [3]\n"
        "    parameters :  2 [4]\n"
        "[3] string  parent=[2]  [3:4)\n"
        "[4] any  parent=[2]  [4:5)\n"
        "[5] int64_t  parent=[0]  [5:6)\n"
        "[6] int64_t  parent=[0]  [6:7)\n"
        "[7] int32_t  parent=[0]  [7:8)\n"
        "[8] struct time_t parent=[0]  [8:12)\n"
        "    nanoseconds -> 2 [10]\n"
        "    secondsPastEpoch -> 1 [9]\n"
        "    userTag -> 3 [11]\n"
        "    secondsPastEpoch :  1 [9]\n"
        "    nanoseconds :  2 [10]\n"
        "    userTag :  3 [11]\n"
        "[9] int64_t  parent=[8]  [9:10)\n"
        "[10] int32_t  parent=[8]  [10:11)\n"
        "[11] int32_t  parent=[8]  [11:12)\n"
        "[12] struct alarm_t parent=[0]  [12:16)\n"
        "    message -> 3 [15]\n"
        "    severity -> 1 [13]\n"
        "    status -> 2 [14]\n"
        "    severity :  1 [13]\n"
        "    status :  2 [14]\n"
        "    message :  3 [15]\n"
        "[13] int32_t  parent=[12]  [13:14)\n"
        "[14] int32_t  parent=[12]  [14:15)\n"
        "[15] string  parent=[12]  [15:16)\n"
        "[16] struct time_t parent=[0]  [16:20)\n"
        "    nanoseconds -> 2 [18]\n"
        "    secondsPastEpoch -> 1 [17]\n"
        "    userTag -> 3 [19]\n"
        "    secondsPastEpoch :  1 [17]\n"
        "    nanoseconds :  2 [18]\n"
        "    userTag :  3 [19]\n"
        "[17] int64_t  parent=[16]  [17:18)\n"
        "[18] int32_t  parent=[16]  [18:19)\n"
        "[19] int32_t  parent=[16]  [19:20)\n"
        "[20] struct[]  parent=[0]  [20:21)\n"
        "    [0] struct dimension_t parent=[0]  [0:6)\n"
        "        binning -> 4 [4]\n"
        "        fullSize -> 3 [3]\n"
        "        offset -> 2 [2]\n"
        "        reverse -> 5 [5]\n"
        "        size -> 1 [1]\n"
        "        size :  1 [1]\n"
        "        offset :  2 [2]\n"
        "        fullSize :  3 [3]\n"
        "        binning :  4 [4]\n"
        "        reverse :  5 [5]\n"
        "    [1] int32_t  parent=[0]  [1:2)\n"
        "    [2] int32_t  parent=[0]  [2:3)\n"
        "    [3] int32_t  parent=[0]  [3:4)\n"
        "    [4] int32_t  parent=[0]  [4:5)\n"
        "    [5] bool  parent=[0]  [5:6)\n"
        "[21] struct[]  parent=[0]  [21:22)\n"
        "    [0] struct epics:nt/NTAttribute:1.0 parent=[0]  [0:15)\n"
        "        alarm -> 5 [5]\n"
        "        alarm.message -> 8 [8]\n"
        "        alarm.severity -> 6 [6]\n"
        "        alarm.status -> 7 [7]\n"
        "        descriptor -> 4 [4]\n"
        "        name -> 1 [1]\n"
        "        source -> 14 [14]\n"
        "        sourceType -> 13 [13]\n"
        "        tags -> 3 [3]\n"
        "        timestamp -> 9 [9]\n"
        "        timestamp.nanoseconds -> 11 [11]\n"
        "        timestamp.secondsPastEpoch -> 10 [10]\n"
        "        timestamp.userTag -> 12 [12]\n"
        "        value -> 2 [2]\n"
        "        name :  1 [1]\n"
        "        value :  2 [2]\n"
        "        tags :  3 [3]\n"
        "        descriptor :  4 [4]\n"
        "        alarm :  5 [5]\n"
        "        timestamp :  9 [9]\n"
        "        sourceType :  13 [13]\n"
        "        source :  14 [14]\n"
        "    [1] string  parent=[0]  [1:2)\n"
        "    [2] any  parent=[0]  [2:3)\n"
        "    [3] string[]  parent=[0]  [3:4)\n"
        "    [4] string  parent=[0]  [4:5)\n"
        "    [5] struct alarm_t parent=[0]  [5:9)\n"
        "        message -> 3 [8]\n"
        "        severity -> 1 [6]\n"
        "        status -> 2 [7]\n"
        "        severity :  1 [6]\n"
        "        status :  2 [7]\n"
        "        message :  3 [8]\n"
        "    [6] int32_t  parent=[5]  [6:7)\n"
        "    [7] int32_t  parent=[5]  [7:8)\n"
        "    [8] string  parent=[5]  [8:9)\n"
        "    [9] struct time_t parent=[0]  [9:13)\n"
        "        nanoseconds -> 2 [11]\n"
        "        secondsPastEpoch -> 1 [10]\n"
        "        userTag -> 3 [12]\n"
        "        secondsPastEpoch :  1 [10]\n"
        "        nanoseconds :  2 [11]\n"
        "        userTag :  3 [12]\n"
        "    [10] int64_t  parent=[9]  [10:11)\n"
        "    [11] int32_t  parent=[9]  [11:12)\n"
        "    [12] int32_t  parent=[9]  [12:13)\n"
        "    [13] int32_t  parent=[0]  [13:14)\n"
        "    [14] string  parent=[0]  [14:15)\n"
    );

    testDiag("Round trip back to bytes");
    std::vector<uint8_t> out;
    out.reserve(msg.size());

    {
        VectorOutBuf buf(true, out);
        to_wire(buf, descs.data());
        testOk1(buf.good());
        out.resize(out.size()-buf.size());
    }

    testEq(msg.size(), out.size());
    testEq(msg, out);
}

// test decode/re-encode of definitions with non-conformant field names
void testBadFieldName()
{
    testDiag("%s", __func__);
    namespace M = members;

    Value proto;
    TypeStore store;
    testFromBytes(true, "\x80\x00\x01\bin-valid&", [&store, &proto](Buffer& B) {
        from_wire_type(B, store, proto);
    });

    testToBytes(true, [proto](Buffer& B) {
        to_wire(B, Value::Helper::desc(proto));
    }, "\x80\x00\x01\bin-valid&");

    // TODO: should local access be allowed?
    testThrows<std::runtime_error>([&proto](){
        proto["in-valid"] = 42;
        testEq(proto["in-valid"].as<uint32_t>(), 42u);
    });
}

void testRegressRedundantBitMask()
{
    testDiag("%s", __func__);

    // NTScalar w/ uint32_t
    uint8_t payload_type[] =
            "\xfd\x01\x00\x80\x15\x65\x70\x69\x63\x73\x3a\x6e\x74\x2f\x4e\x54" \
            "\x53\x63\x61\x6c\x61\x72\x3a\x31\x2e\x30\x06\x05\x76\x61\x6c\x75" \
            "\x65\x22\x05\x61\x6c\x61\x72\x6d\xfd\x02\x00\x80\x07\x61\x6c\x61" \
            "\x72\x6d\x5f\x74\x03\x08\x73\x65\x76\x65\x72\x69\x74\x79\x22\x06" \
            "\x73\x74\x61\x74\x75\x73\x22\x07\x6d\x65\x73\x73\x61\x67\x65\x60" \
            "\x09\x74\x69\x6d\x65\x53\x74\x61\x6d\x70\xfd\x03\x00\x80\x00\x03" \
            "\x10\x73\x65\x63\x6f\x6e\x64\x73\x50\x61\x73\x74\x45\x70\x6f\x63" \
            "\x68\x23\x0b\x6e\x61\x6e\x6f\x73\x65\x63\x6f\x6e\x64\x73\x22\x07" \
            "\x75\x73\x65\x72\x54\x61\x67\x22\x07\x64\x69\x73\x70\x6c\x61\x79" \
            "\xfd\x04\x00\x80\x00\x06\x08\x6c\x69\x6d\x69\x74\x4c\x6f\x77\x43" \
            "\x09\x6c\x69\x6d\x69\x74\x48\x69\x67\x68\x43\x0b\x64\x65\x73\x63" \
            "\x72\x69\x70\x74\x69\x6f\x6e\x60\x05\x75\x6e\x69\x74\x73\x60\x09" \
            "\x70\x72\x65\x63\x69\x73\x69\x6f\x6e\x22\x04\x66\x6f\x72\x6d\xfd" \
            "\x05\x00\x80\x06\x65\x6e\x75\x6d\x5f\x74\x02\x05\x69\x6e\x64\x65" \
            "\x78\x22\x07\x63\x68\x6f\x69\x63\x65\x73\x68\x07\x63\x6f\x6e\x74" \
            "\x72\x6f\x6c\xfd\x06\x00\x80\x09\x63\x6f\x6e\x74\x72\x6f\x6c\x5f" \
            "\x74\x03\x08\x6c\x69\x6d\x69\x74\x4c\x6f\x77\x43\x09\x6c\x69\x6d" \
            "\x69\x74\x48\x69\x67\x68\x43\x07\x6d\x69\x6e\x53\x74\x65\x70\x43" \
            "\x0a\x76\x61\x6c\x75\x65\x41\x6c\x61\x72\x6d\xfd\x07\x00\x80\x0c" \
            "\x76\x61\x6c\x75\x65\x41\x6c\x61\x72\x6d\x5f\x74\x0a\x06\x61\x63" \
            "\x74\x69\x76\x65\x00\x0d\x6c\x6f\x77\x41\x6c\x61\x72\x6d\x4c\x69" \
            "\x6d\x69\x74\x43\x0f\x6c\x6f\x77\x57\x61\x72\x6e\x69\x6e\x67\x4c" \
            "\x69\x6d\x69\x74\x43\x10\x68\x69\x67\x68\x57\x61\x72\x6e\x69\x6e" \
            "\x67\x4c\x69\x6d\x69\x74\x43\x0e\x68\x69\x67\x68\x41\x6c\x61\x72" \
            "\x6d\x4c\x69\x6d\x69\x74\x43\x10\x6c\x6f\x77\x41\x6c\x61\x72\x6d" \
            "\x53\x65\x76\x65\x72\x69\x74\x79\x22\x12\x6c\x6f\x77\x57\x61\x72" \
            "\x6e\x69\x6e\x67\x53\x65\x76\x65\x72\x69\x74\x79\x22\x13\x68\x69" \
            "\x67\x68\x57\x61\x72\x6e\x69\x6e\x67\x53\x65\x76\x65\x72\x69\x74" \
            "\x79\x22\x11\x68\x69\x67\x68\x41\x6c\x61\x72\x6d\x53\x65\x76\x65" \
            "\x72\x69\x74\x79\x22\x0a\x68\x79\x73\x74\x65\x72\x65\x73\x69\x73\x20"
            ;


    // initial monitor data payload from QSRV (with redundant bit mask)
    // bit 0 is set for entire structure, but so are other bits
    uint8_t payload_value[] =
            "\x04\x81\xfb\x32\x1e\xf6\x00\x00\x70\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x08\x4e\x4f\x5f\x41\x4c\x41\x52\x4d\x31\xa8\xf5\x60\x00\x00" \
            "\x00\x00\xe5\xfd\x73\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x07\x07\x44\x65\x66\x61\x75\x6c\x74\x06\x53\x74" \
            "\x72\x69\x6e\x67\x06\x42\x69\x6e\x61\x72\x79\x07\x44\x65\x63\x69" \
            "\x6d\x61\x6c\x03\x48\x65\x78\x0b\x45\x78\x70\x6f\x6e\x65\x6e\x74" \
            "\x69\x61\x6c\x0b\x45\x6e\x67\x69\x6e\x65\x65\x72\x69\x6e\x67\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x7f" \
            "\x00\x00\x00\x00\x00\x00\xf8\x7f\x00\x00\x00\x00\x00\x00\xf8\x7f" \
            "\x00\x00\x00\x00\x00\x00\xf8\x7f\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ;

    const char reencoded_value[] =
            "\x01\x01\xf6\x00\x00\x70\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x08\x4e\x4f\x5f\x41\x4c\x41\x52\x4d\x31\xa8\xf5\x60\x00\x00" \
            "\x00\x00\xe5\xfd\x73\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x07\x07\x44\x65\x66\x61\x75\x6c\x74\x06\x53\x74" \
            "\x72\x69\x6e\x67\x06\x42\x69\x6e\x61\x72\x79\x07\x44\x65\x63\x69" \
            "\x6d\x61\x6c\x03\x48\x65\x78\x0b\x45\x78\x70\x6f\x6e\x65\x6e\x74" \
            "\x69\x61\x6c\x0b\x45\x6e\x67\x69\x6e\x65\x65\x72\x69\x6e\x67\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x7f" \
            "\x00\x00\x00\x00\x00\x00\xf8\x7f\x00\x00\x00\x00\x00\x00\xf8\x7f" \
            "\x00\x00\x00\x00\x00\x00\xf8\x7f\x00\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ;

    Value prototype;
    TypeStore registry;
    {
        FixedBuf buf(false, payload_type);
        from_wire_type(buf, registry, prototype);
        testOk1(buf.good());
        testEq(buf.size(), 0u);
    }
    Value payload(prototype.cloneEmpty());
    {
        FixedBuf buf(false, payload_value);
        from_wire_valid(buf, registry, payload);
        testOk1(buf.good());
        testEq(buf.size(), 0u);
    }
    testShow()<<payload;
    testEq(payload["value"].as<uint32_t>(), 0x700000f6u);
    std::vector<uint8_t> actual_payload;
    testToBytes(false, [&payload](Buffer& buf) {
        to_wire_valid(buf, payload);
        testOk1(buf.good());
    }, reencoded_value);
}

// issue with TypeStore maintenance
void testRegressCNEN()
{
    testDiag("%s", __func__);

    uint8_t payload_type1[] =
    "\xfd\x01\x00\x80\x15\x65\x70\x69\x63\x73\x3a\x6e\x74\x2f\x4e\x54" \
    "\x53\x63\x61\x6c\x61\x72\x3a\x31\x2e\x30\x06\x05\x76\x61\x6c\x75" \
    "\x65\x43\x05\x61\x6c\x61\x72\x6d\xfd\x02\x00\x80\x07\x61\x6c\x61" \
    "\x72\x6d\x5f\x74\x03\x08\x73\x65\x76\x65\x72\x69\x74\x79\x22\x06" \
    "\x73\x74\x61\x74\x75\x73\x22\x07\x6d\x65\x73\x73\x61\x67\x65\x60" \
    "\x09\x74\x69\x6d\x65\x53\x74\x61\x6d\x70\xfd\x03\x00\x80\x00\x03" \
    "\x10\x73\x65\x63\x6f\x6e\x64\x73\x50\x61\x73\x74\x45\x70\x6f\x63" \
    "\x68\x23\x0b\x6e\x61\x6e\x6f\x73\x65\x63\x6f\x6e\x64\x73\x22\x07" \
    "\x75\x73\x65\x72\x54\x61\x67\x22\x07\x64\x69\x73\x70\x6c\x61\x79" \
    "\xfd\x04\x00\x80\x00\x06\x08\x6c\x69\x6d\x69\x74\x4c\x6f\x77\x43" \
    "\x09\x6c\x69\x6d\x69\x74\x48\x69\x67\x68\x43\x0b\x64\x65\x73\x63" \
    "\x72\x69\x70\x74\x69\x6f\x6e\x60\x05\x75\x6e\x69\x74\x73\x60\x09" \
    "\x70\x72\x65\x63\x69\x73\x69\x6f\x6e\x22\x04\x66\x6f\x72\x6d\xfd" \
    "\x05\x00\x80\x06\x65\x6e\x75\x6d\x5f\x74\x02\x05\x69\x6e\x64\x65" \
    "\x78\x22\x07\x63\x68\x6f\x69\x63\x65\x73\x68\x07\x63\x6f\x6e\x74" \
    "\x72\x6f\x6c\xfd\x06\x00\x80\x09\x63\x6f\x6e\x74\x72\x6f\x6c\x5f" \
    "\x74\x03\x08\x6c\x69\x6d\x69\x74\x4c\x6f\x77\x43\x09\x6c\x69\x6d" \
    "\x69\x74\x48\x69\x67\x68\x43\x07\x6d\x69\x6e\x53\x74\x65\x70\x43" \
    "\x0a\x76\x61\x6c\x75\x65\x41\x6c\x61\x72\x6d\xfd\x07\x00\x80\x0c" \
    "\x76\x61\x6c\x75\x65\x41\x6c\x61\x72\x6d\x5f\x74\x0a\x06\x61\x63" \
    "\x74\x69\x76\x65\x00\x0d\x6c\x6f\x77\x41\x6c\x61\x72\x6d\x4c\x69" \
    "\x6d\x69\x74\x43\x0f\x6c\x6f\x77\x57\x61\x72\x6e\x69\x6e\x67\x4c" \
    "\x69\x6d\x69\x74\x43\x10\x68\x69\x67\x68\x57\x61\x72\x6e\x69\x6e" \
    "\x67\x4c\x69\x6d\x69\x74\x43\x0e\x68\x69\x67\x68\x41\x6c\x61\x72" \
    "\x6d\x4c\x69\x6d\x69\x74\x43\x10\x6c\x6f\x77\x41\x6c\x61\x72\x6d" \
    "\x53\x65\x76\x65\x72\x69\x74\x79\x22\x12\x6c\x6f\x77\x57\x61\x72" \
    "\x6e\x69\x6e\x67\x53\x65\x76\x65\x72\x69\x74\x79\x22\x13\x68\x69" \
    "\x67\x68\x57\x61\x72\x6e\x69\x6e\x67\x53\x65\x76\x65\x72\x69\x74" \
    "\x79\x22\x11\x68\x69\x67\x68\x41\x6c\x61\x72\x6d\x53\x65\x76\x65" \
    "\x72\x69\x74\x79\x22\x0a\x68\x79\x73\x74\x65\x72\x65\x73\x69\x73\x20";


    uint8_t payload_type2[] =
    "\xfd\x08\x00\x80\x13\x65\x70\x69\x63\x73\x3a\x6e\x74\x2f\x4e\x54" \
    "\x45\x6e\x75\x6d\x3a\x31\x2e\x30\x03\x05\x76\x61\x6c\x75\x65\xfe" \
    "\x05\x00\x05\x61\x6c\x61\x72\x6d\xfe\x02\x00\x09\x74\x69\x6d\x65" \
    "\x53\x74\x61\x6d\x70\xfe\x03\x00"
    ;

    uint8_t payload_type_expected[] =
    "\xfd\x01\x00\x80\x13\x65\x70\x69\x63\x73\x3a\x6e\x74\x2f\x4e\x54" \
    "\x45\x6e\x75\x6d\x3a\x31\x2e\x30\x03\x05\x76\x61\x6c\x75\x65\xfd" \
    "\x02\x00\x80\x06\x65\x6e\x75\x6d\x5f\x74\x02\x05\x69\x6e\x64\x65" \
    "\x78\x22\x07\x63\x68\x6f\x69\x63\x65\x73\x68\x05\x61\x6c\x61\x72" \
    "\x6d\xfd\x03\x00\x80\x07\x61\x6c\x61\x72\x6d\x5f\x74\x03\x08\x73" \
    "\x65\x76\x65\x72\x69\x74\x79\x22\x06\x73\x74\x61\x74\x75\x73\x22" \
    "\x07\x6d\x65\x73\x73\x61\x67\x65\x60\x09\x74\x69\x6d\x65\x53\x74" \
    "\x61\x6d\x70\xfd\x04\x00\x80\x00\x03\x10\x73\x65\x63\x6f\x6e\x64" \
    "\x73\x50\x61\x73\x74\x45\x70\x6f\x63\x68\x23\x0b\x6e\x61\x6e\x6f" \
    "\x73\x65\x63\x6f\x6e\x64\x73\x22\x07\x75\x73\x65\x72\x54\x61\x67\x22";

    Value prototype1;
    TypeStore registry;
    {
        FixedBuf buf(false, payload_type1);
        from_wire_type(buf, registry, prototype1);
        testTrue(buf.good())<<" at"<<buf.file()<<":"<<buf.line();
        testEq(buf.size(), 0u);
    }
    Value prototype2;
    {
        FixedBuf buf(false, payload_type2);
        from_wire_type(buf, registry, prototype2);
        testTrue(buf.good())<<" at"<<buf.file()<<":"<<buf.line();
        testEq(buf.size(), 0u);
    }

    Value prototypeE;
    TypeStore registryE;
    {
        FixedBuf buf(false, payload_type_expected);
        from_wire_type(buf, registryE, prototypeE);
        testTrue(buf.good())<<" at"<<buf.file()<<":"<<buf.line();
        testEq(buf.size(), 0u);
    }

    testTrue(prototype2.equalType(prototypeE))<<" "<<prototype2<<"\n"<<prototypeE;
}

void testRegressBadBitMask()
{
    testDiag("%s", __func__);

    {
        // "null" bitmask not allowed
        uint8_t input[] = "\xff";
        FixedBuf buf(false, input);
        BitMask mask;
        from_wire(buf, mask);
        testFalse(buf.good())<<" at"<<buf.file()<<":"<<buf.line();
    }
}

// test the common case for a pvRequest of caching an empty Struct
void testEmptyRequest()
{
    testDiag("%s", __func__);

    TypeStore registry;

    std::vector<FieldDesc> descs1;
    {
        uint8_t msg[] = "\xfd\x02\x00\x80\x00\x00";
        FixedBuf buf(false, msg);
        from_wire(buf, descs1, registry);
        testOk1(buf.good());
        testEq(buf.size(), 0u)<<"remaining of "<<sizeof(msg)-1;
    }

    if(testEq(registry.size(), 1u)) {
        testEq(registry[2].size(), 1u);
    }

    std::vector<FieldDesc> descs2;
    {
        uint8_t msg[] = "\xfe\x02\x00";
        FixedBuf buf(false, msg);
        from_wire(buf, descs2, registry);
        testOk1(buf.good());
        testEq(buf.size(), 0u)<<"remaining of "<<sizeof(msg)-1;
    }

    testEq(descs1.size(), 1u);
    testEq(descs2.size(), 1u);

    testEq(std::string(SB()<<descs1.data()),
           "[0] struct  parent=[0]  [0:1)\n")<<"\nActual descs1\n"<<descs1.data();

    testEq(std::string(SB()<<descs2.data()),
           "[0] struct  parent=[0]  [0:1)\n")<<"\nActual descs2\n"<<descs2.data();
}

} // namespace

MAIN(testxcode)
{
    testPlan(143);
    testSetup();
    testDeserializeString();
    testSerialize1();
    testDeserialize1();
    testSimpleDef();
    testSerialize2();
    testDeserialize2();
    testDeserialize3();
    testDecode1();
    testArrayXCode();
    testXCodeNTScalar();
    testXCodeNTNDArray();
    testRegressRedundantBitMask();
    testRegressCNEN();
    testRegressBadBitMask();
    testBadFieldName();
    testEmptyRequest();
    return testDone();
}
