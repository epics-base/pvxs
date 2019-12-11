/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/util.h>
#include <pvxs/unittest.h>
#include "dataimpl.h"
#include "pvaproto.h"

namespace {
using namespace pvxs;
using namespace pvxs::impl;

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
        // update cache with key 0
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

    std::vector<FieldDesc> descs;
    TypeStore cache;

    {
        FixedBuf buf(true, msg);
        TypeDeserContext ctxt{descs, cache};
        from_wire(buf, ctxt);
        if(testOk1(buf.good()))
            FieldDesc_calculate_offset(descs.data());
        testEq(buf.size(), 0u)<<"Of "<<msg.size();
    }

    testEq(cache.size(), 1u);
    {
        auto it = cache.find(1);
        if(testOk1(it!=cache.end())) {
            testEq(it->second.size(), 4u);
        }
    }

    if(testOk1(!descs.empty())) {
        testEq(descs.size(), descs.front().size());
    }

    //   cat <<EOF | sed -e 's|"|\\"|g' -e 's|^# |    "|' -e 's|$|\\n"|g'
    // paste in Actual
    testEq(std::string(SB()<<descs.data()),
           "[0] struct timeStamp_t <0:4>  [0:4)\n"
           "  nanoSeconds -> 2 [2]\n"
           "  secondsPastEpoch -> 1 [1]\n"
           "  userTag -> 3 [3]\n"
           "  secondsPastEpoch :  1 [1]\n"
           "  nanoSeconds :  2 [2]\n"
           "  userTag :  3 [3]\n"
           "[1] int64_t  <1:2>  [1:2)\n"
           "[2] int32_t  <2:3>  [2:3)\n"
           "[3] int32_t  <3:4>  [3:4)\n"
     )<<"Actual:\n"<<descs.data();
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
        TypeDeserContext ctxt{descs, cache};
        from_wire(buf, ctxt);
        if(testOk1(buf.good()))
            FieldDesc_calculate_offset(descs.data());
        testEq(buf.size(), 0u)<<"remaining of "<<msg.size();
    }

    if(testOk1(!descs.empty())) {
        testEq(descs.size(), descs.front().size());
    }

    testEq(std::string(SB()<<descs.data()),
           "[0] struct epics:nt/NTScalarArray:1.0 <0:10>  [0:10)\n"
           "  alarm -> 2 [2]\n"
           "  alarm.message -> 5 [5]\n"
           "  alarm.severity -> 3 [3]\n"
           "  alarm.status -> 4 [4]\n"
           "  timeStamp -> 6 [6]\n"
           "  timeStamp.nanoseconds -> 8 [8]\n"
           "  timeStamp.secondsPastEpoch -> 7 [7]\n"
           "  timeStamp.userTag -> 9 [9]\n"
           "  value -> 1 [1]\n"
           "  value :  1 [1]\n"
           "  alarm :  2 [2]\n"
           "  timeStamp :  6 [6]\n"
           "[1] double[]  <1:2>  [1:2)\n"
           "[2] struct alarm_t <2:3>  [2:6)\n"
           "  message -> 3 [5]\n"
           "  severity -> 1 [3]\n"
           "  status -> 2 [4]\n"
           "  severity :  1 [3]\n"
           "  status :  2 [4]\n"
           "  message :  3 [5]\n"
           "[3] int32_t  <3:4>  [3:4)\n"
           "[4] int32_t  <4:5>  [4:5)\n"
           "[5] string  <5:6>  [5:6)\n"
           "[6] struct time_t <6:7>  [6:10)\n"
           "  nanoseconds -> 2 [8]\n"
           "  secondsPastEpoch -> 1 [7]\n"
           "  userTag -> 3 [9]\n"
           "  secondsPastEpoch :  1 [7]\n"
           "  nanoseconds :  2 [8]\n"
           "  userTag :  3 [9]\n"
           "[7] int64_t  <7:8>  [7:8)\n"
           "[8] int32_t  <8:9>  [8:9)\n"
           "[9] int32_t  <9:10>  [9:10)\n"
    )<<"Actual:\n"<<descs.data();

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
        TypeDeserContext ctxt{descs, cache};
        from_wire(buf, ctxt);
        if(testOk1(buf.good()))
            FieldDesc_calculate_offset(descs.data());
        testEq(buf.size(), 0u)<<"remaining of "<<msg.size();
    }

    if(testOk1(!descs.empty())) {
        testEq(descs.size(), descs.front().size());
    }

    testEq(std::string(SB()<<descs.data()),
           "[0] struct epics:nt/NTNDArray:1.0 <0:22>  [0:54)\n"
           "  alarm -> 23 [23]\n"
           "  alarm.message -> 26 [26]\n"
           "  alarm.severity -> 24 [24]\n"
           "  alarm.status -> 25 [25]\n"
           "  attribute -> 38 [38]\n"
           "  codec -> 13 [13]\n"
           "  codec.name -> 14 [14]\n"
           "  codec.parameters -> 15 [15]\n"
           "  compressedSize -> 16 [16]\n"
           "  dataTimeStamp -> 19 [19]\n"
           "  dataTimeStamp.nanoseconds -> 21 [21]\n"
           "  dataTimeStamp.secondsPastEpoch -> 20 [20]\n"
           "  dataTimeStamp.userTag -> 22 [22]\n"
           "  dimension -> 31 [31]\n"
           "  timeStamp -> 27 [27]\n"
           "  timeStamp.nanoseconds -> 29 [29]\n"
           "  timeStamp.secondsPastEpoch -> 28 [28]\n"
           "  timeStamp.userTag -> 30 [30]\n"
           "  uncompressedSize -> 17 [17]\n"
           "  uniqueId -> 18 [18]\n"
           "  value -> 1 [1]\n"
           "  value :  1 [1]\n"
           "  codec :  13 [13]\n"
           "  compressedSize :  16 [16]\n"
           "  uncompressedSize :  17 [17]\n"
           "  uniqueId :  18 [18]\n"
           "  dataTimeStamp :  19 [19]\n"
           "  alarm :  23 [23]\n"
           "  timeStamp :  27 [27]\n"
           "  dimension :  31 [31]\n"
           "  attribute :  38 [38]\n"
           "[1] union  <1:2>  [1:13)\n"
           "  booleanValue -> 1 [2]\n"
           "  byteValue -> 2 [3]\n"
           "  doubleValue -> 11 [12]\n"
           "  floatValue -> 10 [11]\n"
           "  intValue -> 4 [5]\n"
           "  longValue -> 5 [6]\n"
           "  shortValue -> 3 [4]\n"
           "  ubyteValue -> 6 [7]\n"
           "  uintValue -> 8 [9]\n"
           "  ulongValue -> 9 [10]\n"
           "  ushortValue -> 7 [8]\n"
           "  booleanValue :  1 [2]\n"
           "  byteValue :  2 [3]\n"
           "  shortValue :  3 [4]\n"
           "  intValue :  4 [5]\n"
           "  longValue :  5 [6]\n"
           "  ubyteValue :  6 [7]\n"
           "  ushortValue :  7 [8]\n"
           "  uintValue :  8 [9]\n"
           "  ulongValue :  9 [10]\n"
           "  floatValue :  10 [11]\n"
           "  doubleValue :  11 [12]\n"
           "[2] bool[]  <0:1>  [2:3)\n"
           "[3] int8_t[]  <0:1>  [3:4)\n"
           "[4] int16_t[]  <0:1>  [4:5)\n"
           "[5] int32_t[]  <0:1>  [5:6)\n"
           "[6] int64_t[]  <0:1>  [6:7)\n"
           "[7] uint8_t[]  <0:1>  [7:8)\n"
           "[8] uint16_t[]  <0:1>  [8:9)\n"
           "[9] uint32_t[]  <0:1>  [9:10)\n"
           "[10] uint64_t[]  <0:1>  [10:11)\n"
           "[11] float[]  <0:1>  [11:12)\n"
           "[12] double[]  <0:1>  [12:13)\n"
           "[13] struct codec_t <2:3>  [13:16)\n"
           "  name -> 1 [14]\n"
           "  parameters -> 2 [15]\n"
           "  name :  1 [14]\n"
           "  parameters :  2 [15]\n"
           "[14] string  <3:4>  [14:15)\n"
           "[15] any  <4:5>  [15:16)\n"
           "[16] int64_t  <5:6>  [16:17)\n"
           "[17] int64_t  <6:7>  [17:18)\n"
           "[18] int32_t  <7:8>  [18:19)\n"
           "[19] struct time_t <8:9>  [19:23)\n"
           "  nanoseconds -> 2 [21]\n"
           "  secondsPastEpoch -> 1 [20]\n"
           "  userTag -> 3 [22]\n"
           "  secondsPastEpoch :  1 [20]\n"
           "  nanoseconds :  2 [21]\n"
           "  userTag :  3 [22]\n"
           "[20] int64_t  <9:10>  [20:21)\n"
           "[21] int32_t  <10:11>  [21:22)\n"
           "[22] int32_t  <11:12>  [22:23)\n"
           "[23] struct alarm_t <12:13>  [23:27)\n"
           "  message -> 3 [26]\n"
           "  severity -> 1 [24]\n"
           "  status -> 2 [25]\n"
           "  severity :  1 [24]\n"
           "  status :  2 [25]\n"
           "  message :  3 [26]\n"
           "[24] int32_t  <13:14>  [24:25)\n"
           "[25] int32_t  <14:15>  [25:26)\n"
           "[26] string  <15:16>  [26:27)\n"
           "[27] struct time_t <16:17>  [27:31)\n"
           "  nanoseconds -> 2 [29]\n"
           "  secondsPastEpoch -> 1 [28]\n"
           "  userTag -> 3 [30]\n"
           "  secondsPastEpoch :  1 [28]\n"
           "  nanoseconds :  2 [29]\n"
           "  userTag :  3 [30]\n"
           "[28] int64_t  <17:18>  [28:29)\n"
           "[29] int32_t  <18:19>  [29:30)\n"
           "[30] int32_t  <19:20>  [30:31)\n"
           "[31] struct[]  <20:21>  [31:38)\n"
           "[32] struct dimension_t <0:6>  [32:38)\n"
           "  binning -> 4 [36]\n"
           "  fullSize -> 3 [35]\n"
           "  offset -> 2 [34]\n"
           "  reverse -> 5 [37]\n"
           "  size -> 1 [33]\n"
           "  size :  1 [33]\n"
           "  offset :  2 [34]\n"
           "  fullSize :  3 [35]\n"
           "  binning :  4 [36]\n"
           "  reverse :  5 [37]\n"
           "[33] int32_t  <1:2>  [33:34)\n"
           "[34] int32_t  <2:3>  [34:35)\n"
           "[35] int32_t  <3:4>  [35:36)\n"
           "[36] int32_t  <4:5>  [36:37)\n"
           "[37] bool  <5:6>  [37:38)\n"
           "[38] struct[]  <21:22>  [38:54)\n"
           "[39] struct epics:nt/NTAttribute:1.0 <0:15>  [39:54)\n"
           "  alarm -> 5 [44]\n"
           "  alarm.message -> 47 [86]\n"
           "  alarm.severity -> 45 [84]\n"
           "  alarm.status -> 46 [85]\n"
           "  descriptor -> 4 [43]\n"
           "  name -> 1 [40]\n"
           "  source -> 14 [53]\n"
           "  sourceType -> 13 [52]\n"
           "  tags -> 3 [42]\n"
           "  timestamp -> 9 [48]\n"
           "  timestamp.nanoseconds -> 50 [89]\n"
           "  timestamp.secondsPastEpoch -> 49 [88]\n"
           "  timestamp.userTag -> 51 [90]\n"
           "  value -> 2 [41]\n"
           "  name :  1 [40]\n"
           "  value :  2 [41]\n"
           "  tags :  3 [42]\n"
           "  descriptor :  4 [43]\n"
           "  alarm :  5 [44]\n"
           "  timestamp :  9 [48]\n"
           "  sourceType :  13 [52]\n"
           "  source :  14 [53]\n"
           "[40] string  <1:2>  [40:41)\n"
           "[41] any  <2:3>  [41:42)\n"
           "[42] string[]  <3:4>  [42:43)\n"
           "[43] string  <4:5>  [43:44)\n"
           "[44] struct alarm_t <5:6>  [44:48)\n"
           "  message -> 3 [47]\n"
           "  severity -> 1 [45]\n"
           "  status -> 2 [46]\n"
           "  severity :  1 [45]\n"
           "  status :  2 [46]\n"
           "  message :  3 [47]\n"
           "[45] int32_t  <6:7>  [45:46)\n"
           "[46] int32_t  <7:8>  [46:47)\n"
           "[47] string  <8:9>  [47:48)\n"
           "[48] struct time_t <9:10>  [48:52)\n"
           "  nanoseconds -> 2 [50]\n"
           "  secondsPastEpoch -> 1 [49]\n"
           "  userTag -> 3 [51]\n"
           "  secondsPastEpoch :  1 [49]\n"
           "  nanoseconds :  2 [50]\n"
           "  userTag :  3 [51]\n"
           "[49] int64_t  <10:11>  [49:50)\n"
           "[50] int32_t  <11:12>  [50:51)\n"
           "[51] int32_t  <12:13>  [51:52)\n"
           "[52] int32_t  <13:14>  [52:53)\n"
           "[53] string  <14:15>  [53:54)\n"
    )<<"Actual:\n"<<descs.data();

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

} // namespace

MAIN(testxcode)
{
    testPlan(0);
    testDecode1();
    testXCodeNTScalar();
    testXCodeNTNDArray();
    return testDone();
}
