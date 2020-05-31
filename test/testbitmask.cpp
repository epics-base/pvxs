/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <testMain.h>

#include <epicsUnitTest.h>

#include <pvxs/unittest.h>
#include "bitmask.h"
#include "pvaproto.h"
#include "utilpvt.h"

using namespace pvxs;
namespace  {

void testEmpty()
{
    testDiag("%s", __func__);

    BitMask empty;
    testOk1(!!empty.empty());
    testEq(empty.size(), 0u);
    testEq(empty.wsize(), 0u);

    testEq(empty.findSet(0u), 0u);

    testEq(std::string(SB()<<empty), "{}");
}

void testBasic1()
{
    testDiag("%s", __func__);

    BitMask M({1, 5, 3, 7}); // 0b10101010
    testOk1(!M.empty());
    testEq(M.size(), 8u);
    testEq(M.wsize(), 1u);

    testEq(M.findSet(0u), 1u);
    testEq(M.findSet(1u), 1u);
    testEq(M.findSet(2u), 3u);
    testEq(M.findSet(3u), 3u);
    testEq(M.findSet(M.size()), M.size());

    testEq(std::string(SB()<<M), "{1, 3, 5, 7}"); // tests M.onlySet()
}

void testBasic2()
{
    testDiag("%s", __func__);

    BitMask M({6, 0, 4, 2}); // 0b01010101
    testOk1(!M.empty());
    testEq(M.size(), 7u);
    testEq(M.wsize(), 1u);

    testEq(M.findSet(0u), 0u);
    testEq(M.findSet(1u), 2u);
    testEq(M.findSet(2u), 2u);
    testEq(M.findSet(3u), 4u);
    testEq(M.findSet(M.size()), M.size());

    testEq(std::string(SB()<<M), "{0, 2, 4, 6}");
}

void testBasic3()
{
    testDiag("%s", __func__);

    BitMask M({63, 64, 67});
    testOk1(!M.empty());
    testEq(M.size(), 68u);
    testEq(M.wsize(), 2u);

    testEq(M.findSet(0u), 63u);
    testEq(M.findSet(62u), 63u);
    testEq(M.findSet(63u), 63u);
    testEq(M.findSet(64u), 64u);
    testEq(M.findSet(65u), 67u);
    testEq(M.findSet(M.size()), M.size());

    testEq(std::string(SB()<<M), "{63, 64, 67}");
}

void testOp()
{
    testDiag("%s", __func__);

    BitMask M({   1, 2,    4, 5}, 6u);
    testOk1(!M.empty());
    testEq(M.size(), 6u);
    testEq(M.wsize(), 1u);

    testOk1(!M[0]);
    testOk1(!!M[1]);
    M[0] = true;
    M[1] = false;
    testOk1(!!M[0]);
    testOk1(!M[1]);
}

void testExpr()
{
    testDiag("%s", __func__);

    BitMask A({   1, 2,    4, 5}, 6u);
    BitMask B({0,    2, 3, 4   }, 6u);
    BitMask C({               5}, 6u);

    BitMask Not(!A);
    BitMask Or(A | B);
    BitMask And(A & B);
    BitMask Complex(C | (A & B));

    testEq(std::string(SB()<<Not), "{0, 3}");
    testEq(std::string(SB()<<Or), "{0, 1, 2, 3, 4, 5}");
    testEq(std::string(SB()<<And), "{2, 4}");
    testEq(std::string(SB()<<Complex), "{2, 4, 5}");
}

template<size_t N>
void testSerCase(bool be, uint8_t(&input)[N], const char *expect)
{
    std::string sinput((char*)input, N-1u);
    testShow()<<__func__<<"("<<(be?"BE":"LE")<<", \""<<escape(sinput)<<"\", \""<<expect<<"\")";

    BitMask mask;
    FixedBuf inbuf(be, input);
    from_wire(inbuf, mask);

    testEq(std::string(SB()<<mask), expect);

    std::vector<uint8_t> O;
    VectorOutBuf outbuf(be, O);
    to_wire(outbuf, mask);

    std::string actual((char*)O.data(), O.size()-outbuf.size());
    testEq(sinput, actual);
}

void testSer()
{
    testDiag("%s", __func__);

    {
        uint8_t actual[] = "\x00";
        testSerCase(true, actual, "{}");
        testSerCase(false, actual, "{}");
    }
    {
        uint8_t actual[] = "\x01\x01";
        testSerCase(true, actual, "{0}");
        testSerCase(false, actual, "{0}");
    }
    {
        uint8_t actual[] = "\x01\x02";
        testSerCase(true, actual, "{1}");
        testSerCase(false, actual, "{1}");
    }
    {
        uint8_t actual[] = "\x02\x00\x01";
        testSerCase(true, actual, "{8}");
        testSerCase(false, actual, "{8}");
    }
    {
        uint8_t actual[] = "\x07\x02\x00\x00\x00\x00\x00\x80";
        testSerCase(true, actual, "{1, 55}");
        testSerCase(false, actual, "{1, 55}");
    }
    {
        uint8_t actual[] = "\x08\x80\x00\x00\x00\x00\x00\x00\x02";
        testSerCase(true, actual, "{1, 63}");
    }
    {
        uint8_t actual[] = "\x08\x02\x00\x00\x00\x00\x00\x00\x80";
        testSerCase(false, actual, "{1, 63}");
    }
    {
        uint8_t actual[] = "\x09\x80\x00\x00\x00\x00\x00\x01\x02\x01";
        testSerCase(true, actual, "{1, 8, 63, 64}");
    }
    {
        uint8_t actual[] = "\x09\x02\x01\x00\x00\x00\x00\x00\x80\x01";
        testSerCase(false, actual, "{1, 8, 63, 64}");
    }
    {
        uint8_t actual[] = "\x10\x80\x00\x00\x00\x00\x00\x00\x02\x40\x00\x00\x00\x00\x00\x00\x01";
        testSerCase(true, actual, "{1, 63, 64, 126}");
    }
    {
        uint8_t actual[] = "\x10\x02\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00\x00\x00\x40";
        testSerCase(false, actual, "{1, 63, 64, 126}");
    }
}

} // namespace

MAIN(testbitmask)
{
    testPlan(76);
    testSetup();
    testEmpty();
    testBasic1();
    testBasic2();
    testBasic3();
    testOp();
    testExpr();
    testSer();
    cleanup_for_valgrind();
    return testDone();
}
