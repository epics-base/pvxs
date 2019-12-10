/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <testMain.h>

#include <epicsUnitTest.h>

#include <pvxs/unittest.h>
#include <pvxs/bitmask.h>
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

} // namespace

MAIN(testbitmask)
{
    testPlan(44);
    testEmpty();
    testBasic1();
    testBasic2();
    testBasic3();
    testOp();
    testExpr();
    cleanup_for_valgrind();
    return testDone();
}
