/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <typeinfo>
#include <vector>
#include <string>
#include <limits>

#include <pvxs/sharedArray.h>
#include <pvxs/data.h>
#include "utilpvt.h"

#include <pvxs/unittest.h>
#include <epicsUnitTest.h>
#include <testMain.h>

namespace {
using namespace pvxs;

template<typename E>
void testEmpty()
{
    testDiag("%s", __func__);

    shared_array<E> v;

    testOk1(v.unique());
    testOk1(v.empty());

    testEq(v.size(), 0u);
}

template<typename I>
void testInt()
{
    testDiag("%s w/ %s", __func__, typeid(I).name());

    shared_array<I> X(2, 5);
    testOk1(X.unique());
    testOk1(!X.empty());
    if(testEq(X.size(), 2u)) {
        testEq(X[0], 5);
        testEq(X[1], 5);
    }

    shared_array<I> Y(X);
    testOk1(!X.unique());
    testOk1(!Y.unique());
    testEq(X.size(), Y.size());

    X.clear();
    testOk1(X.unique());
    testOk1(Y.unique());
    testEq(X.size(), 0u);
    testEq(Y.size(), 2u);

    X = std::move(Y);
    testOk1(X.unique());
    testOk1(Y.unique());
    testEq(X.size(), 2u);
    testEq(Y.size(), 0u);

    shared_array<I> Z(std::move(X));
    testOk1(X.unique());
    testOk1(Y.unique());
    testOk1(Z.unique());
    testEq(X.size(), 0u);
    testEq(Y.size(), 0u);
    testEq(Z.size(), 2u);

    // copy empty
    shared_array<I> Q(Y);
    testOk1(Y.unique());
    testOk1(Q.unique());
    testEq(Y.size(), 0u);
    testEq(Q.size(), 0u);
}

template<typename Void, typename I>
void testVoid()
{
    testDiag("%s", __func__);

    shared_array<I> X(2);

    shared_array<Void> Y(X.template castTo<Void>());
    testOk1(!X.unique());
    testOk1(!Y.unique());
    testEq(X.size(), 2u);
    testEq(Y.size(), 2u);
    testEq(Y.original_type(), ArrayType::UInt32); // never const uint32_t

    testThrows<std::logic_error>([&Y]() {
        auto Z = Y.freeze();
    });

    X.clear();
    testOk1(Y.unique());

    auto Z = Y.freeze();
    testOk1(Y.unique());
    testOk1(Z.unique());
    testEq(Y.size(), 0u);
    testEq(Z.size(), 2u);
}

template<typename Void, typename I>
void testVoidAssemble()
{
    testDiag("%s", __func__);

    pvxs::ArrayType code = pvxs::detail::CaptureBase<I>::code;

    auto temp = (typename std::remove_cv<I>::type*)calloc(3, sizeof(I));
    if(!temp)
        testAbort("calloc failure");

    temp[0] = 1;
    temp[1] = 2;
    temp[2] = 3;

    pvxs::shared_array<Void> X((Void*)temp, [](Void *p) {
        free((void*)p);
    }, 3u, code);

    testEq(temp, X.data());
    testEq(code, X.original_type());
    testEq(3u, X.size());

    auto Y(X.template castTo<I>());
    testEq(temp, Y.data());
    testEq(3u, Y.size());
    testEq(Y[0], 1u);
}

void testFreeze()
{
    testDiag("%s", __func__);

    shared_array<uint32_t> X(2, 5);
    shared_array<const uint32_t> Y(X.freeze());
    testOk1(X.unique());
    testOk1(Y.unique());
    testEq(X.size(), 0u);
    testEq(Y.size(), 2u);
}

void testFreezeError()
{
    testDiag("%s", __func__);

    shared_array<uint32_t> X(2, 5), Z(X);
    testOk1(!X.unique());
    testThrows<std::logic_error>([&X]() {
        shared_array<const uint32_t> Y(X.freeze());
    })<<"Attempt to freeze() non-unique";
}

void testThaw()
{
    testDiag("%s", __func__);

    shared_array<const uint32_t> X({2, 5}), Y(X), Z({4, 5});
    auto saveX = X.data();
    auto saveZ = Z.data();

    auto A(X.thaw()); // copies
    auto B(Y.thaw()); // casts
    auto C(Z.thaw()); // casts
    testOk1(A.unique());
    testOk1(B.unique());
    testOk1(C.unique());
    testEq(A.size(), 2u);
    testEq(B.size(), 2u);
    testEq(C.size(), 2u);
    testEq(X.size(), 0u);
    testEq(Y.size(), 0u);
    testEq(Z.size(), 0u);
    testNotEq(A.data(), saveX);
    testEq   (B.data(), saveX);
    testEq   (C.data(), saveZ);
    testEq(A[0], 2u);
    testEq(B[0], 2u);
    testEq(C[0], 4u);
}

void testFreezeThawVoid()
{
    testDiag("%s", __func__);

    shared_array<uint32_t> A(2, 5);
    auto saveA = A.data();
    auto vA(A.castTo<void>());
    A.clear();
    auto cvB(vA.freeze());
    testEq(vA.size(), 0u);
    testEq(cvB.size(), 2u);
    testEq(cvB.original_type(), ArrayType::UInt32);
    testTrue(cvB.unique());

    auto cvC(cvB);
    auto vB(cvB.thaw()); // copy
    testTrue(cvC.unique());
    auto vC(cvC.thaw()); // cast
    testEq(cvB.size(), 0u);
    testEq(cvC.size(), 0u);
    testEq(vB.size(), 2u);
    testEq(vC.size(), 2u);
    testNotEq(vB.data(), saveA);
    testEq   (vC.data(), saveA);

    auto B(vB.castTo<uint32_t>());
    auto C(vC.castTo<uint32_t>());
    testEq(B[0], 5u);
    testEq(C[0], 5u);
}

struct ImMobile {
    int v = 0;
    ImMobile() = default;

    void store(int x) { v=x; }
    int load() const { return v; }

    ImMobile(const ImMobile&) = delete;
    ImMobile(ImMobile&&) = delete;
    ImMobile& operator=(const ImMobile&) = delete;
    ImMobile& operator=(ImMobile&&) = delete;
};

void testComplex()
{
    testDiag("%s", __func__);

    shared_array<ImMobile> X(2);

    X[0].store(4);
    testEq(X[0].load(), 4);
}

void testValue()
{
    testDiag("%s", __func__);

    auto top = TypeDef(TypeCode::UInt32).create();

    shared_array<Value> A(allocArray(ArrayType::Value, 2u).castTo<Value>());

    A[0] = top.cloneEmpty();
    A[0] = 1u;
    A[1] = top.cloneEmpty();
    A[1] = 2u;

    auto varr(A.castTo<void>());
    testEq(varr.size(), 2u);
    testEq(varr.original_type(), ArrayType::Value);

    auto B(varr.castTo<Value>());

    testEq(B.size(), 2u);
    testEq(B.at(0).as<uint32_t>(), 1u);
    testEq(B.at(1).as<uint32_t>(), 2u);
}

void testCast()
{
    testDiag("%s", __func__);

    shared_array<void> Void;

    (void)Void.castTo<void>();
    (void)Void.castTo<uint32_t>();
    // not allowed
    //(void)Void.castTo<const void>();
    //(void)Void.castTo<const uint32_t>();

    shared_array<const void> CVoid;

    (void)CVoid.castTo<const void>();
    (void)CVoid.castTo<const uint32_t>();
    // not allowed
    //(void)CVoid.castTo<void>();
    //(void)CVoid.castTo<uint32_t>();

    shared_array<uint32_t> Int;

    (void)Int.castTo<uint32_t>();
    (void)Int.castTo<void>();
    // not allowed
    //(void)Int.castTo<const uint32_t>();
    //(void)Int.castTo<const void>();

    shared_array<const uint32_t> CInt;

    (void)CInt.castTo<const uint32_t>();
    (void)CInt.castTo<const void>();
    // not allowed
    //(void)CInt.castTo<uint32_t>();
    //(void)CInt.castTo<void>();

    shared_array<double> Double({1.0, 2.0});
    Void = Double.castTo<void>();
    testThrows<std::logic_error>([&Void](){
        (void)Void.castTo<uint32_t>();
    })<<"Attempt cast to wrong type";

    Void.clear();
    // now doesn't throw
    (void)Void.castTo<uint32_t>();
}

void testFromVector()
{
    testDiag("%s", __func__);

    std::vector<uint32_t> V({1, 2, 3});

    shared_array<uint32_t> A(V.begin(), V.end());
    testEq(A.size(), 3u);
    testEq(A.at(2), 3u);
    // not consumed
    testEq(V.size(), 3u);
}

void testElemAlloc()
{
    testDiag("%s", __func__);

    testEq(elementSize(ArrayType::UInt8), 1u);
    testEq(elementSize(ArrayType::UInt16), 2u);
    testEq(elementSize(ArrayType::UInt32), 4u);
    testEq(elementSize(ArrayType::UInt64), 8u);

    auto varr = allocArray(ArrayType::UInt32, 3u);
    testEq(varr.size(), 3u);
    testEq(varr.original_type(), ArrayType::UInt32);
}

// round trip conversion when TO can exactly represent all possible values of FROM
template<typename FROM, typename TO>
void testConvertExact()
{
    shared_array<const FROM> inp({
                                     FROM(0),
                                     FROM(1),
                                     FROM(-1),
                                     std::numeric_limits<FROM>::min(),
                                     std::numeric_limits<FROM>::max(),
                                 });
    shared_array<const TO> expect({
                                      (TO)FROM(0),
                                      (TO)FROM(1),
                                      (TO)FROM(-1),
                                      (TO)std::numeric_limits<FROM>::min(),
                                      (TO)std::numeric_limits<FROM>::max(),
                                  });
    auto conv(inp.template convertTo<const TO>());
    testShow()<<"Input "<<inp;
    testArrEq(conv, expect)<<" "<<__func__<<"("<<typeid(FROM).name()<<" -> "<<typeid(TO).name()<<")";
    testArrEq(expect.template convertTo<const FROM>(), inp)<<" "<<__func__<<"("<<typeid(FROM).name()<<" <- "<<typeid(TO).name()<<")";
}

// conversion based on truncation of unsigned integer
template<typename FROM, typename TO>
void testConvertTrunc()
{
    shared_array<const FROM> inp({
                                     FROM(0),
                                     FROM(1),
                                     FROM(-1),
                                     std::numeric_limits<FROM>::min(),
                                     std::numeric_limits<FROM>::max(),
                                 });
    shared_array<const TO> expect({
                                      (TO)FROM(0),
                                      (TO)FROM(1),
                                      (TO)FROM(-1),
                                      (TO)std::numeric_limits<FROM>::min(),
                                      (TO)std::numeric_limits<FROM>::max(),
                                  });
    auto conv(inp.template convertTo<const TO>());
    testShow()<<"Input "<<inp;
    testArrEq(conv, expect)<<" "<<__func__<<"("<<typeid(FROM).name()<<" -> "<<typeid(TO).name()<<")";
}

template<typename T>
void testToFromString()
{
    shared_array<const T> inp({
                                  T(0),
                                  T(1),
                                  T(-1),
                                  std::numeric_limits<T>::min(),
                                  std::numeric_limits<T>::max(),
                              });
    shared_array<const std::string> expect({
                                               (SB()<<promote_print<T>::op(T(0))).str(),
                                               (SB()<<promote_print<T>::op(T(1))).str(),
                                               (SB()<<promote_print<T>::op(T(-1))).str(),
                                               (SB()<<promote_print<T>::op(std::numeric_limits<T>::min())).str(),
                                               (SB()<<promote_print<T>::op(std::numeric_limits<T>::max())).str(),
                                           });

    testShow()<<"Input "<<inp;
    try {
        auto conv(inp.template convertTo<const std::string>());
        testArrEq(conv, expect)<<" "<<__func__<<"("<<typeid(T).name()<<" -> str)";
    }catch(std::exception& e){
        testFail("%s(%s -> str) throws %s", __func__, typeid(T).name(), e.what());
    }
    try{
        testArrEq(expect.template convertTo<const T>(), inp)<<" "<<__func__<<"("<<typeid(T).name()<<" <- str)";
    }catch(std::exception& e){
        testFail("%s(%s <- str) throws %s", __func__, typeid(T).name(), e.what());
    }
}

void testConvert()
{
    testDiag("%s", __func__);

    static_assert (detail::CaptureCode<uint32_t>::code!=detail::CaptureCode<uint16_t>::code, "");

    testDiag("reversible conversions");
    testConvertExact<uint8_t, uint8_t>();
    testConvertExact<uint8_t, int16_t>();
    testConvertExact<uint8_t, uint16_t>();
    testConvertExact<uint8_t, int32_t>();
    testConvertExact<uint8_t, uint32_t>();
    testConvertExact<uint8_t, int64_t>();
    testConvertExact<uint8_t, uint64_t>();
    testConvertExact<uint8_t, float>();
    testConvertExact<uint8_t, double>();

    testConvertExact<int8_t, int8_t>();
    testConvertExact<int8_t, int16_t>();
    testConvertExact<int8_t, uint16_t>();
    testConvertExact<int8_t, int32_t>();
    testConvertExact<int8_t, uint32_t>();
    testConvertExact<int8_t, int64_t>();
    testConvertExact<int8_t, uint64_t>();
    testConvertExact<int8_t, float>();
    testConvertExact<int8_t, double>();

    testConvertExact<uint16_t, uint16_t>();
    testConvertExact<uint16_t, int32_t>();
    testConvertExact<uint16_t, uint32_t>();
    testConvertExact<uint16_t, int64_t>();
    testConvertExact<uint16_t, uint64_t>();
    testConvertExact<uint16_t, float>();
    testConvertExact<uint16_t, double>();

    testConvertExact<int16_t, int16_t>();
    testConvertExact<int16_t, int32_t>();
    testConvertExact<int16_t, uint32_t>();
    testConvertExact<int16_t, int64_t>();
    testConvertExact<int16_t, uint64_t>();
    testConvertExact<int16_t, float>();
    testConvertExact<int16_t, double>();

    testConvertExact<uint32_t, uint32_t>();
    testConvertExact<uint32_t, int64_t>();
    testConvertExact<uint32_t, uint64_t>();
    testConvertExact<uint32_t, double>();

    testConvertExact<int32_t, int32_t>();
    testConvertExact<int32_t, int64_t>();
    testConvertExact<int32_t, uint64_t>();
    testConvertExact<int32_t, double>();

    testConvertExact<uint64_t, uint64_t>();

    testConvertExact<int64_t, int64_t>();

    testConvertExact<float, double>();

    testDiag("integer truncation");
    testConvertTrunc<uint16_t, uint8_t>();
    testConvertTrunc<uint32_t, uint8_t>();
    testConvertTrunc<uint64_t, uint8_t>();
    testConvertTrunc<uint32_t, uint16_t>();
    testConvertTrunc<uint64_t, uint16_t>();
    testConvertTrunc<uint64_t, uint32_t>();

    testToFromString<uint8_t>();
    testToFromString<uint16_t>();
    testToFromString<uint32_t>();
    testToFromString<uint64_t>();
    testToFromString<int8_t>();
    testToFromString<int16_t>();
    testToFromString<int32_t>();
    testToFromString<int64_t>();
    testTodoBegin("problems parsing +-DBL/FLT_MIN/MAX");
    testToFromString<float>();
    testToFromString<double>();
    testTodoEnd();

    testArrEq(shared_array<bool>({true, false}).convertTo<std::string>(),
              shared_array<std::string>({"true", "false"}));

    testArrEq(shared_array<uint32_t>({1u, 2u, 0xffffffffu}).convertTo<uint32_t>(),
              shared_array<uint32_t>({1u, 2u, 0xffffffffu}));

    testArrEq(shared_array<uint32_t>({1u, 2u, 0xffffffffu}).convertTo<uint16_t>(),
              shared_array<uint16_t>({1u, 2u, 0xffffu}));

    testArrEq(shared_array<uint32_t>({1u, 2u, 0xffffffffu}).convertTo<int32_t>(),
              shared_array<int32_t>({1, 2, -1}));

    testArrEq(shared_array<uint32_t>({1u, 2u, 0xffffffffu}).convertTo<int16_t>(),
              shared_array<int16_t>({1, 2, -1}));

    testArrEq(shared_array<int32_t>({1, 2, -1}).convertTo<uint32_t>(),
              shared_array<uint32_t>({1u, 2u, 0xffffffffu}));

    testArrEq(shared_array<int32_t>({1, 2, -1}).convertTo<double>(),
              shared_array<double>({1.0, 2.0, -1.0}));

    testArrEq(shared_array<int32_t>({1, 2, -1}).convertTo<std::string>(),
              shared_array<std::string>({"1", "2", "-1"}));
}

} // namespace

MAIN(testshared)
{
    testPlan(268);
    testSetup();
    testEmpty<void>();
    testEmpty<const void>();
    testEmpty<int32_t>();
    testEmpty<const int32_t>();
    testInt<int32_t>();
    testInt<const int32_t>();
    testVoid<void, uint32_t>();
    testVoid<const void, const uint32_t>();
    testVoidAssemble<void, uint32_t>();
    testVoidAssemble<const void, const uint32_t>();
    testFreeze();
    testFreezeError();
    testThaw();
    testFreezeThawVoid();
    testComplex();
    testValue();
    testCast();
    testFromVector();
    testElemAlloc();
    testConvert();
    return testDone();
}
