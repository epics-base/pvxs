/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <typeinfo>
#include <vector>
#include <string>

#include <pvxs/sharedArray.h>
#include <pvxs/data.h>

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

void testComplex()
{
    testDiag("%s", __func__);

    shared_array<std::unique_ptr<uint32_t>> X(2, nullptr);

    X[0] = decltype (X)::value_type{new uint32_t(4u)};
    testEq(*X[0], 4u);
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

void testConvert()
{
    testDiag("%s", __func__);

    static_assert (detail::CaptureCode<uint32_t>::code!=detail::CaptureCode<uint16_t>::code, "");

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
    testPlan(115);
    testSetup();
    testEmpty<void>();
    testEmpty<const void>();
    testEmpty<int32_t>();
    testEmpty<const int32_t>();
    testInt<int32_t>();
    testInt<const int32_t>();
    testVoid<void, uint32_t>();
    testVoid<const void, const uint32_t>();
    testFreeze();
    testFreezeError();
    testComplex();
    testValue();
    testCast();
    testFromVector();
    testElemAlloc();
    testConvert();
    return testDone();
}
