/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <typeinfo>

#include <pvxs/sharedArray.h>

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

    shared_array<Void> Y(shared_array_static_cast<Void>(X));
    testOk1(!X.unique());
    testOk1(!Y.unique());
    testEq(X.size(), 2u);
    testEq(Y.size(), 8u);
    testEq(Y.original_type(), ArrayType::UInt32); // never const uint32_t
}

void testFreeze()
{
    testDiag("%s", __func__);

    shared_array<uint32_t> X(2, 5);
    shared_array<const uint32_t> Y(freeze(std::move(X)));
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
        shared_array<const uint32_t> Y(freeze(std::move(X)));
    })<<"Attempt to freeze() non-unique";
}

void testComplex()
{
    testDiag("%s", __func__);

    shared_array<std::unique_ptr<uint32_t>> X(2, nullptr);

    X[0] = decltype (X)::value_type{new uint32_t(4u)};
    testEq(*X[0], 4u);
}

} // namespace

MAIN(testshared)
{
    testPlan(81);
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
    return testDone();
}
