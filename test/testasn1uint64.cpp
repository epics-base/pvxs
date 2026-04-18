/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define PVXS_ENABLE_EXPERT_API

#include <cstdint>
#include <memory>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>

#include "certstatus.h"

namespace pvxs {
namespace certs {
uint64_t ASN1ToUint64(const ASN1_INTEGER* asn1_number);
}
}

namespace {

using pvxs::certs::OCSPParseException;

template <typename T, void (*FreeFn)(T*)>
struct OsslDeleter {
    void operator()(T* p) const {
        if(p) FreeFn(p);
    }
};

using ASN1IntPtr = std::unique_ptr<ASN1_INTEGER, OsslDeleter<ASN1_INTEGER, ASN1_INTEGER_free>>;
using BNPtr = std::unique_ptr<BIGNUM, OsslDeleter<BIGNUM, BN_free>>;

ASN1IntPtr bnToAsn1(const BIGNUM* bn)
{
    return ASN1IntPtr(BN_to_ASN1_INTEGER(bn, nullptr));
}

}

MAIN(testasn1uint64)
{
    testPlan(6);

    {
        const BNPtr bn(BN_new());
        testOk(!!bn, "BN_new");
        BN_set_word(bn.get(), 1);
        const auto asn1 = bnToAsn1(bn.get());
        testOk(!!asn1, "BN_to_ASN1_INTEGER");
        testEq(pvxs::certs::ASN1ToUint64(asn1.get()), uint64_t{1});
    }

    {
        const BNPtr bn(BN_new());
        BN_one(bn.get());
        BN_lshift(bn.get(), bn.get(), 64);
        const auto asn1 = bnToAsn1(bn.get());
        bool caught = false;
        try {
            (void)pvxs::certs::ASN1ToUint64(asn1.get());
        } catch (const OCSPParseException&) {
            caught = true;
        }
        testOk(caught, "Overflow (2^64) throws OCSPParseException");
    }

    {
        const BNPtr bn(BN_new());
        BN_set_word(bn.get(), 5);
        BN_set_negative(bn.get(), 1);
        const auto asn1 = bnToAsn1(bn.get());
        bool caught = false;
        try {
            (void)pvxs::certs::ASN1ToUint64(asn1.get());
        } catch (const OCSPParseException&) {
            caught = true;
        }
        testOk(caught, "Negative ASN1 integer throws OCSPParseException");
    }

    {
        bool caught = false;
        try {
            (void)pvxs::certs::ASN1ToUint64(nullptr);
        } catch (const OCSPParseException&) {
            caught = true;
        }
        testOk(caught, "Null ASN1 integer throws OCSPParseException");
    }

    return testDone();
}
