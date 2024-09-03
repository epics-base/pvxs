/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <iostream>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>

#include "certstatus.h"

namespace {
using namespace pvxs;

#define ONE_DAY_OF_SECONDS (60*60*24)

struct Tester {
    // Pristine values
    const time_t now;
    const time_t future;
    const std::string now_string;
    const std::string future_string;

    // For testing Status date
    const certs::StatusDate date_now;
    const certs::StatusDate date_future;

    Tester()
    : now(time(nullptr)), future(now + ONE_DAY_OF_SECONDS),
      now_string(((certs::StatusDate)now).s), future_string(certs::StatusDate(future).s),
      date_now(now), date_future(future) {
        testShow()<<"Testing TLS Date Functions:\n";
    }

    ~Tester() = default;

    void initialisation()
    {
        testShow()<<__func__;
        testEq(now, date_now.t);
        testEq(future, date_future.t);
        testEq(now_string, date_now.s);
        testEq(future_string, date_future.s);
    }

    void conversion()
    {
        testShow()<<__func__;
        testEq(now, ((certs::StatusDate)date_now.s).t);
        testEq(future, ((certs::StatusDate)date_future.s).t);
        testEq(now_string, certs::StatusDate(date_now.t).s);
        testEq(future_string, certs::StatusDate(date_future.t).s);
    }

    void asn1_time()
    {
        testShow()<<__func__;
        ossl_ptr<ASN1_TIME> now_asn1(ASN1_TIME_new());
        ASN1_TIME_set(now_asn1.get(), now);
        ossl_ptr<ASN1_TIME> future_asn1(ASN1_TIME_new());
        ASN1_TIME_set(future_asn1.get(), future);

        testEq(now, ((certs::StatusDate)now_asn1).t);
        testEq(future, ((certs::StatusDate)future_asn1.get()).t);

        testEq(now, ((certs::StatusDate)date_now.toAsn1_Time().get()).t);
        testEq(future, ((certs::StatusDate)certs::StatusDate::toAsn1_Time(date_future).get()).t);
    }
};

} // namespace

MAIN(testget)
{
    testPlan(12);
    testSetup();
    logger_config_env();
    Tester().initialisation();
    Tester().conversion();
    Tester().asn1_time();
    cleanup_for_valgrind();
    return testDone();
}
