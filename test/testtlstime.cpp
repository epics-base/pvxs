/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <iostream>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/log.h>
#include <pvxs/unittest.h>
#include <pvxs/config.h>

#include "certstatus.h"
#include "certdate.h"

namespace {
using namespace pvxs;
using certs::CertDate;
using certs::CertTimeParseException;

#define ONE_DAY_IN_SECONDS (60 * 60 * 24)
#define HALF_DAY_IN_SECONDS (60 * 60 * 12)
#define SIXTY_MINUTES_IN_SECONDS (60 * 60)
#define THIRTY_MINUTES_IN_SECONDS (60 * 30)
#define FIVE_MINUTES_IN_SECONDS (60 * 5)

#define ONE_DAY_IN_MINUTES (60 * 24)
#define HALF_DAY_IN_MINUTES (60 * 12)
#define SIXTY_MINUTES (60)
#define THIRTY_MINUTES (30)
#define FIVE_MINUTES (5)

struct Tester {
    // Pristine values
    const time_t now{};
    const time_t future;
    const std::string now_string{};
    const std::string future_string{};

    // For testing Status date
    const CertDate date_now;
    const CertDate date_future;

    Tester()
        : now(time(nullptr)),
          future(now + ONE_DAY_IN_SECONDS),
          now_string(static_cast<CertDate>(now).s),
          future_string(CertDate(future).s),
          date_now(now),
          date_future(future) {
        testShow() << "Testing TLS Date Functions:\n";
    }

    ~Tester() = default;

    void initialisation() const {
        testShow() << __func__;
        testEq(now, date_now.t);
        testEq(future, date_future.t);
        testEq(now_string, date_now.s);
        testEq(future_string, date_future.s);
    }

    void conversion() const {
        testShow() << __func__;
        testEq(now, static_cast<CertDate>(date_now.s).t);
        testEq(future, static_cast<CertDate>(date_future.s).t);
        testEq(now_string, CertDate(date_now.t).s);
        testEq(future_string, CertDate(date_future.t).s);
    }

    void asn1_time() const {
        testShow() << __func__;
        const ossl_ptr<ASN1_TIME> now_asn1(ASN1_TIME_new());
        ASN1_TIME_set(now_asn1.get(), now);
        const ossl_ptr<ASN1_TIME> future_asn1(ASN1_TIME_new());
        ASN1_TIME_set(future_asn1.get(), future);

        testEq(now, static_cast<CertDate>(now_asn1).t);
        testEq(future, static_cast<CertDate>(future_asn1.get()).t);

        testEq(now, static_cast<CertDate>(date_now.toAsn1_Time().get()).t);
        testEq(future, static_cast<CertDate>(CertDate::toAsn1_Time(date_future).get()).t);
    }
};

void test_parseDuration() {
    testShow() << __func__;
    const auto now = time(nullptr);
    // Test basic durations
    testEq(CertDate::parseDuration("1y"), CertDate::addCalendarUnits(now, 1) - now);
    testEq(CertDate::parseDuration("4y"), CertDate::addCalendarUnits(now, 4) - now);
    testEq(CertDate::parseDuration("1M"), CertDate::addCalendarUnits(now, 0, 1) - now);
    testEq(CertDate::parseDuration("1w"), CertDate::addCalendarUnits(now, 0,0, 7) - now);
    testEq(CertDate::parseDuration("1d"), CertDate::addCalendarUnits(now, 0,0, 1) - now);
    testEq(CertDate::parseDuration("1h"), SIXTY_MINUTES_IN_SECONDS);
    testEq(CertDate::parseDuration("1m"), 60);
    testEq(CertDate::parseDuration("1s"), 1);

    // Test with whitespace and punctuation
    testEq(CertDate::parseDuration("1 y"), CertDate::addCalendarUnits(now, 1) - now);
    testEq(CertDate::parseDuration("1y, 6M"), CertDate::addCalendarUnits(now, 1, 6) - now);
    testEq(CertDate::parseDuration("1d 12h"), ONE_DAY_IN_SECONDS + HALF_DAY_IN_SECONDS);

    // Test combined durations
    testEq(CertDate::parseDuration("1y6M"), CertDate::addCalendarUnits(now, 1, 6) - now);
    testEq(CertDate::parseDuration("1d12h"), ONE_DAY_IN_SECONDS + HALF_DAY_IN_SECONDS);
    testEq(CertDate::parseDuration("1y6M30d12h30m45s"),
        CertDate::addCalendarUnits(now, 1, 6, 30) - now +
           HALF_DAY_IN_SECONDS +
           THIRTY_MINUTES_IN_SECONDS +
           45);

    // Test unadorned numbers as minutes
    testEq(CertDate::parseDuration("5"), FIVE_MINUTES_IN_SECONDS);
    testEq(CertDate::parseDuration("60"), SIXTY_MINUTES_IN_SECONDS);
    testEq(CertDate::parseDuration(" 30 "), THIRTY_MINUTES_IN_SECONDS);

    // Test error cases
    try {
        CertDate::parseDuration("");
        testFail("Expected exception for empty duration string");
    } catch (const CertTimeParseException &) {
        testPass("Empty duration string rejected");
    }

    try {
        CertDate::parseDuration("abc");
        testFail("Expected exception for invalid duration format");
    } catch (std::runtime_error &) {
        testPass("Invalid duration format rejected");
    }
    try {
        CertDate::parseDuration("1x");
        testFail("Expected exception for invalid unit in duration format");
    } catch (std::runtime_error &) {
        testPass("Invalid unit in duration format rejected");
    }
    try {
        CertDate::parseDuration("y");
        testFail("Expected exception for unit without number in duration format");
    } catch (std::runtime_error &) {
        testPass("Invalid duration format for unit without number rejected");
    }
}

void test_formatDurationMins() {
    testShow() << __func__;
    const auto now = time(nullptr);

    // Test basic durations.
    // Note that this result depends on when the test is run because of leap years.
    // The formatter should correctly handle this.
    auto const one_year = (CertDate::addCalendarUnits(now, 1, 0) - now) / 60;
    testEq(CertDate::formatDurationMins(one_year), "1y");
    auto const four_years = (CertDate::addCalendarUnits(now, 4, 0) - now)  / 60;
    testEq(CertDate::formatDurationMins(four_years), "4y");
    auto const one_month = (CertDate::addCalendarUnits(now, 0, 1) - now) / 60;
    testEq(CertDate::formatDurationMins(one_month), "1M");
    testEq(CertDate::formatDurationMins(ONE_DAY_IN_MINUTES * 7), "7d"); // 7 days
    testEq(CertDate::formatDurationMins(ONE_DAY_IN_MINUTES), "1d"); // 1 day
    testEq(CertDate::formatDurationMins(SIXTY_MINUTES), "1h"); // 1 hour
    testEq(CertDate::formatDurationMins(1), "1m"); // 1 minute

    // Test complex durations.
    // Note that this result depends on when the test is run because of leap years
    // and daylight savings time.  The formatter should correctly handle this.
    const auto one_year_and_six_months = (CertDate::addCalendarUnits(now, 1, 6) - now) / 60;
    testEq(CertDate::formatDurationMins(one_year_and_six_months), "1y 6M");
    testEq(CertDate::formatDurationMins(ONE_DAY_IN_MINUTES + HALF_DAY_IN_MINUTES), "1d 12h"); // 1 day 12 hours
    testEq(CertDate::formatDurationMins(HALF_DAY_IN_MINUTES + THIRTY_MINUTES), "12h 30m"); // 12 hours 30 minutes

    // Test round-trip conversion with a complex duration.
    // Note that this result depends on when the test is run because of leap years
    // and daylight savings time.  The formatter should correctly handle this.
    const std::string duration_str = "1y 6M 20d 12h 30m";
    const int64_t minutes = CertDate::parseDurationMins(duration_str);
    const std::string formatted = CertDate::formatDurationMins(minutes);

    testEq(formatted, duration_str);

    // Test duration with some zero values in between.
    // Note that this result depends on when the test is run because of leap years.
    // The formatter should correctly handle this.
    testEq(CertDate::formatDurationMins(one_year + 60), "1y 1h"); // 1 year 0 months 0 days 1 hour 0 minutes

    // Test with a calculated value that would have extra components
    // Note that this result depends on when the test is run because of leap years
    // and daylight savings time.  The formatter should correctly handle this.
    testEq(CertDate::formatDurationMins(one_year_and_six_months + 60), "1y 6M 1h");

    // Test with seconds - these would normally be truncated when converting to minutes
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1y 1s")), "1y");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1h 59s")), "1h");

    // Test zero
    testEq(CertDate::formatDurationMins(0), "0m");

    // Additional round-trip tests
    // Simple values
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1y")), "1y");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("6M")), "6M");
    // Note that this test needs to be less than 28 because that can, in some cases,
    // be a full month if, for example, the test is run in a leap year, at the beginning
    // of February.  The formatter would then return "1M" instead of "28d" days.
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("27d")), "27d");
    // Note that the formatter will never return weeks, so "1w" becomes "7d".
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1w")), "7d");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1d")), "1d");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1h")), "1h");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1m")), "1m");

    // Combined values that should preserve well in round-trip
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1y 1M")), "1y 1M");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1y 6M")), "1y 6M");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("1d 12h")), "1d 12h");
    testEq(CertDate::formatDurationMins(CertDate::parseDurationMins("12h 30m")), "12h 30m");
}

}  // namespace

MAIN(testtlstime) {
    testPlan(60);  // Updated to match the actual number of tests
    testSetup();
    logger_config_env();
    Tester().initialisation();
    Tester().conversion();
    Tester().asn1_time();
    test_parseDuration();
    test_formatDurationMins();
    cleanup_for_valgrind();
    return testDone();
}
