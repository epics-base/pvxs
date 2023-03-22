/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <dbAccess.h>
#include <dbUnitTest.h>
#include <iocInit.h>
#include <iocsh.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/iochooks.h>
#include <pvxs/server.h>
#include <pvxs/unittest.h>

extern "C" {
extern int testioc_registerRecordDeviceDriver(struct dbBase*);
}

using namespace pvxs;

namespace {

} // namespace

#define testOkB(__pass, __fmt, ...) boxLeft(); testOk(__pass, __fmt, ##__VA_ARGS__)
#define testEqB(__lhs, __rhs) boxLeft(); testEq(__lhs, __rhs)
#define testStrEqB(__lhs, __rhs) boxLeft(); testStrEq(__lhs, __rhs)
#define testArrEqB(__lhs, __rhs) boxLeft(); testArrEq(__lhs, __rhs)
#define testdbPutArrFieldOkB(__pv, __dbrType, __count, __pbuf) boxLeft(); testdbPutArrFieldOk(__pv, __dbrType, __count, __pbuf)
#define testdbGetFieldEqualB(__pv, __dbrType, ...) boxLeft(); testdbGetFieldEqual(__pv, __dbrType, ##__VA_ARGS__)
#define testdbGetArrFieldEqualB(__pv, __dbfType, __nRequest, __pbufcnt, __pbuf) boxLeft(); testdbGetArrFieldEqual(__pv, __dbfType, __nRequest, __pbufcnt, __pbuf)
#define testThrowsB(__lambda) boxLeft(); testThrows<std::logic_error>(__lambda)

static void boxLeft();

static pvxs::client::Context clientContext;

// List of all tests to be run in order
static std::initializer_list<void (*)()> tests = {
		[]() {
			testThrowsB([] { ioc::server(); });
		},
		[]() {
			testdbReadDatabase("testioc.dbd", nullptr, nullptr);
			testOkB(true, R"("testioc.dbd" loaded)");
		},
		[]() {
			testOkB(!testioc_registerRecordDeviceDriver(pdbbase), "testioc_registerRecordDeviceDriver(pdbbase)");
		},
		[]() { testOkB((bool)ioc::server(), "ioc::server()"); },
		[]() {
			testdbReadDatabase("testioc.db", nullptr, "user=test");
			testOkB(true, R"(testdbReadDatabase("testioc.db", nullptr, "user=test"))");
        },
        []() {
            testdbReadDatabase("testiocg.db", nullptr, "user=test");
            testOkB(true, R"(testdbReadDatabase("testiocg.db", nullptr, "user=test"))");
        },
        []() {
            testdbReadDatabase("image.db", nullptr, "N=tst");
            testOkB(true, R"(testdbReadDatabase("testiocg.db", nullptr, "user=test"))");
        },
        []() { testOkB(!pvxs::ioc::dbLoadGroup("../testioc.json"), R"(dbLoadGroup("testioc.json"))"); },
        []() {
            testIocInitOk();
            testPass("testIocInitOk()");
        },
        []() { testdbGetFieldEqualB("test:aiExample", DBR_DOUBLE, 42.2); },
        []() { testdbGetFieldEqualB("test:stringExample", DBR_STRING, "Some random value"); },
        []() {
            shared_array<double> expected({ 1.0, 2.0, 3.0 });
            testdbGetArrFieldEqualB("test:arrayExample", DBR_DOUBLE, 3, expected.size(), expected.data());
        },
        []() { testdbGetFieldEqualB("test:longExample", DBR_LONG, 102042); },
        []() { testdbGetFieldEqualB("test:enumExample", DBR_ENUM, 2); },
        []() {
            char expected[MAX_STRING_SIZE * 2]{ 0 };
			std::string first("Column A");
			std::string second("Column B");
			first.copy(&expected[0], MAX_STRING_SIZE - 1);
			second.copy(&expected[MAX_STRING_SIZE], MAX_STRING_SIZE - 1);

			testdbGetArrFieldEqualB("test:groupExampleAS", DBR_STRING, 2, 2, &expected);
		},
		[]() {
			shared_array<double> expected({ 10, 20, 30, 40, 50 });
			testdbGetArrFieldEqualB("test:vectorExampleD1", DBR_DOUBLE, 5, expected.size(), expected.data());
		},
		[]() {
			shared_array<double> expected({ 1.1, 2.2, 3.3, 4.4, 5.5 });
			testdbGetArrFieldEqualB("test:vectorExampleD2", DBR_DOUBLE, 5, expected.size(), expected.data());
		},
		[]() {
            clientContext = ioc::server().clientConfig().build();
            testShow() << clientContext.config();
            testOkB(true, "cli = ioc::server().clientConfig().build()");
        },
		[]() {
			auto val = clientContext.get("test:aiExample").exec()->wait(5.0);
			auto aiExample = val["value"].as<double>();
			auto expected = 42.2;
			testEqB(aiExample, expected);
		},
		[]() {
			auto val = clientContext.get("test:stringExample").exec()->wait(5.0);
			auto stringExample = val["value"].as<std::string>();
			auto expected = "Some random value";
			testStrEqB(stringExample, expected);
		},
		[]() {
			auto val = clientContext.get("test:arrayExample").exec()->wait(5.0);
			shared_array<double> expected({ 1.0, 2.0, 3.0 });
			auto arrayExample = val["value"].as<shared_array<const double>>();
			testArrEqB(arrayExample, expected);
		},
		[]() {
			auto val = clientContext.get("test:arrayExample.[1:2]").exec()->wait(5.0);
			shared_array<double> expected({ 2.0, 3.0 });
			auto arrayExample = val["value"].as<shared_array<const double>>();
			testArrEqB(arrayExample, expected);
		},
		[]() {
			shared_array<double> array({});
			testdbPutArrFieldOkB("test:arrayExample", DBR_DOUBLE, array.size(), array.data());
		},
		[]() {
			auto val = clientContext.get("test:arrayExample").exec()->wait(5.0);
			shared_array<double> expected({});
			auto arrayExample = val["value"].as<shared_array<const double>>();
			testArrEqB(arrayExample, expected);
		},
		[]() {
			shared_array<double> array({ 1.0, 2.0, 3.0, 4.0, 5.0 });
			testdbPutArrFieldOkB("test:arrayExample", DBR_DOUBLE, array.size(), array.data());
		},
		[]() {
			auto val = clientContext.get("test:arrayExample").exec()->wait(5.0);
			shared_array<double> expected({ 1.0, 2.0, 3.0, 4.0, 5.0 });
			auto arrayExample = val["value"].as<shared_array<const double>>();
			testArrEqB(arrayExample, expected);
		},
		[]() {
			auto val = clientContext.get("test:longExample").exec()->wait(5.0);
			auto longValue = val["value"].as<long>();
			auto expected = 102042;
			testEqB(longValue, expected);
		},
		[]() {
			auto val = clientContext.get("test:enumExample").exec()->wait(5.0);
			auto enumExample = val["value.index"].as<short>();
			auto expected = 2;
			testEqB(enumExample, expected);
		},
		[]() {
			auto val = clientContext.get("test:enumExample").exec()->wait(5.0);
			shared_array<const std::string> expected({ "zero", "one", "two" });
			auto enumExampleChoices = val["value.choices"].as<shared_array<const std::string>>();
			testArrEqB(enumExampleChoices, expected);
		},
		[]() {
			auto val = clientContext.get("test:tableExample").exec()->wait(5.0);
			shared_array<const std::string> expected({ "Column A", "Column B" });
			auto tableExampleLabels = val["labels"].as<shared_array<const std::string>>();
			testArrEqB(tableExampleLabels, expected);
		},
		[]() {
			auto val = clientContext.get("test:tableExample").exec()->wait(5.0);
			shared_array<const double> expected({ 10, 20, 30, 40, 50 });
			auto tableExampleValueA = val["value.A"].as<shared_array<const double>>();
			testArrEqB(tableExampleValueA, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample").exec()->wait(5.0);
			auto structExampleStringValue = val["string.value"].as<std::string>();
			auto expected = "Some random value";
			testStrEqB(structExampleStringValue, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample").exec()->wait(5.0);
			auto structExampleAiValue = val["ai.value"].as<double>();
			auto expected = 42.2;
			testEqB(structExampleAiValue, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample").exec()->wait(5.0);
			shared_array<const double> expected({ 1, 2, 3, 4, 5 });
			auto structExampleArrayValue = val["array.value"].as<shared_array<const double>>();
			testArrEqB(structExampleArrayValue, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample").exec()->wait(5.0);
			auto structExampleSa_0_LongValue = val["sa[0].long.value"].as<long>();
			auto expected = 102042;
			testEqB(structExampleSa_0_LongValue, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample").exec()->wait(5.0);
			auto structExampleSa_0_EnumValueIndex = val["sa[0].enum.value.index"].as<short>();
			auto expected = 2;
			testEqB(structExampleSa_0_EnumValueIndex, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample").exec()->wait(5.0);
			auto structExampleSa_0_EnumValueChoices = val["sa[0].enum.value.choices"]
					.as<shared_array<const std::string>>();
			shared_array<const std::string> expected({ "zero", "one", "two" });
			testArrEqB(structExampleSa_0_EnumValueChoices, expected);
		},
		[]() {
			auto val = clientContext.get("test:structExample2").exec()->wait(5.0);
			auto structExample2Sa_0_AnyValue = val["sa[0].any"].as<long>();
			auto expected = 102042;
			testEqB(structExample2Sa_0_AnyValue, expected);
		},
		[]() {
			clientContext.put("test:calcExample.FLNK").set("value", "").exec()->wait(5.0);
			testdbGetFieldEqualB("test:calcExample.FLNK", DBR_STRING, "");
		},
		[]() {
			clientContext.put("test:calcExample.FLNK").set("value", "test:stringExample").exec()->wait(5.0);
			testdbGetFieldEqualB("test:calcExample.FLNK", DBR_STRING, "test:stringExample");
		},
		[]() {
			// TODO check whether long strings need to be null terminated
			shared_array<const int8_t> arrayLinkVal(
					{ 't', 'e', 's', 't', ':', 'a', 'i', 'E', 'x', 'a', 'm', 'p', 'l', 'e', '\0' });
			clientContext.put("test:calcExample.FLNK$").set("value", arrayLinkVal).exec()->wait(5.0);
			testdbGetFieldEqualB("test:calcExample.FLNK", DBR_STRING, "test:aiExample");
		},
		[]() {
			shared_array<const uint16_t> expected({});
			clientContext.put("tst:Array").build([&expected](Value&& prototype) -> Value {
						auto putval = prototype.cloneEmpty();
						putval["value"] = expected;
						return putval;
					})
					.exec()->wait(5.0);
			testdbGetArrFieldEqualB("tst:ArrayData", DBR_USHORT, 0, expected.size(), expected.data());
		},
		[]() {
			shared_array<const uint16_t> expected({ 1, 2, 3, 4, 5 });
			clientContext.put("tst:Array").build([&expected](Value&& prototype) -> Value {
						auto putval = prototype.cloneEmpty();
						putval["value"] = expected;
						return putval;
					})
					.exec()->wait(5.0);
			testdbGetArrFieldEqualB("tst:ArrayData", DBR_USHORT, 5, expected.size(), expected.data());
		},
		[]() {
			clientContext.put("test:slowmo.PROC").set("value", 0).pvRequest("record[block=true]").exec()->wait(5.0);
			testdbGetFieldEqualB("test:slowmo", DBR_DOUBLE, 1.0);
		},
		[]() {
			clientContext.put("test:procCounter.HIGH").set("value", 0).pvRequest("record[process=true]").exec()
					->wait(5.0);
			testdbGetFieldEqualB("test:procCounter", DBR_DOUBLE, 1.0);
		},
		[]() {
			clientContext.put("test:procCounter.HIGH").set("value", 0).pvRequest("record[process=false]").exec()
					->wait(5.0);
			testdbGetFieldEqualB("test:procCounter", DBR_DOUBLE, 1.0);
		},
		[]() {
			clientContext.put("test:procCounter.HIGH").set("value", 0).pvRequest("record[process=passive]").exec()
					->wait(5.0);
			testdbGetFieldEqualB("test:procCounter", DBR_DOUBLE, 2.0);
		},
};

/**
 * Test runner
 *
 * @return overall test status
 */
MAIN(testioc) {
	auto testNum = 0;
	testPlan((int)tests.size());
	testSetup();
	testdbPrepare();

	// Run tests
	for (auto& test: tests) {
		if (testNum++) {
			printf("#├──────────────────────────────────────────────────────────────────────┤\n");
		} else {
			printf("#┌──────────────────────────────────────────────────────────────────────┐\n");
		}
		try {
			test();
		} catch (const std::exception& e) {
			testFail("Test failed with unexpected exception: %s\n", e.what());
		}
	}
	printf("#└──────────────────────────────────────────────────────────────────────┘");

    testIocShutdownOk();
    testdbCleanup();

	return testDone();
}

//static void testDbLoadGroupOk(const char* file) {
//	testOk(!pvxs::ioc::dbLoadGroup(file), "%s scheduled to be loaded during IocInit()", file);
//}

static void boxLeft() {
}
