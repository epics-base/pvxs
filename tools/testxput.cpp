/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <sstream>
#include <functional>

#include <testMain.h>

#include <envDefs.h>
#include <dbDefs.h>
#include <epicsUnitTest.h>

#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/nt.h>
#include <pvxs/unittest.h>

#define REALMAIN pvxput
#include "put.cpp"

using namespace pvxs;

namespace {
struct Redirect {
    std::ostream& ref;
    std::streambuf *prev;
    Redirect(std::ostream& ref, std::ostream& target)
        :ref(ref)
        ,prev(ref.rdbuf(target.rdbuf()))
    {}
    ~Redirect() {
        ref.rdbuf(prev);
    }
};

struct Run {
    std::string out, err;
    int code;

    Run(std::initializer_list<std::string> args) {
        std::vector<const char*> argv({"pvxput"});
        {
            testCase cmdline;
            cmdline<<"exec: pvxput";
            for(auto& arg : args) {
                cmdline<<" '"<<arg<<'\'';
                argv.push_back(arg.c_str());
            }
        }
        std::ostringstream out, err;
        {
            Redirect rd_cout(std::cout, out);
            Redirect rd_cerr(std::cerr, err);
            try{
                code = pvxput(argv.size(), (char**)argv.data());
            }catch(std::exception& e){
                testFail("Uncaught c++ exception: %s", e.what());
                code = -1;
            }
        }
        this->out = out.str();
        this->err = err.str();
        if(!this->out.empty())
            testShow()<<"stdout:\n"<<this->out;
        if(!this->err.empty())
            testShow()<<"stderr:\n"<<this->err;

    }

    Run& exitWith(int expect) {
        testOk(expect==code, "%d == %d", expect, code);
        return *this;
    }
    Run& success() {
        return exitWith(0);
    }

    testCase _lineMatching(const std::string& inp, const std::string& expr) {
        std::istringstream strm(inp);
        std::string line;
        testCase c;
        while(std::getline(strm, line)) {
            if(c.setPassMatch(expr, line))
                break;
        }
        return c;
    }

    inline
    testCase outMatch(const std::string& expr) {
        return _lineMatching(out, expr);
    }
    inline
    testCase errMatch(const std::string& expr) {
        return _lineMatching(err, expr);
    }
};

} // namespace

MAIN(testxput)
{
    testPlan(39);

    auto pvI32(server::SharedPV::buildMailbox());
    pvI32.open(nt::NTScalar{TypeCode::Int32}.create()
               .update("value", 5));

    auto pvI32arr(server::SharedPV::buildMailbox());
    pvI32arr.open(nt::NTScalar{TypeCode::Int32A}.create());

    auto pvS(server::SharedPV::buildMailbox());
    pvS.open(nt::NTScalar{TypeCode::String}.create()
               .update("value", "foo"));

    auto pvE(server::SharedPV::buildMailbox());
    pvE.open(nt::NTEnum{}.create()
             .update("value.index", 0)
             .update("value.choices", shared_array<const std::string>({"one", "two"})));

    // setup isolated server
    auto srv(server::Config::isolated()
             .build()
             .addPV("testI32", pvI32)
             .addPV("arrI32", pvI32arr)
             .addPV("testS", pvS)
             .addPV("testE", pvE)
             .start());

    // setup environment for pvxput() to find only our isolated server
    {
        client::Config::defs_t envs;
        srv.clientConfig().updateDefs(envs);
        for(const auto& pair : envs) {
            testShow()<<" "<<pair.first<<"="<<pair.second;
            epicsEnvSet(pair.first.c_str(), pair.second.c_str());
        }
    }

    {
        Run run({"-v", "-d", "-w1", "-w", "2", "-r", "foo", "-h"});
        run.success();
        run.outMatch(".*Show this message.*");
    }

    {
        Run run({"-V"});
        run.success();
        run.outMatch(".*PVXS.*");
        run.outMatch(".*libevent.*");
    }

    {
        Run run({});
        run.exitWith(1);
        testStrEq(run.out, "");
        run.errMatch(".*Expected PV name.*");
    }

    {
        Run run({"-w", "foo"});
        run.exitWith(1);
        testStrEq(run.out, "");
        run.errMatch(".*Invalid.*foo.*");
    }

    Run({"testI32", "6"}).success();
    testEq(pvI32.fetch()["value"].as<int32_t>(), 6);

    Run({"testI32", "value=7"}).success();
    testEq(pvI32.fetch()["value"].as<int32_t>(), 7);

    Run({"testI32", R"({"value":8})"}).success();
    testEq(pvI32.fetch()["value"].as<int32_t>(), 8);

    Run({"arrI32", R"({"value":8})"}).exitWith(1);

    Run({"arrI32", R"([3,4,5])"}).success();
    testArrEq(pvI32arr.fetch()["value"].as<shared_array<const int32_t>>(),
            shared_array<const int32_t>({3,4,5}));

    Run({"arrI32", R"(value=[1,4])"}).success();
    testArrEq(pvI32arr.fetch()["value"].as<shared_array<const int32_t>>(),
            shared_array<const int32_t>({1,4}));

    Run({"arrI32", R"({"value":[5,6]})"}).success();
    testArrEq(pvI32arr.fetch()["value"].as<shared_array<const int32_t>>(),
            shared_array<const int32_t>({5, 6}));

    Run({"testS", "hello"}).success();
    testEq(pvS.fetch()["value"].as<std::string>(), "hello");

    Run({"testS", "value=world"}).success();
    testEq(pvS.fetch()["value"].as<std::string>(), "world");

    Run({"testS", R"({"value":"baz"})"}).success();
    testEq(pvS.fetch()["value"].as<std::string>(), "baz");


    Run({"testE", "hello"}).exitWith(1); // invalid choice
    testEq(pvE.fetch()["value.index"].as<int32_t>(), 0);

    Run({"testE", "two"}).success();
    testEq(pvE.fetch()["value.index"].as<int32_t>(), 1);

    Run({"testE", "0"}).success();
    testEq(pvE.fetch()["value.index"].as<int32_t>(), 0);

    Run({"testE", "42"}).success(); // can set arbitrary index
    testEq(pvE.fetch()["value.index"].as<int32_t>(), 42);

    Run({"testE", R"({"value":{"index":1, "choices":["A","B","C"]}})"}).success();
    testEq(pvE.fetch()["value.index"].as<int32_t>(), 1);
    Run({"testE", "C"}).success();
    testEq(pvE.fetch()["value.index"].as<int32_t>(), 2);

    // update choices and assign from string with one op.  A place where order matters...
    Run({"testE", R"({"value":"d", "value.choices":["a","b","c","d"]})"}).exitWith(1);
    Run({"testE", R"({"value.choices":["x","y","z","q"], "value":"x"})"}).success();

    return testDone();
}
