/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <vector>
#include <ostream>
#include <sstream>

#include <epicsUnitTest.h>
#include <testMain.h>
#include <osiProcess.h>

#include <epicsThread.h>

#include <pvxs/unittest.h>
#include <pvxs/util.h>
#include <utilpvt.h>

namespace {
using namespace pvxs;

void testServerGUID()
{
    testShow()<<__func__;

    testEq("0x000000000000000000000000", std::string(SB()<<ServerGUID{}));

    ServerGUID seq;
    for(size_t i=0; i<seq.size(); i++)
        seq[i] = i;
    testEq("0x000102030405060708090a0b", std::string(SB()<<seq));

}

void testFill()
{
    testShow()<<__func__;

    MPMCFIFO<std::unique_ptr<int>> Q(4u);

    for(int i=0; i<4; i++)
        Q.push(std::unique_ptr<int>{new int(i)});

    testEq(*Q.pop(), 0);
    testEq(*Q.pop(), 1);
    testEq(*Q.pop(), 2);
    testEq(*Q.pop(), 3);
}

struct Spammer : public epicsThreadRunable
{
    MPMCFIFO<int>& Q;
    const int begin, end;
    epicsThread worker;
    Spammer(MPMCFIFO<int>& Q, int begin, int end)
        :Q(Q)
        ,begin(begin)
        ,end(end)
        ,worker(*this, "spammer", epicsThreadGetStackSize(epicsThreadStackBig))
    {
        worker.start();
    }

    void run() override final {
        for(auto i=begin; i<end; i++)
            Q.push(i);
    }
};

void testSpam()
{
    testShow()<<__func__;

    MPMCFIFO<int> Q(32u);
    std::vector<bool> rxd(1024, false);

    Spammer A(Q, 0, 256);
    Spammer B(Q, 256, 512);
    Spammer C(Q, 512, 768);
    Spammer D(Q, 768, 1024);

    // not critical, but try to get some of the spammers to block
    epicsThreadSleep(0.1);

    for(size_t i=0; i<rxd.size(); i++) {
        auto n = Q.pop();
        rxd.at(n) = true;
    }

    bool ok = true;
    for(size_t i=0; i<rxd.size(); i++) {
        ok &= rxd[i];
    }
    testTrue(ok)<<" Received all";
}

struct Receiver : public epicsThreadRunable
{
    MPMCFIFO<int>& Q;
    std::array<std::atomic<bool>, 1024>& rxd;
    epicsThread worker;
    Receiver(MPMCFIFO<int>& Q, std::array<std::atomic<bool>, 1024>& rxd)
        :Q(Q)
        ,rxd(rxd)
        ,worker(*this, "rxer", epicsThreadGetStackSize(epicsThreadStackBig))
    {
        worker.start();
    }

    void run() override final {
        while(true) {
            int val = Q.pop();
            if(val<0)
                break;
            bool prev = rxd[val].exchange(true, std::memory_order_relaxed);
            if(prev)
                testFail("Duplicate %d", val);
        }
    }
};

void testSpamMany()
{
    testShow()<<__func__;

    MPMCFIFO<int> Q(32u);
    std::array<std::atomic<bool>, 1024> rxd{};

    Spammer A(Q, 0, 256);
    Spammer B(Q, 256, 512);
    Spammer C(Q, 512, 768);
    Spammer D(Q, 768, 1024);

    Receiver X(Q, rxd);
    Receiver Y(Q, rxd);
    Receiver Z(Q, rxd);

    // not critical, but try to get some of the spammers to block
    epicsThreadSleep(0.1);

    A.worker.exitWait();
    B.worker.exitWait();
    C.worker.exitWait();
    D.worker.exitWait();
    testDiag("All push()'d");

    Q.push(-1);
    Q.push(-1);
    Q.push(-1);
    X.worker.exitWait();
    Y.worker.exitWait();
    Z.worker.exitWait();
    testDiag("All pop()'d");

    bool ok = true;
    for(size_t i=0; i<rxd.size(); i++) {
        ok &= rxd[i];
    }
    testTrue(ok)<<" Received all";
}

void testAccount()
{
    testShow()<<__func__;

    std::string account;
    {
        std::vector<char> buf(128);
        testOk(osiGetUserName(buf.data(), buf.size()-1u)==osiGetUserNameSuccess, "osiGetUserName()");
        buf.back() = '\0';
        account = buf.data();
    }
    testOk(!account.empty(), "User: '%s'", account.c_str());

    std::set<std::string> roles;
    osdGetRoles(account, roles);

    testNotEq(roles.size(), 0u);
    for(auto& role : roles) {
        testDiag(" %s", role.c_str());
    }
}

void testTestEq()
{
    testShow()<<__func__;

    testStrNotEq((char*)nullptr, std::string());
    testStrNotEq(std::string(), (char*)nullptr);
    testStrEq((char*)nullptr, (char*)nullptr);
    testStrEq(std::string(), std::string());

    testStrEq("hello", "hello");
    testStrEq("hello", std::string("hello"));
    testStrEq(std::string("hello"), "hello");
    testStrEq(std::string("hello"), std::string("hello"));

    testStrNotEq("hello", "world");
    testStrNotEq("hello", std::string("world"));
    testStrNotEq(std::string("hello"), "world");
    testStrNotEq(std::string("hello"), std::string("world"));

    testStrMatch("[Hh]ello [Ww]orld", "hello world");
}

void testStrDiff()
{
    testShow()<<__func__;

    const auto testD = [](const char *lhs, const char *rhs, const char *expect) -> bool {
        std::ostringstream strm;
        strDiff(strm, lhs, rhs);
        auto actual(strm.str());
        return testEq(expect, actual).operator bool();
    };

    testD("", "", "");
    testD("one", "one", "  \"one\"\n");
    testD("one\n",
          "one\n",
          "  \"one\"\n");
    testD("one\n",
          "two\n",
          "- \"one\"\n"
          "+ \"two\"\n");
    testD("one\n"
          " aaa\n"
          "two\n",
          "one\n"
          " bbb\n"
          "two\n",
          "  \"one\"\n"
          "- \" aaa\"\n"
          "+ \" bbb\"\n"
          "  \"two\"\n");
    testD("one\n"
          " aaa\n"
          "two\n",
          "one\n"
          "two\n",
          "  \"one\"\n"
          "- \" aaa\"\n"
          "  \"two\"\n");
    testD("one\n"
          "two\n",
          "one\n"
          " bbb\n"
          "two\n",
          "  \"one\"\n"
          "+ \" bbb\"\n"
          "  \"two\"\n");
    testD("one\n"
          " aaa\n"
          "two\n"
          " xxx\n",
          "one\n"
          " bbb\n"
          "two\n"
          " yyy\n",
          "  \"one\"\n"
          "- \" aaa\"\n"
          "+ \" bbb\"\n"
          "  \"two\"\n"
          "- \" xxx\"\n"
          "+ \" yyy\"\n");
}

size_t onceCount[2];

template<size_t I>
void onceInc() {
    onceCount[I]++;
}

void testOnce()
{
    testShow()<<__func__;

    threadOnce<onceInc<0>>();
    threadOnce<onceInc<1>>();
    threadOnce<onceInc<0>>();
    threadOnce<onceInc<1>>();

    testEq(onceCount[0], 1u);
    testEq(onceCount[1], 1u);
}

} // namespace

MAIN(testutil)
{
    testPlan(35);
    testTrue(version_abi_check())<<" 0x"<<std::hex<<PVXS_VERSION<<" ~= 0x"<<std::hex<<PVXS_ABI_VERSION;
    testServerGUID();
    testFill();
    testSpam();
    testSpamMany();
    testAccount();
    testTestEq();
    testStrDiff();
    testOnce();
    return testDone();
}
