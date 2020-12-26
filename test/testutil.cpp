/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>
#include <osiProcess.h>

#include <epicsThread.h>

#include <pvxs/unittest.h>
#include <pvxs/util.h>
#include <utilpvt.h>

namespace {
using namespace pvxs;


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

} // namespace

MAIN(testutil)
{
    testPlan(4);
    testTrue(version_abi_check())<<" 0x"<<std::hex<<PVXS_VERSION<<" ~= 0x"<<std::hex<<PVXS_ABI_VERSION;
    testAccount();
    return testDone();
}
