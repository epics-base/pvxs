/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <cstring>

#include <testMain.h>
#include <epicsUnitTest.h>
#include <pvxs/unittest.h>

#include <osiSock.h>
#include <event2/util.h>
#include <epicsEvent.h>

#include <pvxs/log.h>
#include "evhelper.h"
#include <udp_collector.h>

namespace {
using namespace pvxsimpl;

void testBeacon(bool be)
{
    testDiag("In %s", __func__);

    SockAddr listener(SockAddr::loopback(AF_INET));
    SockAddr sender(SockAddr::loopback(AF_INET));

    evsocket sock(AF_INET, SOCK_DGRAM, 0);
    sock.bind(sender);
    testDiag("Sending from %s", sender.tostring().c_str());

    epicsEvent rx;
    auto manager = UDPManager::instance();
    auto sub = manager.onBeacon(listener,
                                [&sender, &rx](const UDPManager::Beacon& msg)
    {
        testDiag("Beacon received");
        testEq(msg.src, sender);
        testEq(msg.server, SockAddr::any(AF_INET, 0x1234));

        uint8_t expect[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        testOk1(msg.guid.size()==12 && std::equal(msg.guid.begin(), msg.guid.end(), expect));

        rx.signal();
    });

    testDiag("Listen on %s", listener.tostring().c_str());

    uint8_t msg[46] = {
        // header
        0xca, pva_version::server, 0, pva_app_msg::Beacon,
        0, 0, 0, 0, // length filled in later
        // GUID
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        // unused/ignored
        0, 0, 0, 0,
        // Server address
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0,
        0, 0, // port filled in later
        // protocol
        3, 't', 'c', 'p',
        // anything further is ignored
    };

    if(be) {
        msg[2] |= pva_flags::MSB;
        msg[7] = sizeof(msg)-8;
        msg[40] = 0x12;
        msg[41] = 0x34;
    } else {
        msg[4] = sizeof(msg)-8;
        msg[40] = 0x34;
        msg[41] = 0x12;
    }

    testOk1(sendto(sock.sock, (char*)msg, sizeof(msg), 0, &listener->sa, listener.size())==sizeof(msg));
    manager.sync();
    testOk1(!!rx.wait(30.0));
}

void testSearch(bool be, std::initializer_list<const char*> names)
{
    testDiag("In %s", __func__);

    SockAddr listener(SockAddr::loopback(AF_INET));
    SockAddr sender(SockAddr::loopback(AF_INET));

    evsocket sock(AF_INET, SOCK_DGRAM, 0);
    sock.bind(sender);
    testDiag("Sending from %s", sender.tostring().c_str());

    epicsEvent rx;
    auto manager = UDPManager::instance();
    auto sub = manager.onSearch(listener, [&rx, names](const UDPManager::Search& msg)
    {
        testDiag("Search received");
        for(auto name : msg.names) {
            testDiag("  For %s", name);
        }
        if(testEq(msg.names.size(), names.size())) {
            size_t i=0;
            for(auto name : msg.names) {
                testEq(msg.names[i++], name);
            }
        }
        rx.signal();
    });

    std::vector<uint8_t> msg(1024, 0);
    sbuf<uint8_t> M(msg.data(), msg.size());
    M[0] = 0xca;
    M[1] = pva_version::client;
    M[2] = be ? pva_flags::MSB : 0;
    M[3] = pva_app_msg::Search;
    M+=4;
    M+=4; //come back to this later
    to_wire(M, uint32_t(0x12345678), be);
    M+=4;
    SockAddr reply(SockAddr::any(AF_INET, 0x1020));
    to_wire(M, reply, be);
    to_wire(M, uint16_t(reply.port()), be);
    // one protocol w/ 3 chars
    M[0] = 1;
    M[1] = 3;
    M[2] = 't';
    M[3] = 'c';
    M[4] = 'p';
    M+=5;
    to_wire(M, uint16_t(names.size()), be);
    uint32_t i=1;
    for(auto name : names) {
        to_wire(M, i++, be);
        M[0] = strlen(name);
        memcpy((char*)M.pos+1, name, M[0]);
        M+=1+M[0];
    }
    testOk1(!M.err);
    testDiag("Buffer pos %u of %u", unsigned(M.pos-msg.data()), unsigned(msg.size()));

    const size_t ntx = M.pos-msg.data();
    testOk1(sendto(sock.sock, (char*)msg.data(), ntx, 0, &listener->sa, listener.size())==int(ntx));
    manager.sync();
    testOk1(!!rx.wait(30.0));
}

} // namespace

int main(int argc, char *argv[])
{
    testPlan(32);
    pvxs::logger_config_env();
    testBeacon(true);
    testBeacon(false);
    testSearch(true , {"hello"});
    testSearch(false, {"hello"});
    testSearch(true , {"one", "two"});
    testSearch(false, {"one", "two"});
    return testDone();
}
