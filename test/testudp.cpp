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
using namespace pvxs;

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
        testEq(msg.server, SockAddr::loopback(AF_INET, 0x1234));

        uint8_t expect[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        testOk1(msg.guid.size()==12 && std::equal(msg.guid.begin(), msg.guid.end(), expect));

        rx.signal();
    });
    sub->start();

    testDiag("Listen on %s", listener.tostring().c_str());

    uint8_t msg[46] = {
        // header
        0xca, pva_version::server, 0, CMD_BEACON,
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
            testDiag("  For %s", name.name);
        }
        if(testEq(msg.names.size(), names.size())) {
            size_t i=0;
            for(auto name : msg.names) {
                testEq(msg.names[i].id, i+1);
                testEq(msg.names[i++].name, name.name);
            }
        }
        rx.signal();
    });
    sub->start();

    std::vector<uint8_t> msg(1024, 0);
    VectorOutBuf M(be, msg);

    M.skip(8, __FILE__, __LINE__); // placeholder for header
    to_wire(M, uint32_t(0x12345678));
    to_wire(M, uint8_t(pva_search_flags::Unicast)); // 127.0.0.1 is ucast
    M.skip(3, __FILE__, __LINE__);
    SockAddr reply(SockAddr::any(AF_INET, 0x1020));
    to_wire(M, reply);
    to_wire(M, uint16_t(reply.port()));
    // one protocol w/ 3 chars
    to_wire(M, Size{1});
    to_wire(M, "tcp");
    to_wire(M, uint16_t(names.size()));
    uint32_t i=1;
    for(auto name : names) {
        to_wire(M, i++);
        to_wire(M, name);
    }

    auto pktlen = M.save()-msg.data();

    FixedBuf H(be, msg.data(), 8);
    to_wire(H, Header{CMD_SEARCH, 0, uint32_t(pktlen-8)});

    testOk1(M.good() && H.good());
    testOk1(M.save()>=msg.data());
    testOk1(M.save()<=msg.data()+msg.size());

    testOk1(sendto(sock.sock, (char*)msg.data(), pktlen, 0, &listener->sa, listener.size())==int(pktlen));
    manager.sync();
    testOk1(!!rx.wait(30.0));
}

} // namespace

int main(int argc, char *argv[])
{
    SockAttach attach;
    testPlan(46);
    testSetup();
    pvxs::logger_config_env();
    testBeacon(true);
    testBeacon(false);
    testSearch(true , {"hello"});
    testSearch(false, {"hello"});
    testSearch(true , {"one", "two"});
    testSearch(false, {"one", "two"});
    cleanup_for_valgrind();
    return testDone();
}
