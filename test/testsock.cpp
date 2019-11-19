/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstring>

#include <epicsUnitTest.h>
#include <testMain.h>
#include <epicsThread.h>
#include <osiSock.h>

#include <evhelper.h>
#include <pvxs/unittest.h>
#include <pvxs/log.h>

namespace {
using namespace pvxs::impl;

void test_udp()
{
    testDiag("Enter %s", __func__);

    evsocket A(AF_INET, SOCK_DGRAM, 0),
             B(AF_INET, SOCK_DGRAM, 0);

    SockAddr bind_addr(SockAddr::loopback(AF_INET));

    A.bind(bind_addr);
    testNotEq(bind_addr.port(), 0)<<"bound port";

    SockAddr send_addr(bind_addr);
    send_addr.setPort(0);
    B.bind(send_addr);
    testNotEq(send_addr.port(), 0);
    testNotEq(send_addr.port(), bind_addr.port());

    uint8_t msg[] = {0x12, 0x34, 0x56, 0x78};
    int ret = sendto(B.sock, (char*)msg, sizeof(msg), 0, &bind_addr->sa, bind_addr.size());
    testOk(ret==(int)sizeof(msg), "Send test ret==%d", ret);

    uint8_t rxbuf[8] = {};
    SockAddr src;

    testDiag("Call recvfrom()");
    socklen_t slen = src.size();
    ret = recvfrom(A.sock, (char*)rxbuf, sizeof(rxbuf), 0, &src->sa, &slen);

    testOk(ret==4 && rxbuf[0]==0x12 && rxbuf[1]==0x34 && rxbuf[2]==0x56 && rxbuf[3]==0x78,
            "Recv'd %d [%u, %u, %u, %u]", ret, rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);
    testEq(src, send_addr);
}

void test_local_mcast()
{
    testDiag("Enter %s", __func__);

    evsocket A(AF_INET, SOCK_DGRAM, 0),
             B(AF_INET, SOCK_DGRAM, 0);

    SockAddr mcast_addr(AF_INET);
    mcast_addr.setAddress("224.0.0.128");

#ifdef _WIN32
    SockAddr bind_addr(SockAddr::any(AF_INET));
#else
    SockAddr bind_addr(mcast_addr);
#endif

    A.bind(bind_addr);
    mcast_addr.setPort(bind_addr.port());

    SockAddr sender_addr(SockAddr::loopback(AF_INET));
    B.bind(sender_addr);

    // receiving socket joins on the loopback interface
    A.mcast_join(mcast_addr, sender_addr); // ignores port(s)

    // sending socket targets the loopback interface
    B.mcast_iface(sender_addr); // ignores port(s)
    B.mcast_ttl(1);
    B.mcast_loop(true);

    uint8_t msg[] = {0x12, 0x34, 0x56, 0x78};
    int ret = sendto(B.sock, (char*)msg, sizeof(msg), 0, &mcast_addr->sa, mcast_addr.size());
    testEq(ret, (int)sizeof(msg))<<"Send test";

    uint8_t rxbuf[8] = {};
    SockAddr src;

    testDiag("Call recvfrom()");
    socklen_t slen = src.size();
    ret = recvfrom(A.sock, (char*)rxbuf, sizeof(rxbuf), 0, &src->sa, &slen);
    testOk(ret==4 && rxbuf[0]==0x12 && rxbuf[1]==0x34 && rxbuf[2]==0x56 && rxbuf[3]==0x78,
            "Recv'd %d [%u, %u, %u, %u]", ret, rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);

    testEq(src, sender_addr);
}

void test_from_wire()
{
    testDiag("Enter %s", __func__);

    {
        uint32_t val;
        const uint8_t buf[] = {0x12, 0x34, 0x56, 0x78, 0xff, 0xff};
        FixedBuf<const uint8_t> pkt(true, buf);

        from_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(pkt.good());
        testOk(val==0x12345678, "0x%08x == 0x12345678", (unsigned)val);
    }

    {
        uint32_t val;
        const uint8_t buf[] = {0x78, 0x56, 0x34, 0x12, 0xff, 0xff};
        FixedBuf<const uint8_t> pkt(false, buf);

        from_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(pkt.good());
        testOk(val==0x12345678, "0x%08x == 0x12345678", (unsigned)val);
    }

    {
        uint32_t val = 0;
        const uint8_t buf[] = {0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 0xff};
        FixedBuf<const uint8_t> pkt(true, buf, 2);

        from_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(!pkt.good());
        testOk(val==0, "0x%08x == 0", (unsigned)val);
    }

    {
        SockAddr val;
        const uint8_t buf[] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 0x7f,0,0,1, 0xde, 0xad, 0xbe, 0xef};
        FixedBuf<const uint8_t> pkt(true, buf);

        from_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(val.family()==AF_INET);
        testOk(val->in.sin_addr.s_addr==htonl(INADDR_LOOPBACK),
               "%08x == 0x7f000001", (unsigned)ntohl(val->in.sin_addr.s_addr));
    }
}

void test_to_wire()
{
    testDiag("Enter %s", __func__);

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8];
        FixedBuf<uint8_t> pkt(true, buf);

        to_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(pkt.good());
        testOk(buf[0]==0xde && buf[1]==0xad && buf[2]==0xbe && buf[3]==0xef,
                "0x%02x%02x%02x%02x == 0xdeadbeef", buf[0], buf[1], buf[2], buf[3]);
    }

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8];
        FixedBuf<uint8_t> pkt(false, buf);

        to_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(pkt.good());
        testOk(buf[0]==0xef && buf[1]==0xbe && buf[2]==0xad && buf[3]==0xde,
                "0x%02x%02x%02x%02x == 0xefbeadde", buf[0], buf[1], buf[2], buf[3]);
    }

    {
        const SockAddr val(SockAddr::loopback(AF_INET));
        uint8_t buf[16+4];
        FixedBuf<uint8_t> pkt(true, buf);

        to_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(pkt.good());

        const uint8_t expect[16] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 0x7f,0,0,1};
        testOk1(std::memcmp(buf, expect, 16)==0);
    }

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8] = {0,0,0,0,0,0,0,0};
        FixedBuf<uint8_t> pkt(true, buf, 2);

        to_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(!pkt.good());
        testOk(buf[0]==0 && buf[1]==0 && buf[2]==0 && buf[3]==0,
                "0x%02x%02x%02x%02x == 0", buf[0], buf[1], buf[2], buf[3]);
    }
}

} // namespace

MAIN(testsock)
{
    testPlan(33);
    test_udp();
    test_local_mcast();
    test_from_wire();
    test_to_wire();
    testDiag("Done");
    libevent_global_shutdown();
    cleanup_for_valgrind();
    return testDone();
}
