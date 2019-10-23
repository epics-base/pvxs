/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvAccessCPP is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstring>

#include <epicsUnitTest.h>
#include <testMain.h>
#include <epicsThread.h>
#include <osiSock.h>

#include <evhelper.h>
#include <pvxs/log.h>

namespace {
using namespace pvxsimpl;

void test_udp()
{
    testDiag("Enter %s", __func__);

    evsocket A(AF_INET, SOCK_DGRAM, 0),
             B(AF_INET, SOCK_DGRAM, 0);

    evsockaddr bind_addr(evsockaddr::loopback(AF_INET));

    A.bind(bind_addr);
    testOk(bind_addr.port()!=0, "bound port %u", bind_addr.port());

    evsockaddr send_addr(bind_addr);
    send_addr.setPort(0);
    B.bind(send_addr);
    testOk(send_addr.port()!=0 && send_addr.port()!=bind_addr.port(),
           "sending from port port %u", send_addr.port());

    uint8_t msg[] = {0x12, 0x34, 0x56, 0x78};
    int ret = sendto(B.sock, (char*)msg, sizeof(msg), 0, &bind_addr->sa, bind_addr.size());
    testOk(ret==(int)sizeof(msg), "Send test ret==%d", ret);

    uint8_t rxbuf[8] = {};
    evsockaddr src;

    testDiag("Call recvfrom()");
    socklen_t slen = src.size();
    ret = recvfrom(A.sock, (char*)rxbuf, sizeof(rxbuf), 0, &src->sa, &slen);

    testOk(ret==4 && rxbuf[0]==0x12 && rxbuf[1]==0x34 && rxbuf[2]==0x56 && rxbuf[3]==0x78,
            "Recv'd %d [%u, %u, %u, %u]", ret, rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);
    testOk(src==send_addr, "Src %s==%s", src.tostring().c_str(), send_addr.tostring().c_str());
}

void test_local_mcast()
{
    testDiag("Enter %s", __func__);

    evsocket A(AF_INET, SOCK_DGRAM, 0),
             B(AF_INET, SOCK_DGRAM, 0);

    evsockaddr mcast_addr(AF_INET);
    mcast_addr.setAddress("224.0.0.128");

#ifdef _WIN32
    evsockaddr bind_addr(evsockaddr::any(AF_INET));
#else
    evsockaddr bind_addr(mcast_addr);
#endif

    A.bind(bind_addr);
    mcast_addr.setPort(bind_addr.port());

    evsockaddr sender_addr(evsockaddr::loopback(AF_INET));
    B.bind(sender_addr);

    // receiving socket joins on the loopback interface
    A.mcast_join(mcast_addr, sender_addr); // ignores port(s)

    // sending socket targets the loopback interface
    B.mcast_iface(sender_addr); // ignores port(s)
    B.mcast_ttl(1);
    B.mcast_loop(true);

    uint8_t msg[] = {0x12, 0x34, 0x56, 0x78};
    int ret = sendto(B.sock, (char*)msg, sizeof(msg), 0, &mcast_addr->sa, mcast_addr.size());
    testOk(ret==(int)sizeof(msg), "Send test ret==%d", ret);

    uint8_t rxbuf[8] = {};
    evsockaddr src;

    testDiag("Call recvfrom()");
    socklen_t slen = src.size();
    ret = recvfrom(A.sock, (char*)rxbuf, sizeof(rxbuf), 0, &src->sa, &slen);
    testOk(ret==4 && rxbuf[0]==0x12 && rxbuf[1]==0x34 && rxbuf[2]==0x56 && rxbuf[3]==0x78,
            "Recv'd %d [%u, %u, %u, %u]", ret, rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);

    testOk(src==sender_addr, "Src %s==%s", src.tostring().c_str(), sender_addr.tostring().c_str());

}

void test_from_wire()
{
    testDiag("Enter %s", __func__);

    {
        uint32_t val;
        const uint8_t buf[] = {0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 0xff};
        sbuf<const uint8_t> pkt(buf, 4);

        from_wire(pkt, val, true);
        testOk1(pkt.empty());
        testOk1(!pkt.err);
        testOk(val==0x12345678, "0x%08x == 0x12345678", (unsigned)val);
    }

    {
        uint32_t val;
        const uint8_t buf[] = {0x78, 0x56, 0x34, 0x12, 0xff, 0xff, 0xff, 0xff};
        sbuf<const uint8_t> pkt(buf, 4);

        from_wire(pkt, val, false);
        testOk1(pkt.empty());
        testOk1(!pkt.err);
        testOk(val==0x12345678, "0x%08x == 0x12345678", (unsigned)val);
    }

    {
        uint32_t val = 0;
        const uint8_t buf[] = {0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 0xff};
        sbuf<const uint8_t> pkt(buf, 2);

        from_wire(pkt, val, true);
        testOk1(pkt.size()==2);
        testOk1(pkt.err);
        testOk(val==0, "0x%08x == 0", (unsigned)val);
    }

    {
        evsockaddr val;
        const uint8_t buf[] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 0x7f,0,0,1, 0xde, 0xad, 0xbe, 0xef};
        sbuf<const uint8_t> pkt(buf, 16);

        from_wire(pkt, val, true);
        testOk1(pkt.empty());
        testOk1(val.family()==AF_INET);
        testOk(val->in.sin_addr.s_addr==htonl(INADDR_LOOPBACK),
               "%08x == 0x7f000001", (unsigned)ntohl(val->in.sin_addr.s_addr));
    }
}

void test_to_wire()
{
    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8];
        sbuf<uint8_t> pkt(buf, 4);

        to_wire(pkt, val, true);
        testOk1(pkt.empty());
        testOk1(!pkt.err);
        testOk(buf[0]==0xde && buf[1]==0xad && buf[2]==0xbe && buf[3]==0xef,
                "0x%02x%02x%02x%02x == 0xdeadbeef", buf[0], buf[1], buf[2], buf[3]);
    }

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8];
        sbuf<uint8_t> pkt(buf, 4);

        to_wire(pkt, val, false);
        testOk1(pkt.empty());
        testOk1(!pkt.err);
        testOk(buf[0]==0xef && buf[1]==0xbe && buf[2]==0xad && buf[3]==0xde,
                "0x%02x%02x%02x%02x == 0xdeadbeef", buf[0], buf[1], buf[2], buf[3]);
    }

    {
        const evsockaddr val(evsockaddr::loopback(AF_INET));
        uint8_t buf[16+4];
        sbuf<uint8_t> pkt(buf, 16);

        to_wire(pkt, val, true);
        testOk1(pkt.empty());
        testOk1(!pkt.err);

        const uint8_t expect[16] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 0x7f,0,0,1};
        testOk1(std::memcmp(buf, expect, 16)==0);
    }

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8] = {0,0,0,0,0,0,0,0};
        sbuf<uint8_t> pkt(buf, 2);

        to_wire(pkt, val, true);
        testOk1(pkt.size()==2);
        testOk1(pkt.err);
        testOk(buf[0]==0 && buf[1]==0 && buf[2]==0 && buf[3]==0,
                "0x%02x%02x%02x%02x == 0", buf[0], buf[1], buf[2], buf[3]);
    }
}

} // namespace

MAIN(testsock)
{
    testPlan(32);
    test_udp();
    test_local_mcast();
    test_from_wire();
    test_to_wire();
    testDiag("Done");
    return testDone();
}
