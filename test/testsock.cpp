/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiSockExt.h>

#ifndef _WIN32
#  include <poll.h>
#endif

#include <cstring>
#include <system_error>
#include <sstream>

#include <epicsUnitTest.h>
#include <testMain.h>
#include <epicsThread.h>
#include <epicsTime.h>
#include <osiSock.h>

#include <evhelper.h>
#include <pvxs/unittest.h>
#include <pvxs/log.h>

namespace {
using namespace pvxs;

#ifdef _WIN32
#  define poll WSAPoll
#  ifndef POLLIN
#    define POLLIN POLLRDNORM
#  endif
#endif

void testEndPoint()
{
    testDiag("Enter %s", __func__);

    {
        SockEndpoint ep("127.0.0.1");
        testEq(ep.addr.tostring(), "127.0.0.1");
        testEq(ep.iface, "");
        testEq(ep.ttl, -1);
    }
    {
        SockEndpoint ep("127.0.0.1:12");
        testEq(ep.addr.tostring(), "127.0.0.1:12");
        testEq(ep.iface, "");
        testEq(ep.ttl, -1);
    }
    {
        SockEndpoint ep("127.0.0.1,1");
        testEq(ep.addr.tostring(), "127.0.0.1");
        testEq(ep.iface, "");
        testEq(ep.ttl, 1);
    }
    {
        SockEndpoint ep("127.0.0.1@ifname");
        testEq(ep.addr.tostring(), "127.0.0.1");
        testEq(ep.iface, "ifname");
        testEq(ep.ttl, -1);
    }
    {
        SockEndpoint ep("127.0.0.1,1@ifname");
        testEq(ep.addr.tostring(), "127.0.0.1");
        testEq(ep.iface, "ifname");
        testEq(ep.ttl, 1);
    }
    {
        SockEndpoint ep("127.0.0.1:12,1@ifname");
        testEq(ep.addr.tostring(), "127.0.0.1:12");
        testEq(ep.iface, "ifname");
        testEq(ep.ttl, 1);
    }

    std::vector<std::string> bad({
        "127.0.0.",
        "127.0.0.1:foo",
        "127.0.0.1:",
        "127.0.0.1:12,foo",
        //"127.0.0.1:12@", // should fail...
        "127.0.0.1:12,@",
        "127.0,0.1,1@ifname",
    });
    for(const auto& inp : bad) {
        testThrows<std::runtime_error>([&inp](){
            SockEndpoint x(inp);
            (void)x;
        })<<" "<<inp;
    }
}

bool waitReadable(const evsocket& sock, double timeout=5.0)
{
    pollfd pfd{};

    pfd.fd = sock.sock;
    pfd.events = POLLIN;

    auto expire(epicsTime::getCurrent() + timeout);
    while(true) {
        auto remaining = expire - epicsTime::getCurrent();
        int msleft = remaining*1000.0;
        if(msleft <= 0)
            return false;

        testDiag("%s waiting for %d ms", __func__, msleft);
        auto ret = poll(&pfd, 1u, msleft);
        if(ret < 0) {
            auto err(SOCKERRNO);
            if(err == SOCK_EINTR)
                continue;
            testFail("%s fails with %d after %f", __func__, err, remaining);
            return false;
        }

        if(ret == 1 && (pfd.revents & POLLIN))
            return true;
    }
}

void test_bind46(const char* saddr1, const char* saddr2, int type, int expect)
{
    const std::string label = SB()<<__func__<<"("<<saddr1<<", "<<saddr2<<", "<<(type==SOCK_STREAM?"tcp":"udp")<<", "<<expect<<")";
    testDiag("%s", label.c_str());

    SockAddr addr1(saddr1);
    SockAddr addr2(saddr2);

    evsocket s1(addr1.family(), type, 0, true),
             s2(addr2.family(), type, 0, true);

    try {
        s1.bind(addr1);
    }catch(std::exception& e){
        testFail("bind() error: %s", e.what());
        return;
    }

    addr2.setPort(addr1.port());

    auto doListen = [type](const SockAddr& addr, const evsocket& sock) {
        if(type==SOCK_STREAM && listen(sock.sock, 4u)) {
            auto err = evutil_socket_geterror(sock.sock);
            testFail("Unable to listen on %s : (%d) %s",
                     addr.tostring().c_str(), err, evutil_socket_error_to_string(err));
        }
    };
    doListen(addr1, s1);

    try{
        s2.bind(addr2);
        doListen(addr2, s2);
        testEq(0, expect)<<label;
    }catch(std::system_error& e){
        auto err = e.code().value();
        testEq(err, expect)<<label<<" : "<<evutil_socket_error_to_string(err);
    }
}

void test_ifacemap()
{
    testDiag("Enter %s", __func__);

    auto& ifs = IfaceMap::instance();

    epicsGuard<epicsMutex> G(ifs.lock); // since we are playing around with the internals...

    ifs.refresh(true);

    testFalse(ifs.byIndex.empty())<<" found "<<ifs.byIndex.size()<<" interfaces";

    bool foundlo = false;
    const auto lo(SockAddr::loopback(AF_INET));

    for(const auto& pair : ifs.byIndex) {
        auto& iface = pair.second;
        testDiag("Interface %u \"%s\"", unsigned(iface.index), iface.name.c_str());
        for(const auto& pair : iface.addrs) {
            testDiag("  Address %s/%s", pair.first.tostring().c_str(), pair.second.tostring().c_str());
            if(pair.first!=lo)
                continue;
            testTrue(!foundlo)<<" Found loopback with index "<<iface.index;
            foundlo = true;
        }
    }
}

void test_udp(int af)
{
    testDiag("Enter %s(%d)", __func__, af);

    evsocket A(af, SOCK_DGRAM, 0, true),
             B(af, SOCK_DGRAM, 0, true);

    SockAddr bind_addr(SockAddr::loopback(af));

    {
        auto rxbuf = evsocket::get_buffer_size(A.sock, false);
        auto txbuf = evsocket::get_buffer_size(A.sock, true);
        testOk(rxbuf>0 && txbuf>0, "non-zero OS socket buffer sizes %zu, %zu\n", rxbuf, txbuf);
    }

    A.enable_IP_PKTINFO();
    B.enable_IP_PKTINFO();
    try{
        A.bind(bind_addr);
    }catch(std::system_error& e){
        if(af==AF_INET6 && e.code().value()==SOCK_EADDRNOTAVAIL) {
            testSkip(7, "No runtime IPv6 support");
            return;
        }
        testAbort("Unable to bind %s : (%d) %s", bind_addr.tostring().c_str(), e.code().value(), e.what());
    }
    testNotEq(bind_addr.port(), 0)<<"bound port";

    SockAddr send_addr(bind_addr);
    send_addr.setPort(0);
    B.bind(send_addr);
    testNotEq(send_addr.port(), 0);
    testNotEq(send_addr.port(), bind_addr.port());

    {
        uint8_t msg[] = {0x12, 0x34, 0x56, 0x78};
        int ret = sendtox{B.sock, (char*)msg, sizeof(msg), &bind_addr}.call();
        testOk(ret==(int)sizeof(msg), "Send test ret==%d(%d)", ret, EVUTIL_SOCKET_ERROR());
    }

    SockAddr reply_to, reply_from;
    uint64_t reply_from_iface = 0;
    {
        testDiag("Call recvfrom()");

        uint8_t rxbuf[8] = {};
        SockAddr src, dest;
        auto rx(recvfromx{A.sock, (char*)rxbuf, sizeof(rxbuf), &src, &dest});
        int ret = rx.call();
        // only the destination address is captured, not the port
        if(dest.family()!=AF_UNSPEC)
            dest.setPort(bind_addr.port());

        testOk(ret==4 && rxbuf[0]==0x12 && rxbuf[1]==0x34 && rxbuf[2]==0x56 && rxbuf[3]==0x78,
                "Recv'd %d(%d) [%u, %u, %u, %u]", ret, EVUTIL_SOCKET_ERROR(), rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);
        testEq(src, send_addr);
        testEq(dest, bind_addr);

        reply_to = src;
        reply_from = dest;
        reply_from_iface = rx.dstif;
    }

    {
        testDiag("Call sendto() with source addr override");
        uint8_t msg[] = {0x9a, 0xbc, 0xde, 0xf0};
        // reply to "src" from "dest"
        int ret = sendtox{A.sock, (char*)msg, sizeof(msg), &reply_to, &reply_from, reply_from_iface}.call();
        testOk(ret==(int)sizeof(msg), "Send test ret==%d(%d)", ret, EVUTIL_SOCKET_ERROR());
    }

    {
        testDiag("Call recvfrom()");

        uint8_t rxbuf[8] = {};
        SockAddr src, dest;
        auto rx(recvfromx{B.sock, (char*)rxbuf, sizeof(rxbuf), &src, &dest});
        int ret = rx.call();
        // only the destination address is captured, not the port
        if(dest.family()!=AF_UNSPEC)
            dest.setPort(send_addr.port());

        testOk(ret==4 && rxbuf[0]==0x9a && rxbuf[1]==0xbc && rxbuf[2]==0xde && rxbuf[3]==0xf0,
                "Recv'd %d(%d) [%u, %u, %u, %u]", ret, EVUTIL_SOCKET_ERROR(), rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);
        testEq(src, reply_from);
        testEq(dest, reply_to);
    }
}

void test_local_mcast()
{
    testDiag("Enter %s", __func__);

    IfaceMap ifinfo;

    evsocket A(AF_INET, SOCK_DGRAM, 0, true),
             B(AF_INET, SOCK_DGRAM, 0, true);

    SockEndpoint mcast_addr("224.0.0.128,1@127.0.0.1");

    // We could bind to mcast_addr on all targets except WIN32
    SockAddr bind_addr(SockAddr::any(AF_INET));

    A.enable_IP_PKTINFO();
    A.bind(bind_addr);
    mcast_addr.addr.setPort(bind_addr.port());

    SockAddr sender_addr(SockAddr::loopback(AF_INET));
    B.bind(sender_addr);

    // receiving socket joins on the loopback interface
    A.mcast_join(mcast_addr.resolve()); // ignores port(s)

    // sending socket targets the loopback interface
    B.mcast_prep_sendto(mcast_addr); // ignores port(s)
    B.mcast_loop(true);

    uint8_t msg[] = {0x12, 0x34, 0x56, 0x78};
    int ret = sendto(B.sock, (char*)msg, sizeof(msg), 0, &mcast_addr.addr->sa, mcast_addr.addr.size());
    testEq(ret, (int)sizeof(msg))<<"Send test";

    uint8_t rxbuf[8] = {};
    SockAddr src;
    SockAddr dest;

    testDiag("Call recvfrom()");
    recvfromx rx{A.sock, (char*)rxbuf, sizeof(rxbuf), &src, &dest};
    ret = rx.call();
    if(dest.family()==AF_INET)
        dest.setPort(mcast_addr.addr.port());

    testTrue(ret>=0 && rx.dstif>0 && ifinfo.has_address(rx.dstif, sender_addr))
            <<" received on index "<<rx.dstif;

    testOk(ret==4 && rxbuf[0]==0x12 && rxbuf[1]==0x34 && rxbuf[2]==0x56 && rxbuf[3]==0x78,
            "Recv'd %d [%u, %u, %u, %u]", ret, rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]);

    testEq(src, sender_addr);
    testEq(dest, mcast_addr.addr);
}

void test_mcast_scope()
{
    testDiag("Enter %s", __func__);

    SockEndpoint mcast_addr("224.0.0.128,1@127.0.0.1");
    auto any(SockAddr::any(AF_INET));
    auto lo(SockAddr::loopback(AF_INET));
    auto sender(SockAddr::loopback(AF_INET));

    evsocket TX (AF_INET, SOCK_DGRAM, 0, true),
             RX1(AF_INET, SOCK_DGRAM, 0, true),
             RX2(AF_INET, SOCK_DGRAM, 0, true),
             RX3(AF_INET, SOCK_DGRAM, 0, true),
             RX4(AF_INET, SOCK_DGRAM, 0, true);

    epicsSocketEnableAddressUseForDatagramFanout(RX1.sock);
    epicsSocketEnableAddressUseForDatagramFanout(RX2.sock);
    epicsSocketEnableAddressUseForDatagramFanout(RX3.sock);
    epicsSocketEnableAddressUseForDatagramFanout(RX4.sock);

    TX.mcast_loop(true);
    TX.mcast_prep_sendto(mcast_addr);
    TX.bind(sender);
    testShow()<<" sender bound to "<<sender;

    // ordering of bind() before joining mcast group is "strongly recommended"
    // by winsock bind() documentation

    RX1.bind(any);
    mcast_addr.addr.setPort(any.port()); // bind all RX* to the same port
    lo.setPort(any.port());
    testShow()<<" RX1 bound to "<<any;
    RX2.bind(any);
    testShow()<<" RX2 bound to "<<any;
    RX3.bind(lo);
    testShow()<<" RX3 bound to "<<lo;
    if(evsocket::ipstack!=evsocket::Winsock) {
        // winsock doesn't allow binding to an mcast address
        RX4.bind(mcast_addr.addr);
        testShow()<<" RX4 bound to "<<mcast_addr;
    }

    testShow()<<" Join RX1 to "<<mcast_addr<<" on "<<lo;
    RX1.mcast_join(mcast_addr.resolve());

    const char msg[] = "hello world!";
    auto msglen = sizeof(msg)-1u;

    auto ret = sendto(TX.sock, msg, msglen, 0, &mcast_addr.addr->sa, mcast_addr.addr.size());
    testEq(ret, int(msglen))<<" sendto("<<sender<<" -> "<<mcast_addr<<") err="<<EVUTIL_SOCKET_ERROR();

    auto doRX = [&lo, &msg, msglen](unsigned idx, const evsocket& sock, bool expectrx) {
        testShow()<<"RX"<<idx<<" expect "<<(expectrx ? "success" : "failure");
        char buf[sizeof(msg)-1u+2u];
        SockAddr src, dest;
        recvfromx rx{sock.sock, buf, sizeof(buf), &src, &dest};

        int ret = -1;
        if(waitReadable(sock)) {
            ret = rx.call();
        } else {
            ret = -1;
            EVUTIL_SET_SOCKET_ERROR(SOCK_EWOULDBLOCK);
        }

        if(expectrx) {
            testEq(ret, int(msglen))<<" recvfrom() RX"<<idx<<" err="<<EVUTIL_SOCKET_ERROR()<<" src="<<src;
            testTrue(lo.compare(src))<<" RX"<<idx<<" from "<<src;

            testTrue(memcmp(buf, msg, msglen)==0)<<" RX"<<idx;

        } else {
            testTrue(ret<0)<<" RX"<<idx<<" expected error ret="<<ret<<" err="<<EVUTIL_SOCKET_ERROR();
            testSkip(2, "Not relevant");
        }
    };

#ifdef _WIN32
    doRX(1, RX1, true);
    doRX(2, RX2, evsocket::ipstack==evsocket::Linsock); // WINE: really Linux IP stack, but we couldn't clear IP_MULTICAST_ALL
    doRX(3, RX3, false);
    testSkip(3, "winsock doesn't allow bind() to an mcast address");

#else
    doRX(1, RX1, true);
    doRX(2, RX2, false);
    doRX(3, RX3, false);
    doRX(4, RX4, false);
#endif
}

void test_from_wire()
{
    testDiag("Enter %s", __func__);

    {
        uint32_t val=0;
        uint8_t buf[] = "\x12\x34\x56\x78\xff\xff";
        FixedBuf pkt(true, buf);

        from_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(pkt.good());
        testOk(val==0x12345678, "0x%08x == 0x12345678", (unsigned)val);
    }

    {
        uint32_t val=0;
        uint8_t buf[] = "\x78\x56\x34\x12\xff\xff";
        FixedBuf pkt(false, buf);

        from_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(pkt.good());
        testOk(val==0x12345678, "0x%08x == 0x12345678", (unsigned)val);
    }

    {
        uint32_t val = 0;
        uint8_t buf[] = "\x12\x34";
        FixedBuf pkt(true, buf);

        from_wire(pkt, val);
        testEq(pkt.size(), 2u);
        testOk1(!pkt.good());
        testOk(val==0, "0x%08x == 0", (unsigned)val);
    }

    {
        SockAddr val;
        uint8_t buf[] = "\0\0\0\0\0\0\0\0\0\0\xff\xff\x7f\0\0\x01\xde\xad\xbe\xef";
        FixedBuf pkt(true, buf);

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
        uint8_t buf[8+1];
        FixedBuf pkt(true, buf);

        to_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(pkt.good());
        testOk(buf[0]==0xde && buf[1]==0xad && buf[2]==0xbe && buf[3]==0xef,
                "0x%02x%02x%02x%02x == 0xdeadbeef", buf[0], buf[1], buf[2], buf[3]);
    }

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[8+1];
        FixedBuf pkt(false, buf);

        to_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(pkt.good());
        testOk(buf[0]==0xef && buf[1]==0xbe && buf[2]==0xad && buf[3]==0xde,
                "0x%02x%02x%02x%02x == 0xefbeadde", buf[0], buf[1], buf[2], buf[3]);
    }

    {
        const SockAddr val(SockAddr::loopback(AF_INET));
        uint8_t buf[16+4+1];
        FixedBuf pkt(true, buf);

        to_wire(pkt, val);
        testEq(pkt.size(), 4u);
        testOk1(pkt.good());

        const uint8_t expect[16] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 0x7f,0,0,1};
        testOk1(std::memcmp(buf, expect, 16)==0);
    }

    {
        const uint32_t val = 0xdeadbeef;
        uint8_t buf[] = "\0\0\0\0\0\0\0\0";
        FixedBuf pkt(true, buf, 2);

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
    SockAttach attach;
    logger_config_env();
    testPlan(100);
    testSetup();
    testEndPoint();
    // check for behavior when binding ipv4 and ipv6 to the same socket
    // as a function of socket type and order.
    if(evsocket::canIPv6) {
        // IPv4 and v6 loopback addresses are entirely distinct,
        // so no problem binding to both w/ or w/o IPV6_V6ONLY
        test_bind46("127.0.0.1" , "::1"       , SOCK_DGRAM  , 0);
        test_bind46("::1"       , "127.0.0.1" , SOCK_DGRAM  , 0);
        test_bind46("127.0.0.1" , "::1"       , SOCK_STREAM , 0);
        test_bind46("::1"       , "127.0.0.1" , SOCK_STREAM , 0);
#if defined(_WIN32) || defined(__rtems__)
        test_bind46("0.0.0.0"   , "::"        , SOCK_DGRAM  , 0);
        test_bind46("::"        , "0.0.0.0"   , SOCK_DGRAM  , 0);
        test_bind46("0.0.0.0"   , "::"        , SOCK_STREAM , 0);
        test_bind46("::"        , "0.0.0.0"   , SOCK_STREAM , 0);
#elif defined(__linux__)
        test_bind46("0.0.0.0"   , "::"        , SOCK_DGRAM  , EADDRINUSE);
        test_bind46("::"        , "0.0.0.0"   , SOCK_DGRAM  , EADDRINUSE);
        test_bind46("0.0.0.0"   , "::"        , SOCK_STREAM , EADDRINUSE);
        test_bind46("::"        , "0.0.0.0"   , SOCK_STREAM , EADDRINUSE);
#else
        test_bind46("0.0.0.0"   , "::"        , SOCK_DGRAM  , 0);
        test_bind46("::"        , "0.0.0.0"   , SOCK_DGRAM  , EADDRINUSE);
        test_bind46("0.0.0.0"   , "::"        , SOCK_STREAM , 0);
        test_bind46("::"        , "0.0.0.0"   , SOCK_STREAM , EADDRINUSE);
#endif
    } else {
        testSkip(8, "No IPv6 runtime support");
    }
    test_ifacemap();
    test_udp(AF_INET);
    try{
        test_udp(AF_INET6);
    }catch(std::exception&e){
        testAbort("test_udp6: %s", e.what());
    }
    test_local_mcast();
    test_mcast_scope();
    test_from_wire();
    test_to_wire();
    testDiag("Done");
    cleanup_for_valgrind();
    return testDone();
}
