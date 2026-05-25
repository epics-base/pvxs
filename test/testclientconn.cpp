/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Drive a real client::Context against a hand-rolled "server" which speaks
// just enough of the PVA wire protocol to reach a given operation state, then
// injects a crafted frame the real server state machine would never send.
// Used to exercise client-side connection/operation state-machine handling
// against a hostile or buggy peer.

#include <atomic>
#include <functional>
#include <vector>

#include <testMain.h>
#include <epicsUnitTest.h>
#include <epicsEvent.h>
#include <epicsThread.h>

#include <osiSock.h>
#include <event2/util.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>

#include "evhelper.h"   // pulls in pvaproto.h (Header, VectorOutBuf, to_wire, ...)

namespace {
using namespace pvxs;

// blocking send of exactly n bytes
bool sendn(evutil_socket_t fd, const void* buf, size_t n)
{
    auto p = static_cast<const char*>(buf);
    while(n) {
        int r = ::send(fd, p, n, 0);
        if(r <= 0)
            return false;
        p += r;
        n -= size_t(r);
    }
    return true;
}

// blocking recv of exactly n bytes.  false on EOF or error.
bool recvn(evutil_socket_t fd, void* buf, size_t n)
{
    auto p = static_cast<char*>(buf);
    while(n) {
        int r = ::recv(fd, p, n, 0);
        if(r <= 0)
            return false;
        p += r;
        n -= size_t(r);
    }
    return true;
}

// Build one application/control frame (always little-endian body, Server flag
// set) and write it.  bodyfn appends the body; the 8-byte header is filled in
// afterwards with the resulting length.
bool sendFrame(evutil_socket_t fd, uint8_t cmd, uint8_t extraFlags,
               const std::function<void(VectorOutBuf&)>& bodyfn)
{
    std::vector<uint8_t> msg(256, 0u); // larger than any frame here, so no realloc
    VectorOutBuf M(false, msg);        // false => LSB
    M.skip(8, __FILE__, __LINE__);     // placeholder for header
    if(bodyfn)
        bodyfn(M);
    if(!M.good())
        return false;
    auto pktlen = M.save() - msg.data();

    FixedBuf H(false, msg.data(), 8);
    to_wire(H, Header{cmd, uint8_t(pva_flags::Server | extraFlags), uint32_t(pktlen - 8)});
    if(!H.good())
        return false;

    return sendn(fd, msg.data(), size_t(pktlen));
}

// Receive one whole frame.  Honors the peer's MSB flag for the length field and
// reports it so the body can be decoded in the same byte order.  Control
// messages carry no body.  false on EOF or error.
bool recvFrame(evutil_socket_t fd, uint8_t& cmd, bool& be, std::vector<uint8_t>& body)
{
    uint8_t hdr[8];
    if(!recvn(fd, hdr, sizeof(hdr)))
        return false;
    if(hdr[0] != 0xca)
        return false;
    be = hdr[2] & pva_flags::MSB;
    cmd = hdr[3];

    if(hdr[2] & pva_flags::Control) {
        body.clear();
        return true; // control frames are header-only
    }

    FixedBuf L(be, hdr + 4, 4);
    uint32_t len = 0;
    from_wire(L, len);
    if(!L.good())
        return false;
    body.resize(len);
    if(len && !recvn(fd, body.data(), len))
        return false;
    return true;
}

enum MockOutcome {
    Pending,
    BadHandshake,   // peer diverged from the expected handshake
    Survived,       // bad frame injected, client closed the connection cleanly
    Unexpected,     // client sent more data instead of disconnecting
    NoReaction,     // client neither closed nor responded (kept the bad op alive)
};

struct Mock : public epicsThreadRunable {
    evsocket listener;
    uint16_t port = 0;
    std::atomic<int> outcome{Pending};
    std::atomic<unsigned> initSubcmd{0xffff};
    epicsEvent done;
    epicsThread worker;
    bool started = false;

    Mock()
        :listener(AF_INET, SOCK_STREAM, 0, true) // blocking
        ,worker(*this, "mockpeer", epicsThreadGetStackSize(epicsThreadStackMedium))
    {
        SockAddr addr(SockAddr::loopback(AF_INET));
        listener.bind(addr);
        listener.listen(1);
        port = addr.port();
    }

    ~Mock()
    {
        if(started)
            worker.exitWait();
    }

    void start() { started = true; worker.start(); }

    void finish(MockOutcome o)
    {
        outcome.store(o);
        done.signal();
    }

    void run() override final
    {
        evutil_socket_t cfd = ::accept(listener.sock, nullptr, nullptr);
        if(cfd == int(INVALID_SOCKET)) {
            finish(BadHandshake);
            return;
        }
        // Bound every blocking recv so a client that hangs, stalls the
        // handshake, or keeps a bad operation alive cannot wedge this thread.
        // Windows SO_RCVTIMEO wants a DWORD of milliseconds, POSIX a timeval.
#ifdef _WIN32
        const uint32_t tmo = 5000u; // ms; 4 bytes == DWORD, no <windows.h> needed
#else
        const struct timeval tmo{5, 0};
#endif
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        MockOutcome o = play(cfd);
        evutil_closesocket(cfd);
        finish(o);
    }

    // Drive the handshake to MONITOR INIT, inject the hostile frame, and report
    // how the client reacted.
    MockOutcome play(evutil_socket_t cfd)
    {
        uint8_t cmd = 0;
        bool be = false;
        std::vector<uint8_t> body;

        // Latch the client's TX byte order to little-endian.
        if(!sendFrame(cfd, pva_ctrl_msg::SetEndian, pva_flags::Control, nullptr))
            return BadHandshake;

        // CONNECTION_VALIDATION: serverReceiveBufferSize, introspectionMax, then
        // a single offered auth method.
        if(!sendFrame(cfd, CMD_CONNECTION_VALIDATION, 0u, [](VectorOutBuf& M){
                          to_wire(M, uint32_t(0x10000));
                          to_wire(M, uint16_t(0x7fff));
                          to_wire(M, Size{1});
                          to_wire(M, "anonymous");
                      }))
            return BadHandshake;

        // client's CONNECTION_VALIDATION reply (auth selection + creds) -- drain
        if(!recvFrame(cfd, cmd, be, body) || cmd != CMD_CONNECTION_VALIDATION)
            return BadHandshake;

        if(!sendFrame(cfd, CMD_CONNECTION_VALIDATED, 0u, [](VectorOutBuf& M){
                          to_wire(M, Status{Status::Ok});
                      }))
            return BadHandshake;

        // client's CREATE_CHANNEL: count(u16), then cid(u32) + name(string)
        if(!recvFrame(cfd, cmd, be, body) || cmd != CMD_CREATE_CHANNEL)
            return BadHandshake;
        uint32_t cid = 0;
        {
            FixedBuf B(be, body);
            uint16_t count = 0;
            from_wire(B, count);
            from_wire(B, cid);
            if(!B.good() || count != 1u)
                return BadHandshake;
        }

        // accept the channel
        if(!sendFrame(cfd, CMD_CREATE_CHANNEL, 0u, [cid](VectorOutBuf& M){
                          to_wire(M, cid);
                          to_wire(M, uint32_t(1u)); // sid
                          to_wire(M, Status{Status::Ok});
                      }))
            return BadHandshake;

        // client's MONITOR INIT: sid(u32), ioid(u32), subcmd(u8=0x08), pvRequest
        if(!recvFrame(cfd, cmd, be, body) || cmd != CMD_MONITOR)
            return BadHandshake;
        uint32_t ioid = 0;
        {
            FixedBuf B(be, body);
            uint32_t sid = 0;
            from_wire(B, sid);
            from_wire(B, ioid);
            if(!B.good() || body.size() < 9)
                return BadHandshake;
            // subcmd is a single byte (byte order irrelevant); read it directly
            // rather than via from_wire<uint8_t>, which trips a spurious
            // -Wmaybe-uninitialized in this inlining context on some GCC versions.
            initSubcmd.store(body[8]);
        }

        // Hostile frame: a MONITOR *data* update (subcmd has neither INIT(0x08)
        // nor a status), arriving while the subscription is still Creating --
        // before any INIT reply.  A correct client must reject this without
        // dereferencing the not-yet-allocated per-request free list.
        if(!sendFrame(cfd, CMD_MONITOR, 0u, [ioid](VectorOutBuf& M){
                          to_wire(M, ioid);
                          to_wire(M, uint8_t(0x00));
                      }))
            return BadHandshake;

        // A correct client treats this as a protocol violation and drops the
        // connection: our next read sees EOF.  (If the client crashed instead,
        // this whole process is gone and the test never reports.)
        uint8_t junk[64];
        int r = ::recv(cfd, reinterpret_cast<char*>(junk), sizeof(junk), 0);
        if(r == 0)
            return Survived;     // EOF: client dropped the connection
        if(r > 0)
            return Unexpected;   // client said something instead of disconnecting
        return NoReaction;       // recv timed out: connection still open, idle
    }
};

void testMonitorDataBeforeInit()
{
    testDiag("%s", __func__);

    // Rejecting the hostile frame is the correct outcome, and it logs CRIT on
    // pvxs.client.io -- the same path every peer protocol violation takes.  CI
    // runs with _PVXS_ABORT_ON_CRIT=1, which turns that expected CRIT into an
    // abort().  Drop this logger below Crit so the expected rejection does not
    // abort the test; the client still disconnects, which is what we check.
    logger_level_set("pvxs.client.io", int(Level::Crit) - 1);

    Mock mock;
    testDiag("mock peer listening on 127.0.0.1:%u", unsigned(mock.port));

    client::Config cconf;
    cconf.autoAddrList = false;     // no broadcast search; we force a direct server
    cconf.addressList.clear();
    auto cli(cconf.build());

    mock.start();

    std::string server("127.0.0.1:");
    server += std::to_string(mock.port);

    auto sub = cli.monitor("hostile")
            .server(server)
            .maskConnected(false)
            .maskDisconnected(false)
            .event([](client::Subscription&){})
            .exec();

    bool signaled = mock.done.wait(20.0);

    if(!signaled) {
        testFail("timed out waiting for mock peer (client may be hung)");
    } else {
        switch(mock.outcome.load()) {
        case Survived:
            testPass("client rejected pre-INIT MONITOR data frame and disconnected without crashing");
            break;
        case BadHandshake:
            testFail("mock handshake diverged before injection (test harness, not the client)");
            break;
        case Unexpected:
            testFail("client answered the bad frame instead of rejecting it");
            break;
        case NoReaction:
            testFail("client kept the connection open instead of rejecting the bad frame");
            break;
        default:
            testFail("mock peer reported no outcome");
        }
    }
    testDiag("observed MONITOR INIT subcmd 0x%02x", mock.initSubcmd.load());

    sub.reset();
}

} // namespace

int main(int argc, char* argv[])
{
    SockAttach attach;
    testPlan(1);
    testSetup();
    pvxs::logger_config_env();
    testMonitorDataBeforeInit();
    cleanup_for_valgrind();
    return testDone();
}
