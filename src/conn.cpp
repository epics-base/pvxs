/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <limits>

#include <epicsAssert.h>

#include <pvxs/log.h>
#include "conn.h"

#ifdef PVXS_ENABLE_OPENSSL
#include "openssl.h"
#endif

DEFINE_LOGGER(connsetup, "pvxs.tcp.setup");
DEFINE_LOGGER(connio, "pvxs.tcp.io");

namespace pvxs {
namespace impl {

// Amount of following messages which we allow to be read while
// processing the current message.  Avoids some extra recv() calls,
// at the price of maybe extra copying.
// Also bounds the loop in ConnBase::bevRead()
//
// Defined as a multiple of the OS RX socket buffer size.
static
constexpr size_t tcp_readahead_mult = 2u;

#ifdef PVXS_ENABLE_OPENSSL
ConnBase::ConnBase(bool isClient, bool isTLS, bool sendBE, evbufferevent&& bev, const SockAddr& peerAddr)
#else
ConnBase::ConnBase(bool isClient, bool sendBE, evbufferevent&& bev, const SockAddr& peerAddr)
#endif
    :peerAddr(peerAddr)
    ,peerName(peerAddr.tostring())
#ifdef PVXS_ENABLE_OPENSSL
    ,isTLS(isTLS)
#endif
    ,isClient(isTLS)
    ,sendBE(sendBE)
    ,peerBE(true) // arbitrary choice, default should be overwritten before use
    ,expectSeg(false)
    ,peerVersion(0)
    ,segCmd(0xff)
    ,segBuf(__FILE__, __LINE__, evbuffer_new())
    ,txBody(__FILE__, __LINE__, evbuffer_new())
    ,state(Holdoff)
{
    if(bev) { // true for server connection.  client will call connect() shortly
        connect(std::move(bev));
    }
}

ConnBase::~ConnBase() {}

const char* ConnBase::peerLabel() const
{
    return isClient ? "Server" : "Client";
}

void ConnBase::connect(ev_owned_ptr<bufferevent> &&bev)
{
    if(!bev)
        throw BAD_ALLOC();
    assert(!this->bev && state==Holdoff);

    readahead = evsocket::get_buffer_size(bufferevent_getfd(bev.get()), false);

#if LIBEVENT_VERSION_NUMBER >= 0x02010000
    // allow to drain OS socket buffer in a single read
    (void)bufferevent_set_max_single_read(bev.get(), readahead);
#endif

    readahead *= tcp_readahead_mult;

#if LIBEVENT_VERSION_NUMBER >= 0x02010000
    // allow attempt to write as much as is available
    (void)bufferevent_set_max_single_write(bev.get(), EV_SSIZE_MAX);
#endif

    state = isClient ? Connecting : Connected;

    this->bev = std::move(bev);

    // initially wait for at least a header
    bufferevent_setwatermark(this->bev.get(), EV_READ, 8, readahead);
}

void ConnBase::disconnect()
{
    bev.reset();
    state = Disconnected;
}

size_t ConnBase::enqueueTxBody(pva_app_msg_t cmd)
{
    auto blen = evbuffer_get_length(txBody.get());
    auto tx = bufferevent_get_output(bev.get());
    to_evbuf(tx, Header{cmd,
                        uint8_t(isClient ? 0u : pva_flags::Server),
                        uint32_t(blen)},
             sendBE);
    auto err = evbuffer_add_buffer(tx, txBody.get());
    assert(!err); // could only fail if frozen/pinned, which is not the case
    statTx += 8u + blen;
    return 8u + blen;
}

void ConnBase::handle_ECHO() {};
void ConnBase::handle_SEARCH() {};
void ConnBase::handle_SEARCH_RESPONSE() {};

void ConnBase::handle_CONNECTION_VALIDATION() {};
void ConnBase::handle_CONNECTION_VALIDATED() {};
void ConnBase::handle_AUTHNZ() {};

void ConnBase::handle_CREATE_CHANNEL() {};
void ConnBase::handle_DESTROY_CHANNEL() {};

void ConnBase::handle_GET() {};
void ConnBase::handle_PUT() {};
void ConnBase::handle_PUT_GET() {};
void ConnBase::handle_MONITOR() {};
void ConnBase::handle_RPC() {};
void ConnBase::handle_GET_FIELD() {};

void ConnBase::handle_CANCEL_REQUEST() {};
void ConnBase::handle_DESTROY_REQUEST() {};

void ConnBase::handle_MESSAGE() {};

#ifndef PVXS_ENABLE_OPENSSL
void ConnBase::bevEvent(short events)
#else
void ConnBase::bevEvent(short events, std::function<void(bool)> fn)
#endif
{

    if (bev && isTLS) {
        if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
            while (auto err = bufferevent_get_openssl_error(bev.get())) {
                auto error_reason = ERR_reason_error_string(err);
                if (error_reason) log_err_printf(connio, "%s: TLS Error (0x%lx) %s\n", peerLabel(), err, error_reason);
            }
        }

#ifndef PVXS_ENABLE_OPENSSL
        // If this is a connect then subscribe to peer status is required
        if (events & BEV_EVENT_CONNECTED) {
            auto ctx = bufferevent_openssl_get_ssl(bev.get());
            assert(ctx);
            try {
                if (!ossl::SSLContext::subscribeToPeerCertStatus(ctx, fn)) {
                    log_warn_printf(connio, "unable to subscribe to %s %s certificate status\n", peerLabel(), peerName.c_str());
                }
            } catch (certs::CertStatusNoExtensionException &e) {
                log_debug_printf(connio, "status monitoring not required for %s %s: %s\n", peerLabel(), peerName.c_str(), e.what());
            } catch (std::exception &e) {
                log_debug_printf(connio, "unexpected error subscribing to %s %s certificate status: %s\n", peerLabel(), peerName.c_str(), e.what());
            }
        }
#endif
    }

    // If any socket warnings / errors then log and disconnect
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        if (events & BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            const char *msg = evutil_socket_error_to_string(err);
            log_err_printf(connio, "connection to %s %s closed with socket error %d : %s\n", peerLabel(), peerName.c_str(), err, msg);
        }
        if (events & BEV_EVENT_EOF) {
            log_debug_printf(connio, "connection to %s %s closed by peer\n", peerLabel(), peerName.c_str());
        }
        if (events & BEV_EVENT_TIMEOUT) {
            log_warn_printf(connio, "connection to %s %s timeout\n", peerLabel(), peerName.c_str());
        }
        state = Disconnected;
        bev.reset();
    }

    if (!bev)
        cleanup();
}

void ConnBase::bevRead()
{
    auto rx = bufferevent_get_input(bev.get());
    auto remaining = evbuffer_get_length(rx);

    while(bev && remaining >= 8) {
        uint8_t header[8];

        auto ret = evbuffer_copyout(rx, header, sizeof(header));
        assert(ret==sizeof(header)); // previously verified

/*
        if(header[0]!=0xca || header[1]==0 || (isClient ^ !!(header[2]&pva_flags::Server))) {
            log_hex_printf(connio, Level::Err, header, sizeof(header),
                           "%s %s Protocol decode fault.  Force disconnect.\n", peerLabel(), peerName.c_str());
            bev.reset();
            break;
        }
*/
        log_hex_printf(connio, Level::Debug, header, sizeof(header),
                       "%s %s Receive header\n", peerLabel(), peerName.c_str());

        if(header[2]&pva_flags::Control) {
            if(header[3]==pva_ctrl_msg::SetEndian) {
                /* This should be the first message sent by a (supposedly) server.
                 * However, old pvAccess* accepts it from either peer at any time.
                 *
                 * The protocol spec. claims that we should inspect the size field
                 * (bytes 4-7) and act as follows.
                 * 0x00000000 - Send future messages using endianness on this (received)
                 *              message.  Peer will ignore MSB flag in our headers!
                 * 0xffffffff - Send future messages as we like.  Peer will test the
                 *              MSB flag.
                 *
                 * However, neither pvAccessCPP nor pvAccessJava actually test this.
                 * Instead the 0x00000000 behavior is assumed.
                 *
                 * So we latch the byte order here, as the peer should ignore the MSB
                 * flag subsequent messages...
                 */
                sendBE = header[2]&pva_flags::MSB;
            }
            // Control messages are not actually useful
            evbuffer_drain(rx, 8);
            statRx += 8u;
            remaining -= 8u;
            continue;
        }
        // application message

        peerBE = header[2]&pva_flags::MSB;
        peerVersion = header[1];

        // a bit verbose :P
        FixedBuf L(peerBE, header+4, 4);
        uint32_t len = 0;
        from_wire(L, len);
        assert(L.good());

        if(remaining-8 < len) {
            // wait for complete payload
            // and some additional if available
            size_t newmax = 8 + len;
            if(newmax < std::numeric_limits<size_t>::max()-readahead)
                newmax += readahead;
            bufferevent_setwatermark(bev.get(), EV_READ, 8 + len, newmax);
            return;
        }

        evbuffer_drain(rx, 8);
        {
            unsigned n = evbuffer_remove_buffer(rx, segBuf.get(), len);
            assert(n==len); // we know rx buf contains the entire body
        }
        remaining -= 8u + len;
        statRx += 8u + len;

        // so far we do not use segmentation to support incremental processing
        // of long messages.  We instead accumulate all segments of a message
        // prior to parsing.

        auto seg = header[2]&pva_flags::SegMask;

        bool continuation = seg&pva_flags::SegLast; // true for mid or last.  false for none or first
        if((continuation ^ expectSeg) || (continuation && header[3]!=segCmd)) {
            log_crit_printf(connio, "%s %s Peer segmentation violation %c%c 0x%02x==0x%02x\n", peerLabel(), peerName.c_str(),
                       expectSeg?'Y':'N', continuation?'Y':'N',
                       segCmd, header[3]);
            bev.reset();
            break;
        }

        if(!seg || seg==pva_flags::SegFirst) {
            expectSeg = true;
            segCmd = header[3];
        }

        if(!seg || seg==pva_flags::SegLast) {
            expectSeg = false;

            // ready to process segBuf
            try {
                switch(segCmd) {
                    case CMD_ECHO: handle_ECHO(); break;

                    case CMD_SEARCH: handle_SEARCH(); break;
                    case CMD_SEARCH_RESPONSE: handle_SEARCH_RESPONSE(); break;

                    case CMD_CONNECTION_VALIDATION: handle_CONNECTION_VALIDATION(); break;
                    case CMD_CONNECTION_VALIDATED: handle_CONNECTION_VALIDATED(); break;
                    case CMD_AUTHNZ: handle_AUTHNZ(); break;

                    case CMD_CREATE_CHANNEL: handle_CREATE_CHANNEL(); break;
                    case CMD_DESTROY_CHANNEL: handle_DESTROY_CHANNEL(); break;

                    case CMD_GET: handle_GET(); break;
                    case CMD_PUT: handle_PUT(); break;
                    case CMD_PUT_GET: handle_PUT_GET(); break;
                    case CMD_MONITOR: handle_MONITOR(); break;
                    case CMD_RPC: handle_RPC(); break;
                    case CMD_GET_FIELD: handle_GET_FIELD(); break;

                    case CMD_CANCEL_REQUEST: handle_CANCEL_REQUEST(); break;
                    case CMD_DESTROY_REQUEST: handle_DESTROY_REQUEST(); break;

                    case CMD_MESSAGE: handle_MESSAGE(); break;

                    default:
                        log_debug_printf(connio, "%s %s Ignore unexpected command 0x%02x\n", peerLabel(), peerName.c_str(), segCmd);
                        evbuffer_drain(segBuf.get(), evbuffer_get_length(segBuf.get()));
                        break;
                }
            }catch(std::exception& e){
                log_exc_printf(connio, "%s Error while processing cmd 0x%02x%s: %s\n",
                               peerLabel(), segCmd, rxRegistryDirty ? " cache may be dirty" : "" ,
                               e.what());
                bev.reset();
            }
            // handlers may have cleared bev to force disconnect
            if(!bev)
                break;

            // silently drain any unprocessed body (forward compatibility)
            if(auto n = evbuffer_get_length(segBuf.get()))
                evbuffer_drain(segBuf.get(), n);

        }
    }

    if(bev) {
        // incomplete body took earlier return
        assert(evbuffer_get_length(rx)<8);
        // wait for next header
        bufferevent_setwatermark(bev.get(), EV_READ, 8, readahead);

    } else {
        cleanup();
    }
}

void ConnBase::bevWrite() {}

void ConnBase::bevEventS(struct bufferevent *bev, short events, void *ptr)
{
    auto conn = static_cast<ConnBase*>(ptr)->self_from_this();
    try {
        conn->bevEvent(events);
    }catch(std::exception& e){
        log_exc_printf(connsetup, "%s %s Unhandled error in bev event callback: %s\n", conn->peerLabel(), conn->peerName.c_str(), e.what());
        conn->cleanup();
    }
}

void ConnBase::bevReadS(struct bufferevent *bev, void *ptr)
{
    auto conn = static_cast<ConnBase*>(ptr)->self_from_this();
    try {
        conn->bevRead();
    }catch(std::exception& e){
        log_exc_printf(connsetup, "%s %s Unhandled error in bev read callback: %s\n", conn->peerLabel(), conn->peerName.c_str(), e.what());
        conn->cleanup();
    }
}

void ConnBase::bevWriteS(struct bufferevent *bev, void *ptr)
{
    auto conn = static_cast<ConnBase*>(ptr)->self_from_this();
    try {
        conn->bevWrite();
    }catch(std::exception& e){
        log_exc_printf(connsetup, "%s %s Unhandled error in bev write callback: %s\n", conn->peerLabel(), conn->peerName.c_str(), e.what());
        conn->cleanup();
    }
}

} // namespace impl
} // namespace pvxs
