/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <limits>

#include <epicsAssert.h>

#include <pvxs/log.h>
#include "conn.h"

DEFINE_LOGGER(connsetup, "pvxs.tcp.setup");
DEFINE_LOGGER(connio, "pvxs.tcp.io");

namespace pvxs {
namespace impl {

ConnBase::ConnBase(bool isClient, bufferevent* bev, const SockAddr& peerAddr)
    :peerAddr(peerAddr)
    ,peerName(peerAddr.tostring())
    ,bev(bev)
    ,isClient(isClient)
    ,peerBE(true) // arbitrary choice, default should be overwritten before use
    ,expectSeg(false)
    ,segCmd(0xff)
    ,segBuf(evbuffer_new())
    ,txBody(evbuffer_new())
{
    // initially wait for at least a header
    bufferevent_setwatermark(this->bev.get(), EV_READ, 8, tcp_readahead);
}

ConnBase::~ConnBase() {}

const char* ConnBase::peerLabel() const
{
    return isClient ? "Server" : "Client";
}

size_t ConnBase::enqueueTxBody(pva_app_msg_t cmd)
{
    auto blen = evbuffer_get_length(txBody.get());
    auto tx = bufferevent_get_output(bev.get());
    to_evbuf(tx, Header{cmd,
                        uint8_t(isClient ? 0u : pva_flags::Server),
                        uint32_t(blen)},
             hostBE);
    auto err = evbuffer_add_buffer(tx, txBody.get());
    assert(!err);
    statTx += 8u + blen;
    return 8u + blen;
}

#define CASE(Op) void ConnBase::handle_##Op() {}
    CASE(ECHO);
    CASE(CONNECTION_VALIDATION);
    CASE(CONNECTION_VALIDATED);
    CASE(SEARCH);
    CASE(SEARCH_RESPONSE);
    CASE(AUTHNZ);

    CASE(CREATE_CHANNEL);
    CASE(DESTROY_CHANNEL);

    CASE(GET);
    CASE(PUT);
    CASE(PUT_GET);
    CASE(MONITOR);
    CASE(RPC);
    CASE(CANCEL_REQUEST);
    CASE(DESTROY_REQUEST);
    CASE(GET_FIELD);

    CASE(MESSAGE);
#undef CASE

void ConnBase::bevEvent(short events)
{
    if(events&(BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
        if(events&BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            const char *msg = evutil_socket_error_to_string(err);
            log_err_printf(connio, "%s %s connection closed with socket error %d : %s\n", peerLabel(), peerName.c_str(), err, msg);
        }
        if(events&BEV_EVENT_EOF) {
            log_debug_printf(connio, "%s %s connection closed by peer\n", peerLabel(), peerName.c_str());
        }
        if(events&BEV_EVENT_TIMEOUT) {
            log_warn_printf(connio, "%s %s connection timeout\n", peerLabel(), peerName.c_str());
        }
        bev.reset();
    }

    if(!bev)
        cleanup();
}

void ConnBase::bevRead()
{
    // temporarily disable to bound the processing loop and ensure fairness with other connections
    bufferevent_disable(bev.get(), EV_READ);

    auto rx = bufferevent_get_input(bev.get());

    while(bev && evbuffer_get_length(rx)>=8) {
        uint8_t header[8];

        auto ret = evbuffer_copyout(rx, header, sizeof(header));
        assert(ret==sizeof(header)); // previously verified

        if(header[0]!=0xca || header[1]==0
                || (isClient ^ !!(header[2]&pva_flags::Server))) {
            log_hex_printf(connio, Level::Err, header, sizeof(header),
                           "%s %s Protocol decode fault.  Force disconnect.\n", peerLabel(), peerName.c_str());
            bev.reset();
            break;
        }
        log_hex_printf(connio, Level::Debug, header, sizeof(header),
                       "%s %s Receive header\n", peerLabel(), peerName.c_str());

        if(header[2]&pva_flags::Control) {
            // Control messages are not actually useful
            evbuffer_drain(rx, 8);
            statRx += 8u;
            continue;
        }
        // application message

        peerBE = header[2]&pva_flags::MSB;

        // a bit verbose :P
        FixedBuf L(peerBE, header+4, 4);
        uint32_t len = 0;
        from_wire(L, len);
        assert(L.good());

        if(evbuffer_get_length(rx)-8 < len) {
            // wait for complete payload
            // and some additional if available
            size_t readahead = len;
            if(readahead < std::numeric_limits<size_t>::max()-tcp_readahead)
                readahead += tcp_readahead;
            bufferevent_setwatermark(bev.get(), EV_READ, len, readahead);
            bufferevent_enable(bev.get(), EV_READ);
            return;
        }

        evbuffer_drain(rx, 8);
        {
            unsigned n = evbuffer_remove_buffer(rx, segBuf.get(), len);
            assert(n==len); // we know rx buf contains the entire body
        }
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
                default:
                    log_debug_printf(connio, "%s %s Ignore unexpected command 0x%02x\n", peerLabel(), peerName.c_str(), segCmd);
                    evbuffer_drain(segBuf.get(), evbuffer_get_length(segBuf.get()));
                    break;
    #define CASE(OP) case CMD_##OP: handle_##OP(); break
                    CASE(ECHO);
                    CASE(CONNECTION_VALIDATION);
                    CASE(CONNECTION_VALIDATED);
                    CASE(SEARCH);
                    CASE(SEARCH_RESPONSE);
                    CASE(AUTHNZ);

                    CASE(CREATE_CHANNEL);
                    CASE(DESTROY_CHANNEL);

                    CASE(GET);
                    CASE(PUT);
                    CASE(PUT_GET);
                    CASE(MONITOR);
                    CASE(RPC);
                    CASE(CANCEL_REQUEST);
                    CASE(DESTROY_REQUEST);
                    CASE(GET_FIELD);

                    CASE(MESSAGE);
    #undef CASE
                }
            }catch(std::exception& e){
                log_exc_printf(connio, "%s Error while processing cmd 0x%02x: %s\n", peerLabel(), segCmd, e.what());
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
        bufferevent_setwatermark(bev.get(), EV_READ, 8, tcp_readahead);
        bufferevent_enable(bev.get(), EV_READ);

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
