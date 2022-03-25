/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef CONN_H
#define CONN_H

#include "evhelper.h"
#include "dataimpl.h"
#include "utilpvt.h"

namespace pvxs {
namespace impl {

// Amount of following messages which we allow to be read while
// processing the current message.  Avoids some extra recv() calls,
// at the price of maybe extra copying.
// Also bounds the loop in ConnBase::bevRead()
constexpr size_t tcp_readahead = 0x1000u;

struct ConnBase
{
    SockAddr peerAddr;
    std::string peerName;
    evbufferevent bev;
    TypeStore rxRegistry;

    const bool isClient;
    bool peerBE;
    bool expectSeg;

    uint8_t segCmd;
    evbuf segBuf, txBody;

    size_t statTx{}, statRx{};

    ConnBase(bool isClient, bufferevent* bev, const SockAddr& peerAddr);
    ConnBase(const ConnBase&) = delete;
    ConnBase& operator=(const ConnBase&) = delete;
    virtual ~ConnBase();

    const char* peerLabel() const;

    size_t enqueueTxBody(pva_app_msg_t cmd);

protected:
#define CASE(Op) virtual void handle_##Op();
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

    virtual std::shared_ptr<ConnBase> self_from_this() =0;
    virtual void cleanup() =0;
    virtual void bevEvent(short events);
    virtual void bevRead();
    virtual void bevWrite();
    static void bevEventS(struct bufferevent *bev, short events, void *ptr);
    static void bevReadS(struct bufferevent *bev, void *ptr);
    static void bevWriteS(struct bufferevent *bev, void *ptr);
};

} // namespace impl
} // namespace pvxs

#endif // CONN_H
