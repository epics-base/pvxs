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

#ifdef PVXS_ENABLE_OPENSSL
#include "certstatus.h"
#include "openssl.h"
#endif

namespace pvxs {
namespace ossl{
    struct CertStatusExData;
    struct SSLPeerStatusAndMonitor;
}
namespace impl {
struct ConnBase
{
    const SockAddr peerAddr;
    const std::string peerName;
protected:
    evbufferevent bev;
#ifdef PVXS_ENABLE_OPENSSL
    // This is the strong reference to the peer status and its monitor.
    //
    // CLEANUP:
    //  - If multiple connections subscribe to the same peer then they will all keep a
    //      shared strong reference, but when the last is cleaned-up, it will finally
    //      call the destructor of the `pvxs::ossl::SSLPeerStatusAndMonitor` instance itself.
    //  - Each `pvxs::ossl::SSLPeerStatusAndMonitor` instance holds the tls context's key into the
    //      master map of `pvxs::ossl::SSLPeerStatusAndMonitor`s stored inside the ex_data
    //      (`pvxs::ossl::CertStatusExData`) attached to the `SSL_CTX` (tls context) of the
    //      client or server.  Attached with `SSL_CTX_set_ex_data()`, and
    //      `SSL_CTX_get_ex_data()`.
    //  - This structure's (`pvxs::ossl::CertStatusExData`) destructor is
    //      automatically called when `SSL_CTX_free()` is called, so this means that we
    //      need to make sure that all connections are removed BEFORE we close the
    //      tls_context (pvxs::ossl::SSLContext) of the client or server.
    //  - So we make sure that the tls context will last longer that any connections that
    //      are attached to the tls context. So we simply need to make sure that
    //      the destructor of a client or server tls context will close connections first then
    //      destroy the context.  It should be already doing this.
    //
    // RECAP:
    //  - `pvxs::ossl::SSLPeerStatusAndMonitor`
    //      Structure holds peer status and a status monitor and also the status pv of cert to monitor
    //  - `pvxs::ossl::ConnBase::peer_status_and_monitor`
    //      Shared ptr strong reference to the peer status and its monitor in each connection
    //  - `pvxs::ossl::CertStatusExData::peer_statuses`
    //      Map of status PV string to peer status and its monitor.
    //  - `pvxs::ossl::CertStatusExData`
    //      Attached to a client or server's tls context with `SSL_CTX_set_ex_data()`,
    //      and `SSL_CTX_get_ex_data()`.  Peer certs can be shared between connections',
    //      and a client or server tls context can have 0 or more distinct peers.
    //  - `pvxs::client::ContextImpl::~ContextImpl()` either
    //      - manually close connections (pvxs::client::ContextImpl::connByAddr) before
    //        freeing `pvxs::client::ContextImpl::tls_context`, or
    //      - order member `pvxs::client::ContextImpl::connByAddr` after
    //        `pvxs::client::ContextImpl::tls_context`
    //  - `pvxs::server::Server::Pvt::~Pvt()` either
    //      - manually close listeners (pvxs::client::ContextImpl::listeners) and
    //        connections (pvxs::server::Server::Pvt::connections) before
    //        freeing `pvxs::server::Server::Pvt::tls_context`, or
    //      - order member `pvxs::server::Server::Pvt::listeners` and
    //        `pvxs::server::Server::Pvt::connections` after
    //        `pvxs::server::Server::Pvt::tls_context`
    //
    // @code
    // namespace pvxs {
    // namespace ossl {
    //    struct CertStatusExData {
    //       ...
    //       std::map<std::string, std::shared_ptr<SSLPeerStatusAndMonitor>> peer_statuses{};
    //    }
    //    struct SSLPeerStatusAndMonitor{
    //       const std::string status_pv;
    //       const std::string status_pv;
    //    }
    // } // ossl
    // namespace client {
    //    struct ContextImpl {
    //       ...
    //       std::map<serial_number_t, std::shared_ptr<SSLPeerStatusAndMonitor>> peer_statuses{};
    //    }
    // } // client
    // namespace server {
    //    struct Server {
    //        struct Pvt {
    //           ...
    //           std::map<serial_number_t, std::shared_ptr<SSLPeerStatusAndMonitor>> peer_statuses{};
    //        }
    //    }
    // } // client
    // } // pvxs
    //
    // @endcode
    //
    // `SSLPeerStatusAndMonitor()` will remove itself from this table using the internally stored key.
    std::shared_ptr<ossl::SSLPeerStatusAndMonitor> peer_status;
    bool isPeerStatusGood() const ;

#endif
public:
    const bool isTLS;

    TypeStore rxRegistry;
    /* Flag if some received delta could not be decoded due to
     * a non-existent IOID, which *may* leave this rxRegistry out
     * of sync with the peer (if it contains Variant Unions).
     * We can't know whether this is the case.
     * Failing soft here may lead to failures decoding future replies.
     * We could force close the Connection here to be "safe".
     * However, we assume the such usage of Variant is relatively rare
     */
    bool rxRegistryDirty = false;

    const bool isClient;
    bool sendBE;
    bool peerBE;
    bool expectSeg;
    uint8_t peerVersion;

    uint8_t segCmd;
    evbuf segBuf, txBody;

    size_t statTx{}, statRx{};
    size_t readahead{};

    enum {
        Holdoff,
        Connecting,
        Connected,
        Validated,
        Disconnected,
    } state;

    ConnBase(bool isClient, bool isTLS, bool sendBE, evbufferevent &&bev, const SockAddr& peerAddr);
    ConnBase(const ConnBase&) = delete;
    ConnBase& operator=(const ConnBase&) = delete;
    virtual ~ConnBase();

    const char* peerLabel() const;

    size_t enqueueTxBody(pva_app_msg_t cmd);

    bufferevent* connection() { return bev.get(); }

    void connect(ev_owned_ptr<bufferevent> &&bev);
    void disconnect();

protected:
    virtual void handle_ECHO();
    virtual void handle_SEARCH();
    virtual void handle_SEARCH_RESPONSE();

    virtual void handle_CONNECTION_VALIDATION();
    virtual void handle_CONNECTION_VALIDATED();
    virtual void handle_AUTHNZ();

    virtual void handle_CREATE_CHANNEL();
    virtual void handle_DESTROY_CHANNEL();

    virtual void handle_GET();
    virtual void handle_PUT();
    virtual void handle_PUT_GET();
    virtual void handle_MONITOR();
    virtual void handle_RPC();
    virtual void handle_GET_FIELD();

    virtual void handle_CANCEL_REQUEST();
    virtual void handle_DESTROY_REQUEST();

    virtual void handle_MESSAGE();

    virtual std::shared_ptr<ConnBase> self_from_this() =0;
    virtual void cleanup() =0;

    virtual void bevEvent(short events);
#ifdef PVXS_ENABLE_OPENSSL
    virtual void peerStatusCallback(certs::cert_status_category_t status_category) = 0;
#endif
    virtual void bevRead();
    virtual void bevWrite();
    static void bevEventS(struct bufferevent *bev, short events, void *ptr);
    static void bevReadS(struct bufferevent *bev, void *ptr);
    static void bevWriteS(struct bufferevent *bev, void *ptr);
};

} // namespace impl
} // namespace pvxs

#endif // CONN_H
