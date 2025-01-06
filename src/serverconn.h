/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef SERVERCONN_H
#define SERVERCONN_H

#include <atomic>
#include <list>
#include <map>
#include <memory>

#include <epicsEvent.h>

#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>

#include "certstatus.h"
#include "certstatusmanager.h"
#include "conn.h"
#include "dataimpl.h"
#include "evhelper.h"
#include "udp_collector.h"
#include "utilpvt.h"

namespace pvxs {namespace impl {

struct ServIface;
struct ServerConn;
struct ServerChan;

// base for tracking in-progress operations.  cf. ServerConn::opByIOID and ServerChan::opByIOID
struct ServerOp
{
    const std::weak_ptr<ServerChan> chan;

    const uint32_t ioid;

    std::function<void(const std::string&)> onClose;
    std::function<void()> onCancel;

    enum state_t {
        Creating,
        Idle,
        Executing,
        Dead,
    } state;

    ServerOp(const std::weak_ptr<ServerChan>& chan, uint32_t ioid) :chan(chan), ioid(ioid), state(Idle) {}
    ServerOp(const ServerOp&) = delete;
    ServerOp& operator=(const ServerOp&) = delete;
    virtual ~ServerOp() =0;

    // called from tcp worker.
    // do any cleanup which must be done from that worker.
    virtual void cleanup();
    virtual void show(std::ostream& strm) const =0;
};

struct ServerChannelControl : public server::ChannelControl
{
    ServerChannelControl(const std::shared_ptr<ServerConn>& conn, const std::shared_ptr<ServerChan>& chan);
    virtual ~ServerChannelControl();

    virtual void onOp(std::function<void(std::unique_ptr<server::ConnectOp>&&)>&& fn) override final;
    virtual void onRPC(std::function<void(std::unique_ptr<server::ExecOp>&&, Value&&)>&& fn) override final;
    virtual void onSubscribe(std::function<void(std::unique_ptr<server::MonitorSetupOp>&&)>&& fn) override final;

    virtual void onClose(std::function<void(const std::string&)>&& fn) override final;
    virtual void close() override final;

    virtual void _updateInfo(const std::shared_ptr<const ReportInfo>& info) override final;

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerChan> chan;

    INST_COUNTER(ServerChannelControl);
};

struct ServerChan
{
    const std::weak_ptr<ServerConn> conn;

    const uint32_t sid, cid;
    const std::string name;

    enum {
        Creating, // CREATE_CHANNEL request received, reply not sent
        Active,   // reply sent
        Destroy,  // DESTROY_CHANNEL request received and/or reply sent
    } state;

    size_t statTx{}, statRx{};
    std::shared_ptr<const ReportInfo> reportInfo;

    std::function<void(std::unique_ptr<server::ConnectOp>&&)> onOp;
    std::function<void(std::unique_ptr<server::ExecOp>&&, Value&&)> onRPC;
    std::function<void(std::unique_ptr<server::MonitorSetupOp>&&)> onSubscribe;
    std::function<void(const std::string&)> onClose;

    std::map<uint32_t, std::shared_ptr<ServerOp> > opByIOID; // our subset of ServerConn::opByIOID

    INST_COUNTER(ServerChan);

    ServerChan(const std::shared_ptr<ServerConn>& conn, uint32_t sid, uint32_t cid, const std::string& name);
    ServerChan(const ServerChan&) = delete;
    ServerChan& operator=(const ServerChan&) = delete;
    ~ServerChan();

    void cleanup();
};

struct ServerConn final : public ConnBase, public std::enable_shared_from_this<ServerConn>
{
    ServIface* const iface;
    const size_t tcp_tx_limit;

    std::shared_ptr<const server::ClientCredentials> cred;

    uint32_t nextSID=0x07050301;
    std::map<uint32_t, std::shared_ptr<ServerChan> > chanBySID;
    std::map<uint32_t, std::shared_ptr<ServerOp> > opByIOID;

    std::list<std::function<void()>> backlog;

    INST_COUNTER(ServerConn);

    ServerConn(ServIface* iface, evutil_socket_t sock, struct sockaddr *peer, int socklen);
    ServerConn(const ServerConn&) = delete;
    ServerConn& operator=(const ServerConn&) = delete;
    ~ServerConn();

    const std::shared_ptr<ServerChan>& lookupSID(uint32_t sid);

private:
#define CASE(Op) virtual void handle_##Op() override final;
    CASE(ECHO);
    CASE(CONNECTION_VALIDATION);
    CASE(SEARCH);
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

    void handle_GPR(pva_app_msg_t cmd);

    virtual std::shared_ptr<ConnBase> self_from_this() override final;
public:
    virtual void cleanup() override final;
private:
    virtual void bevEvent(short events) override final;
    virtual void bevRead() override final;
    virtual void bevWrite() override final;
};

struct ServIface
{
    server::Server::Pvt * const server;
#ifdef PVXS_ENABLE_OPENSSL
    const bool isTLS;
#endif

    SockAddr bind_addr;
    std::string name;

    evsocket sock;
    evlisten listener;

    ServIface(const SockAddr &addr, server::Server::Pvt *server, bool fallback, bool isTLS);

    static void onConnS(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *peer, int socklen, void *raw);
};


//! Home of the magic "server" PV used by "pvinfo"
struct ServerSource : public server::Source
{
    const std::string name;
    server::Server::Pvt* const serv;

    const Value info;

    INST_COUNTER(ServerSource);

    ServerSource(server::Server::Pvt* serv);

    virtual void onSearch(Search &op) override final;

    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&op) override final;
};

} // namespace impl

namespace server {
using namespace impl;

struct Server::Pvt
{
    SockAttach attach;

    std::weak_ptr<Server::Pvt> internal_self;
    Server &server;

    // "const" after ctor
    Config effective;

    epicsEvent done;

    std::vector<uint8_t> beaconMsg;
    uint8_t beaconSeq = 0u;
    uint8_t beaconCnt = 0u;
    std::atomic<uint16_t> beaconChange{0u};

    // handle server "background" tasks.
    // accept new connections and send beacons
    evbase acceptor_loop;

    std::list<std::unique_ptr<UDPListener> > listeners;
    std::vector<SockEndpoint> beaconDest;
    std::vector<SockAddr> ignoreList;

    std::list<ServIface> interfaces;
    std::map<ServerConn*, std::shared_ptr<ServerConn> > connections;

    evsocket beaconSender4, beaconSender6;
    evevent beaconTimer;

    std::vector<uint8_t> searchReply;

    // properly a local of Pvt::onSearch() on the UDP worker.
    // made a member to avoid re-alloc of _names vector.
    Source::Search searchOp;

    StaticSource builtinsrc;

    RWLock sourcesLock;
    std::map<std::pair<int, std::string>, std::shared_ptr<Source> > sources;

    enum state_t {
        Stopped,
        Starting,
        Running,
        Stopping,
    } state;

#ifdef PVXS_ENABLE_OPENSSL
    std::shared_ptr<ossl::SSLContext> tls_context;
    CertEventCallback custom_cert_event_callback;
    evevent cert_event_timer;
    bool first_cert_event{true};
    certs::TlsConfFileWatcher file_watcher;
    void* cached_ocsp_response{nullptr};
    time_t cached_ocsp_status_date;
#endif

    INST_COUNTER(ServerPvt);

#ifndef PVXS_ENABLE_OPENSSL
    Pvt(const Config& conf);
#else
    Pvt(Server &server, const Config& conf, CertEventCallback custom_cert_event_callback = nullptr);
#endif
    ~Pvt();

    void start();
    void stop();

    inline bool canRespondToTcpSearch() { return !tls_context || tls_context->state >= ossl::SSLContext::DegradedMode; }
    inline bool canRespondToTlsSearch() { return tls_context && tls_context->state >= ossl::SSLContext::TcpReady && effective.tls_port; }
    inline bool isInDegradedMode() { return !tls_context || tls_context->state <= ossl::SSLContext::DegradedMode; }

   private:
    void onSearch(const UDPManager::Search& msg);
    void doBeacons(short evt);
    static void doBeaconsS(evutil_socket_t fd, short evt, void *raw);

#ifdef PVXS_ENABLE_OPENSSL
    static void doCertEventHandler(evutil_socket_t fd, short evt, void* raw);
    void fileEventCallback(short evt);

    /**
     * @brief Can the TLS listener respond with `tcp` to `tcp`-only SEARCH requests
     *
     * This is true if TLS is correctly configured, the cert is valid,
     * the CA chain is valid, and the key usage and other parameters check out.
     *
     * If the SEARCH request contains `tcp` only then a SEARCH RESPONSE will be given.
     * If the SEARCH request contains both `tls` and `tcp` then no response will be given
     * because CMS will not yet have validated the certificate.
     *
     * @note this will return false if the tls context is in a degraded state, responding to all SEARCH requests with `tcp`
     *
     * @return True if the TLS listener can respond with `tcp` to `tcp`-only SEARCH requests
     */
    inline bool isInitialisedForTls(std::shared_ptr<ossl::SSLContext> new_context = nullptr) {
        auto& context_to_use = (new_context == nullptr ? tls_context : new_context);
        return context_to_use && context_to_use->state >= ossl::SSLContext::TcpReady;
    }

    /**
     * @brief Can the TLS listener respond with `tls` to SEARCH requests containing `tls`
     *
     * This is true if TLS is correctly configured, the cert is valid,
     * the CA chain is valid, the key usage and other parameters check out, and either
     * a) status monitoring is disabled, or
     * b) the CMS has already responded with a certificate status of GOOD
     *
     * If the SEARCH request contains `tcp` only then a `tcp` SEARCH RESPONSE will be given.
     * If the SEARCH request contains `tls` then a `tls` SEARCH RESPONSE will be given.
     *
     * @return True if the TLS listener can respond with `tls` to SEARCH requests containing `tls`
     */
    inline bool isContextReadyForTls(std::shared_ptr<ossl::SSLContext> new_context = nullptr) {
        auto& context_to_use = (new_context == nullptr ? tls_context : new_context);
        return context_to_use && context_to_use->state == ossl::SSLContext::TlsReady;
    }

   public:
    void enterDegradedMode();
    void removePeerTlsConnections(const ServerConn* server_conn = nullptr);
    void reloadTlsFromConfig();
    void enableTlsForPeerConnection(const ServerConn* server_conn = nullptr);
#endif
};

}} // namespace pvxs::server

#endif // SERVERCONN_H
