/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef SERVERCONN_H
#define SERVERCONN_H

#include <list>
#include <map>
#include <memory>

#include <epicsEvent.h>

#include <pvxs/server.h>
#include "evhelper.h"
#include "utilpvt.h"
#include "dataimpl.h"
#include "udp_collector.h"

namespace pvxs {namespace impl {

struct ServIface;
struct ServerConn;
struct ServerChan;
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

    const std::weak_ptr<server::Server::Pvt> server;
    const std::weak_ptr<ServerChan> chan;
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

    std::function<void(std::unique_ptr<server::ConnectOp>&&)> onOp;
    std::function<void(std::unique_ptr<server::ExecOp>&&, Value&&)> onRPC;
    std::function<void(std::unique_ptr<server::MonitorSetupOp>&&)> onSubscribe;
    std::function<void(const std::string&)> onClose;

    std::map<uint32_t, std::shared_ptr<ServerOp> > opByIOID; // our subset of ServerConn::opByIOID

    ServerChan(const std::shared_ptr<ServerConn>& conn, uint32_t sid, uint32_t cid, const std::string& name);
    ServerChan(const ServerChan&) = delete;
    ServerChan& operator=(const ServerChan&) = delete;
    ~ServerChan();
};

struct ServerConn : public std::enable_shared_from_this<ServerConn>
{
    ServIface* const iface;

    SockAddr peerAddr;
    std::string peerName;
    evbufferevent bev;
    TypeStore rxRegistry;

    // credentials

    bool peerBE;
    bool expectSeg;

    uint8_t segCmd;
    evbuf segBuf, txBody;

    uint32_t nextSID;
    std::map<uint32_t, std::shared_ptr<ServerChan> > chanBySID;
    std::map<uint32_t, std::shared_ptr<ServerChan> > chanByCID;
    std::map<uint32_t, std::shared_ptr<ServerOp> > opByIOID;

    ServerConn(ServIface* iface, evutil_socket_t sock, struct sockaddr *peer, int socklen);
    ServerConn(const ServerConn&) = delete;
    ServerConn& operator=(const ServerConn&) = delete;
    ~ServerConn();

    const std::shared_ptr<ServerChan>& lookupSID(uint32_t sid);

    void enqueueTxBody(pva_app_msg_t cmd);

private:
#define CASE(Op) void handle_##Op();
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

    void cleanup();
    void bevEvent(short events);
    void bevRead();
    void bevWrite();
    static void bevEventS(struct bufferevent *bev, short events, void *ptr);
    static void bevReadS(struct bufferevent *bev, void *ptr);
    static void bevWriteS(struct bufferevent *bev, void *ptr);
};

struct ServIface
{
    server::Server::Pvt * const server;

    SockAddr bind_addr;
    std::string name;

    evsocket sock;
    evlisten listener;

    ServIface(const std::string& addr, unsigned short port, server::Server::Pvt *server);

    static void onConnS(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *peer, int socklen, void *raw);
};


//! Home of the magic "server" PV used by "pvinfo"
struct ServerSource : public server::Source
{
    const std::string name;
    server::Server::Pvt* const serv;

    const Value info;

    ServerSource(server::Server::Pvt* serv);

    virtual void onSearch(Search &op) override final;

    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&op) override final;
};

} // namespace impl

namespace server {
using namespace impl;

struct Server::Pvt
{
    std::weak_ptr<Server::Pvt> internal_self;

    // "const" after ctor
    Config effective;

    epicsEvent done;

    // handle server "background" tasks.
    // accept new connections and send beacons
    evbase acceptor_loop;

    std::vector<uint8_t> beaconMsg;

    std::list<std::unique_ptr<UDPListener> > listeners;
    std::vector<SockAddr> beaconDest;

    std::list<ServIface> interfaces;
    std::map<ServerConn*, std::shared_ptr<ServerConn> > connections;

    evsocket beaconSender;
    evevent beaconTimer;

    std::vector<uint8_t> searchReply;

    Source::Search searchOp;

    RWLock sourcesLock;
    std::map<std::pair<int, std::string>, std::shared_ptr<Source> > sources;

    enum state_t {
        Stopped,
        Starting,
        Running,
        Stopping,
    } state;

    Pvt(Config&& conf);
    ~Pvt();

    void start();
    void stop();

private:
    void onSearch(const UDPManager::Search& msg);
    void doBeacons(short evt);
    static void doBeaconsS(evutil_socket_t fd, short evt, void *raw);
};

}} // namespace pvxs::server

#endif // SERVERCONN_H
