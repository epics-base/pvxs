/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef CLIENTIMPL_H
#define CLIENTIMPL_H

#include <list>

#include <epicsTime.h>
#include <epicsEvent.h>
#include <epicsMutex.h>

#include <pvxs/client.h>

#include "evhelper.h"
#include "dataimpl.h"
#include "utilpvt.h"
#include "udp_collector.h"
#include "conn.h"

namespace pvxs {
namespace client {

struct Channel;
struct ContextImpl;

struct ResultWaiter {
    epicsMutex lock;
    epicsEvent notify;
    Result result;
    enum {
        Busy,
        Done,
        Abort,
    } outcome = Busy;

    Value wait(double timeout=-1.0);
    void complete(Result&& result, bool interrupt);
};

// internal actions on an Operation
struct OperationBase : public Operation
{
    const evbase loop;
    // remaining members only accessibly from loop worker
    std::shared_ptr<Channel> chan;
    uint32_t ioid = 0;
    Value result;
    bool done = false;
    std::shared_ptr<ResultWaiter> waiter;

    OperationBase(operation_t op, const evbase& loop);
    virtual ~OperationBase();

    virtual void createOp() =0;
    virtual void disconnected(const std::shared_ptr<OperationBase>& self) =0;

    virtual const std::string& name() override final;
    virtual Value wait(double timeout=-1.0) override final;
    virtual void interrupt() override final;
};

struct RequestInfo {
    const uint32_t sid, ioid;
    const Operation::operation_t op;
    const std::weak_ptr<OperationBase> handle;

    Value prototype;

    RequestInfo(uint32_t sid, uint32_t ioid, std::shared_ptr<OperationBase>& handle);
};

struct Connection : public ConnBase, public std::enable_shared_from_this<Connection> {
    const std::shared_ptr<ContextImpl> context;

    const evevent echoTimer;

    bool ready = false;
    bool nameserver = false;

    // channels to be created on this Connection in state==Connecting
    std::map<uint32_t, std::weak_ptr<Channel>> pending;

    std::map<uint32_t, std::weak_ptr<Channel>> creatingByCID, // in state==Creating
                                               chanBySID;     // in state==Active

    // entries always have matching entry in a Channel::opByIOID
    std::map<uint32_t, RequestInfo> opByIOID;

    uint32_t nextIOID = 0x10002000u;

    INST_COUNTER(Connection);

    Connection(const std::shared_ptr<ContextImpl>& context, const SockAddr &peerAddr);
    virtual ~Connection();

    static
    std::shared_ptr<Connection> build(const std::shared_ptr<ContextImpl>& context,
                                      const SockAddr& serv);

    void createChannels();

    void sendDestroyRequest(uint32_t sid, uint32_t ioid);

    virtual void bevEvent(short events) override final;

    virtual std::shared_ptr<ConnBase> self_from_this() override final;
    virtual void cleanup() override final;

#define CASE(Op) virtual void handle_##Op() override final;
    CASE(CONNECTION_VALIDATION);
    CASE(CONNECTION_VALIDATED);

    CASE(SEARCH_RESPONSE);
    CASE(CREATE_CHANNEL);
    CASE(DESTROY_CHANNEL);

    CASE(GET);
    CASE(PUT);
    //CASE(PUT_GET);
    CASE(MONITOR);
    CASE(RPC);
    CASE(GET_FIELD);
#undef CASE

    void handle_GPR(pva_app_msg_t cmd);
protected:
    void tickEcho();
    static void tickEchoS(evutil_socket_t fd, short evt, void *raw);
};

struct ConnectImpl : public Connect
{
    const evbase loop;
    std::shared_ptr<Channel> chan;
    const std::string _name;
    std::atomic<bool> _connected;
    std::function<void()> _onConn;
    std::function<void()> _onDis;

    ConnectImpl(const evbase& loop, const std::string& name)
        :loop(loop)
        ,_name(name)
        ,_connected{false}
    {}
    virtual ~ConnectImpl();

    virtual const std::string &name() const override final;
    virtual bool connected() const override final;
};

struct Channel {
    const std::shared_ptr<ContextImpl> context;
    const std::string name;
    // Our chosen ID for this channel.
    // used as persistent CID and searchID
    const uint32_t cid;

    enum state_t {
        Searching,  // waiting for a server to claim
        Connecting, // waiting for Connection to become ready
        Creating,   // waiting for reply to CREATE_CHANNEL
        Active,
    } state = Searching;

    bool garbage = false;

    std::shared_ptr<Connection> conn;
    uint32_t sid = 0u;

    // channel created with .server() to bypass normal search process
    SockAddr forcedServer;

    // when state==Searching, number of repetitions
    size_t nSearch = 0u;

    // GUID of last positive reply when state!=Searching
    ServerGUID guid;
    SockAddr replyAddr;

    std::list<std::weak_ptr<OperationBase>> pending;

    // points to storage of Connection::opByIOID
    std::map<uint32_t, RequestInfo*> opByIOID;

    std::list<ConnectImpl*> connectors;

    size_t statTx{}, statRx{};

    INST_COUNTER(Channel);

    Channel(const std::shared_ptr<ContextImpl>& context, const std::string& name, uint32_t cid);
    ~Channel();

    void createOperations();
    void disconnect(const std::shared_ptr<Channel>& self);

    static
    std::shared_ptr<Channel> build(const std::shared_ptr<ContextImpl>& context,
                                   const std::string& name,
                                   const std::string& server);
};

struct ContextImpl : public std::enable_shared_from_this<ContextImpl>
{
    SockAttach attach;

    // "const" after ctor
    Config effective;

    const Value caMethod;

    uint32_t nextCID=0x12345678;
    uint32_t prevndrop = 0u;

    evsocket searchTx;
    uint16_t searchRxPort;

    std::vector<ServerGUID> ignoreServerGUIDs;

    // poked and beaconSenders from both TCP and UDP workers
    epicsMutex pokeLock;
    epicsTimeStamp lastPoke{};
    bool poked = false;

    struct BTrack {
        ServerGUID guid;
        epicsTimeStamp lastRx;
    };
    std::map<SockAddr, BTrack> beaconSenders;

    std::vector<uint8_t> searchMsg;

    // search destination address and whether to set the unicast flag
    std::vector<std::pair<SockAddr, bool>> searchDest;

    size_t currentBucket = 0u;
    std::vector<std::list<std::weak_ptr<Channel>>> searchBuckets;

    std::list<std::unique_ptr<UDPListener> > beaconRx;

    std::map<uint32_t, std::weak_ptr<Channel>> chanByCID;
    // strong ref. loop through Channel::context
    // explicitly broken by Context::close(), Context::cacheClear(), or ContextImpl::cacheClean()
    // chanByName key'd by (pv, forceServer)
    std::map<std::pair<std::string, std::string>, std::shared_ptr<Channel>> chanByName;

    std::map<SockAddr, std::weak_ptr<Connection>> connByAddr;

    std::vector<std::pair<SockAddr, std::shared_ptr<Connection>>> nameServers;

    evbase tcp_loop;
    const evevent searchRx;
    const evevent searchTimer;

    // beacon handling done on UDP worker.
    // we keep a ref here as long as beaconCleaner is in use
    UDPManager manager;

    const evevent beaconCleaner;
    const evevent cacheCleaner;
    const evevent nsChecker;

    INST_COUNTER(ClientContextImpl);

    ContextImpl(const Config& conf, const evbase &tcp_loop);
    ~ContextImpl();

    void startNS();

    void close();

    void poke(bool force);

    void onBeacon(const UDPManager::Beacon& msg);

    bool onSearch();
    static void onSearchS(evutil_socket_t fd, short evt, void *raw);
    void tickSearch();
    static void tickSearchS(evutil_socket_t fd, short evt, void *raw);
    void tickBeaconClean();
    static void tickBeaconCleanS(evutil_socket_t fd, short evt, void *raw);
    void cacheClean(const std::string &name, Context::cacheAction force);
    static void cacheCleanS(evutil_socket_t fd, short evt, void *raw);
    void onNSCheck();
    static void onNSCheckS(evutil_socket_t fd, short evt, void *raw);
};

struct Context::Pvt {
    // external ref to running loop.
    // impl directly, and indirectly, contains internal refs
private:
    evbase loop;
public:
    std::shared_ptr<ContextImpl> impl;

    INST_COUNTER(ClientPvt);

    Pvt(const Config& conf);
    ~Pvt(); // I call ContextImpl::close()
};

} // namespace client

} // namespace pvxs

#endif // CLIENTIMPL_H
