/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef SERVERCONN_H
#define SERVERCONN_H

#include <list>
#include <map>

#include <epicsEvent.h>

#include <pvxs/server.h>
#include "evhelper.h"
#include "utilpvt.h"
#include "udp_collector.h"

namespace pvxsimpl {

struct ServIface;
struct ServerConn;

struct ServerOp
{
    ServerConn* const conn;

    evbuf rx;

    ServerOp();
};

struct ServerConn
{
    ServIface* const iface;

    SockAddr peerAddr;
    std::string peerName;
    evbufferevent bev;

    // credentials

    bool peerBE;
    bool expectSeg;

    uint8_t segCmd;
    evbuf segBuf, txBody;

    ServerConn(ServIface* iface, evutil_socket_t sock, struct sockaddr *peer, int socklen);
    ~ServerConn();

private:
#define CASE(Op) void handle_##Op();
                CASE(Echo);
                CASE(ConnValid);
                CASE(Search);
                CASE(AuthZ);

                CASE(CreateChan);
                CASE(DestroyChan);

                CASE(GetOp);
                CASE(PutOp);
                CASE(PutGetOp);
                CASE(RPCOp);
                CASE(CancelOp);
                CASE(DestroyOp);
                CASE(Introspect);

                CASE(Message);
#undef CASE

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

    std::list<ServerConn> connections;

    ServIface(const std::string& addr, unsigned short port, server::Server::Pvt *server);

    static void onConnS(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *peer, int socklen, void *raw);
};

} // namespace pvxsimpl

namespace pvxs {
namespace server {
using namespace pvxsimpl;

struct Server::Pvt
{
    // "const" after ctor
    Config effective;

    epicsEvent done;

    std::vector<uint8_t> beaconMsg;

    std::list<std::unique_ptr<UDPListener> > listeners;
    std::list<ServIface> interfaces;

    std::vector<SockAddr> beaconDest;

    // handlers for active TCP connections, by priority.
    // once added, these remain stable for the lifetime of the Server
    std::map<unsigned, evbase> prio_loops;

    // handle server "background" tasks.
    // accept new connections and send beacons
    evbase acceptor_loop;

    evsocket beaconSender;
    evevent beaconTimer;

    std::vector<uint8_t> searchReply;

    Source::Search searchOp;

    RWLock sourcesLock;
    std::map<std::pair<int, std::string>, std::shared_ptr<Source> > sources;

    enum {
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
