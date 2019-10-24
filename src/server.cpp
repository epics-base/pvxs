/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <list>
#include <regex>
#include <system_error>

#include <dbDefs.h>
#include <envDefs.h>
#include <epicsThread.h>

#include <pvxs/server.h>
#include <pvxs/log.h>
#include "evhelper.h"
#include "utilpvt.h"
#include "udp_collector.h"

namespace pvxs {
namespace server {
using namespace pvxsimpl;

DEFINE_LOGGER(serversetup, "server.setup");
DEFINE_LOGGER(serverio, "server.io");

namespace {
void split_into(std::vector<std::string>& out, const char *inp)
{
    std::regex word("\\s*(\\S+)(.*)");
    std::cmatch M;

    while(*inp && std::regex_match(inp, M, word)) {
        out.push_back(M[1].str());
        inp = M[2].first;
    }
}
}

Server::Config Server::Config::from_env()
{
    Server::Config ret;
    ret.default_udp = 5076;

    if(const char *env = getenv("EPICS_PVAS_INTF_ADDR_LIST")) {
        split_into(ret.interfaces, env);
    }

    if(const char *env = getenv("EPICS_PVAS_BEACON_ADDR_LIST")) {
        split_into(ret.beaconDestinations, env);
    } else if(const char *env = getenv("EPICS_PVA_ADDR_LIST")) {
        split_into(ret.beaconDestinations, env);
    }

    ret.tcp_port = 5075;
    if(const char *env = getenv("EPICS_PVAS_SERVER_PORT")) {
        ret.tcp_port = lexical_cast<unsigned short>(env);
    } else if(const char *env = getenv("EPICS_PVA_SERVER_PORT")) {
        ret.tcp_port = lexical_cast<unsigned short>(env);
    }

    ret.default_udp = 5076;
    if(const char *env = getenv("EPICS_PVAS_BROADCAST_PORT")) {
        ret.default_udp = lexical_cast<unsigned short>(env);
    } else if(const char *env = getenv("EPICS_PVA_BROADCAST_PORT")) {
        ret.default_udp = lexical_cast<unsigned short>(env);
    }

    return ret;
}

namespace {

struct ServIface
{
    Server::Pvt * const server;

    SockAddr bind_addr;
    std::string name;

    evsocket sock;
    evlisten listener;

    std::unique_ptr<UDPListener> searchrx;

    ServIface(const std::string& addr, Server::Pvt *server);

    void onConn(evutil_socket_t sock, struct sockaddr *peer, int socklen);
    static void onConnS(struct evconnlistener *listener, evutil_socket_t sock, struct sockaddr *peer, int socklen, void *raw)
    {
        try {
            if(peer->sa_family!=AF_INET) {
                log_printf(serversetup, PLVL_CRIT, "Rejecting !ipv4 client\n");
                evutil_closesocket(sock);
                return;
            }
            static_cast<ServIface*>(raw)->onConn(sock, peer, socklen);
        }catch(std::exception& e){
            log_printf(serverio, PLVL_CRIT, "Unhandled error in accept callback: %s\n", e.what());
        }
    }
};

} // namespace

struct Server::Pvt
{
    // "const" after ctor
    Config effective;

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

    void doBeacons(short evt);
    static void doBeaconsS(evutil_socket_t fd, short evt, void *raw)
    {
        try {
            static_cast<Pvt*>(raw)->doBeacons(evt);
        }catch(std::exception& e){
            log_printf(serverio, PLVL_CRIT, "Unhandled error in beacon timer callback: %s\n", e.what());
        }
    }
};


Server::Server() {}

Server::Server(Config&& conf)
    :pvt(new Pvt(std::move(conf)))
{}

Server::~Server() {}

const Server::Config& Server::config() const
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    return pvt->effective;
}

Server& Server::start()
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->start();
    return *this;
}

Server::Pvt::Pvt(Config&& conf)
    :effective(std::move(conf))
    ,acceptor_loop("PVXS Acceptor", epicsThreadPriorityCAServerLow-2)
    ,beaconSender(AF_INET, SOCK_DGRAM, 0)
    ,beaconTimer(acceptor_loop.base, -1, EV_TIMEOUT, doBeaconsS, this)
    ,state(Stopped)
{
    // empty interface address list implies the wildcard
    // (because no addresses isn't interesting...)
    if(effective.interfaces.empty()) {
        effective.interfaces.push_back("0.0.0.0");
    }

    acceptor_loop.call([this](){
        // from acceptor worker

        for(const auto& addr : effective.interfaces) {
            interfaces.emplace_back(addr, this);
        }

        for(const auto& addr : effective.beaconDestinations) {
            beaconDest.emplace_back(AF_INET, addr);
        }

        if(effective.auto_beacon) {
            // append broadcast addresses associated with our bound interface(s)

            ELLLIST bcasts = ELLLIST_INIT;

            try {
                evsocket dummy(AF_INET, SOCK_DGRAM, 0);

                for(const auto& iface : interfaces) {
                    if(iface.bind_addr.family()!=AF_INET)
                        continue;
                    osiSockAddr match;
                    match.ia = iface.bind_addr->in;
                    osiSockDiscoverBroadcastAddresses(&bcasts, dummy.sock, &match);
                }

                // do our best to avoid an bad_alloc during iteration
                beaconDest.reserve(beaconDest.size()+(size_t)ellCount(&bcasts));

                while(ELLNODE *cur = ellGet(&bcasts)) {
                    osiSockAddrNode *node = CONTAINER(cur, osiSockAddrNode, node);
                    beaconDest.emplace_back(AF_INET);
                    beaconDest.back()->in = node->addr.ia;
                    free(cur);
                }

            }catch(...){
                ellFree(&bcasts);
                throw;
            }
        }

        effective.interfaces.clear();
        for(const auto& iface : interfaces) {
            effective.interfaces.emplace_back(iface.bind_addr.tostring());
        }

        effective.beaconDestinations.clear();
        for(const auto& addr : beaconDest) {
            effective.beaconDestinations.emplace_back(addr.tostring());
        }

        effective.auto_beacon = false;
    });
}

Server::Pvt::~Pvt() {}

void Server::Pvt::start()
{
    log_printf(serversetup, PLVL_DEBUG, "Server Starting\n");
    acceptor_loop.call([this]()
    {
        if(state!=Stopped) {
            // already running
            log_printf(serversetup, PLVL_DEBUG, "Server not stopped %d\n", state);
            return;
        }
        state = Starting;
        log_printf(serversetup, PLVL_DEBUG, "Server starting\n");

        for(auto& iface : interfaces) {
            if(evconnlistener_enable(iface.listener.lev)) {
                log_printf(serversetup, PLVL_ERR, "Error enabling listener on %s\n", iface.name.c_str());
            }
            log_printf(serversetup, PLVL_DEBUG, "Server enabled listener on %s\n", iface.name.c_str());
        }

        // send first beacon immediately
        if(event_add(beaconTimer, nullptr))
            log_printf(serversetup, PLVL_ERR, "Error enabling beacon timer on\n");

        state = Running;
    });

    auto manager = UDPManager::instance();

    for(auto& iface : interfaces) {
        auto addr = iface.bind_addr;
        addr.setPort(effective.default_udp);
        iface.searchrx = manager.subscribe(addr, [](const UDPMsg& msg) {
            // TODO handle search
        });
    }
}

void Server::Pvt::stop()
{
    log_printf(serversetup, PLVL_DEBUG, "Server Stopping\n");

    // Stop sending Beacons
    acceptor_loop.call([this]()
    {
        if(state!=Running) {
            log_printf(serversetup, PLVL_DEBUG, "Server not running %d\n", state);
            return;
        }
        state = Stopping;

        if(event_del(beaconTimer.ev))
            log_printf(serversetup, PLVL_ERR, "Error disabling beacon timer on\n");
    });

    // stop processing Search requests
    for(auto& iface : interfaces) {
        iface.searchrx.reset();
    }

    // stop listening for new TCP connections
    acceptor_loop.call([this]()
    {

        for(auto& iface : interfaces) {
            if(evconnlistener_disable(iface.listener.lev)) {
                log_printf(serversetup, PLVL_ERR, "Error disabling listener on %s\n", iface.name.c_str());
            }
            log_printf(serversetup, PLVL_DEBUG, "Server disabled listener on %s\n", iface.name.c_str());
        }
    });

    // Close in-progress connections (and cancel Ops)

    acceptor_loop.call([this]()
    {
        state = Stopped;
    });
}

void Server::Pvt::doBeacons(short evt)
{
    log_printf(serversetup, PLVL_DEBUG, "Server beacon timer expires\n");

    // TODO send beacons

    timeval interval = {15, 0};
    if(event_add(beaconTimer, &interval))
        log_printf(serversetup, PLVL_ERR, "Error re-enabling beacon timer on\n");
}

ServIface::ServIface(const std::string& addr, Server::Pvt *server)
    :server(server)
    ,bind_addr(AF_INET, addr)
    ,sock(AF_INET, SOCK_STREAM, 0)
{
    server->acceptor_loop.assertInLoop();

    // try to bind to requested port, then fallback to a random port
    while(true) {
        try {
            sock.bind(bind_addr);
        } catch(std::system_error& e) {
            if(e.code().value()==SOCK_EADDRINUSE && bind_addr.port()!=0) {
                bind_addr.setPort(0);
                continue;
            }
            throw;
        }
        break;
    }

    name = bind_addr.tostring();

    const int backlog = 4;
    listener = evlisten(server->acceptor_loop.base, onConnS, this, LEV_OPT_DISABLED, backlog, sock.sock);
}

void ServIface::onConn(evutil_socket_t sock, struct sockaddr *peer, int socklen)
{
    evutil_closesocket(sock);
}

}} // namespace pvxs::server
