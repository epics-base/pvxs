/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <list>
#include <map>
#include <regex>
#include <system_error>
#include <functional>
#include <cstdlib>

#include <dbDefs.h>
#include <envDefs.h>
#include <epicsThread.h>
#include <epicsTime.h>
#include <epicsGuard.h>

#include <pvxs/server.h>
#include <pvxs/log.h>
#include "evhelper.h"
#include "serverconn.h"
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
    ret.udp_port = 5076;

    if(const char *env = getenv("EPICS_PVAS_INTF_ADDR_LIST")) {
        split_into(ret.interfaces, env);
    }

    if(const char *env = getenv("EPICS_PVAS_BEACON_ADDR_LIST")) {
        split_into(ret.beaconDestinations, env);
    } else if(const char *env = getenv("EPICS_PVA_ADDR_LIST")) {
        split_into(ret.beaconDestinations, env);
    }

    // TODO resolve host->IP in interfaces and beaconDestinations

    ret.tcp_port = 5075;
    if(const char *env = getenv("EPICS_PVAS_SERVER_PORT")) {
        ret.tcp_port = lexical_cast<unsigned short>(env);
    } else if(const char *env = getenv("EPICS_PVA_SERVER_PORT")) {
        ret.tcp_port = lexical_cast<unsigned short>(env);
    }

    ret.udp_port = 5076;
    if(const char *env = getenv("EPICS_PVAS_BROADCAST_PORT")) {
        ret.udp_port = lexical_cast<unsigned short>(env);
    } else if(const char *env = getenv("EPICS_PVA_BROADCAST_PORT")) {
        ret.udp_port = lexical_cast<unsigned short>(env);
    }

    return ret;
}



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
    ,beaconMsg(128)
    ,acceptor_loop("PVXS Acceptor", epicsThreadPriorityCAServerLow-2)
    ,beaconSender(AF_INET, SOCK_DGRAM, 0)
    ,beaconTimer(event_new(acceptor_loop.base, -1, EV_TIMEOUT, doBeaconsS, this))
    ,searchReply(0x10000)
    ,state(Stopped)
{
    // empty interface address list implies the wildcard
    // (because no addresses isn't interesting...)
    if(effective.interfaces.empty()) {
        effective.interfaces.push_back("0.0.0.0");
    }

    auto manager = UDPManager::instance();

    for(const auto& iface : effective.interfaces) {
        SockAddr addr(AF_INET, iface.c_str());
        addr.setPort(effective.udp_port);
        listeners.push_back(manager.onSearch(addr,
                                             std::bind(&Pvt::onSearch, this, std::placeholders::_1) ));
        // update to allow udp_port==0
        effective.udp_port = addr.port();
    }

    evsocket dummy(AF_INET, SOCK_DGRAM, 0);

    {
        // choose new GUID.
        // treat as 3x 32-bit unsigned.
        union {
            std::array<uint32_t, 3> i;
            std::array<uint8_t, 3*4> b;
        } pun;
        static_assert (sizeof(pun)==12, "");

        // i[0] time
        epicsTimeStamp now;
        epicsTimeGetCurrent(&now);
        pun.i[0] = now.secPastEpoch ^ now.nsec;

        // i[1] host
        // mix together all local bcast addresses
        pun.i[1] = 0xdeadbeef; // because... why not
        {
            ELLLIST bcasts = ELLLIST_INIT;
            osiSockDiscoverBroadcastAddresses(&bcasts, dummy.sock, nullptr);

            while(ELLNODE *cur = ellGet(&bcasts)) {
                osiSockAddrNode *node = CONTAINER(cur, osiSockAddrNode, node);
                if(node->addr.sa.sa_family==AF_INET)
                    pun.i[1] ^= ntohl(node->addr.ia.sin_addr.s_addr);
                free(cur);
            }
        }

        // i[2] random
        pun.i[2] = (rand()/double(RAND_MAX))*0xffffffff;

        std::copy(pun.b.begin(), pun.b.end(), effective.guid.begin());
    }

    acceptor_loop.call([this, &dummy](){
        // from acceptor worker

        for(const auto& addr : effective.interfaces) {
            interfaces.emplace_back(addr, effective.tcp_port, this);
            if(effective.tcp_port==0)
                effective.tcp_port = interfaces.back().bind_addr.port();
        }

        for(const auto& addr : effective.beaconDestinations) {
            beaconDest.emplace_back(AF_INET, addr.c_str(), effective.udp_port);
        }

        if(effective.auto_beacon) {
            // append broadcast addresses associated with our bound interface(s)

            ELLLIST bcasts = ELLLIST_INIT;

            try {
                for(const auto& iface : interfaces) {
                    if(iface.bind_addr.family()!=AF_INET)
                        continue;
                    osiSockAddr match;
                    match.ia = iface.bind_addr->in;
                    osiSockDiscoverBroadcastAddresses(&bcasts, dummy.sock, &match);
                }

                // do our best to avoid a bad_alloc during iteration
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

Server::Pvt::~Pvt()
{
    stop();
}

void Server::Pvt::start()
{
    log_printf(serversetup, PLVL_DEBUG, "Server Starting\n");

    // begin accepting connections
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
            if(evconnlistener_enable(iface.listener.get())) {
                log_printf(serversetup, PLVL_ERR, "Error enabling listener on %s\n", iface.name.c_str());
            }
            log_printf(serversetup, PLVL_DEBUG, "Server enabled listener on %s\n", iface.name.c_str());
        }
    });

    // being processing Searches
    for(auto& L : listeners) {
        L->start();
    }

    // begin sending beacons
    acceptor_loop.call([this]()
    {
        // send first beacon immediately
        if(event_add(beaconTimer.get(), nullptr))
            log_printf(serversetup, PLVL_ERR, "Error enabling beacon timer on\n");

        state = Running;
    });


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

        if(event_del(beaconTimer.get()))
            log_printf(serversetup, PLVL_ERR, "Error disabling beacon timer on\n");
    });

    // stop processing Search requests
    for(auto& L : listeners) {
        L->stop();
    }

    // stop accepting new TCP connections
    acceptor_loop.call([this]()
    {
        for(auto& iface : interfaces) {
            if(evconnlistener_disable(iface.listener.get())) {
                log_printf(serversetup, PLVL_ERR, "Error disabling listener on %s\n", iface.name.c_str());
            }
            log_printf(serversetup, PLVL_DEBUG, "Server disabled listener on %s\n", iface.name.c_str());
        }

        state = Stopped;
    });
}

void Server::Pvt::onSearch(const UDPManager::Search& msg)
{
    // on UDPManager worker

    searchOp._names.resize(msg.names.size());
    for(auto i : range(msg.names.size())) {
        searchOp._names[i]._name = msg.names[i].name;
        searchOp._names[i]._claim = false;
    }

    {
        epicsGuard<RWLock::Reader> G(sourcesLock.reader());
        for(const auto& pair : sources) {
            try {
                pair.second->onSearch(searchOp);
            }catch(std::exception& e){
                log_printf(serversetup, PLVL_ERR, "Unhandled error in Source::onSearch for '%s' : %s\n",
                           pair.first.second.c_str(), e.what());
            }
        }
    }

    uint16_t nreply = 0;
    for(const auto& name : searchOp._names) {
        if(name._claim)
            nreply++;
    }

    // "pvlist" breaks unless we honor mustReply flag
    if(nreply==0 && !msg.mustReply)
        return;

    sbuf<uint8_t> M(searchReply.data(), searchReply.size());

    const bool be = true;
    to_wire(M, {0xca, pva_version::server, pva_flags::MSB|pva_flags::Server, pva_app_msg::SearchReply}, be);
    auto blen = M.split(4);

    _to_wire<12>(M, effective.guid.data(), false);
    to_wire(M, msg.searchID, be);
    to_wire(M, SockAddr::any(AF_INET), be);
    to_wire(M, uint16_t(effective.udp_port), be);
    to_wire(M, "tcp", be);
    // "found" flag
    to_wire(M, {uint8_t(nreply!=0 ? 1 : 0)}, be);

    to_wire(M, uint16_t(nreply), be);
    for(auto i : range(msg.names.size())) {
        if(searchOp._names[i]._claim)
            to_wire(M, uint32_t(msg.names[i].id), be);
    }

    uint32_t ntx = M.pos-searchReply.data();
    to_wire(blen, uint32_t(ntx-8), be);

    if(M.err || blen.err) {
        log_printf(serverio, PLVL_CRIT, "Logic error in Search buffer fill\n");
    } else {
        (void)msg.reply(searchReply.data(), ntx);
    }
}

void Server::Pvt::doBeacons(short evt)
{
    log_printf(serversetup, PLVL_DEBUG, "Server beacon timer expires\n");

    sbuf<uint8_t> M(beaconMsg.data(), beaconMsg.size());
    const bool be = true;
    to_wire(M, {0xca, pva_version::server, pva_flags::MSB|pva_flags::Server, pva_app_msg::Beacon}, be);
    auto lenfld = M.split(4);

    _to_wire<12>(M, effective.guid.data(), false);
    M += 4; // ignored/unused

    to_wire(M, SockAddr::any(AF_INET), be);
    to_wire(M, uint16_t(effective.tcp_port), be);
    to_wire(M, "tcp", be);
    // "NULL" serverStatus
    to_wire(M, {0xff}, be);

    to_wire(lenfld, uint32_t(M.pos - beaconMsg.data()), be);

    assert(!M.err && !lenfld.err);

    for(const auto& dest : beaconDest) {
        int ntx = sendto(beaconSender.sock, (char*)beaconMsg.data(), beaconMsg.size(), 0, &dest->sa, dest.size());

        if(ntx<0) {
            int err = evutil_socket_geterror(beaconSender.sock);
            log_printf(serverio, PLVL_WARN, "Beacon tx error (%d) %s\n",
                       err, evutil_socket_error_to_string(err));

        } else if(unsigned(ntx)<beaconMsg.size()) {
            log_printf(serverio, PLVL_WARN, "Beacon truncated %u", unsigned(dest.size()));
        }
    }

    timeval interval = {15, 0};
    if(event_add(beaconTimer.get(), &interval))
        log_printf(serversetup, PLVL_ERR, "Error re-enabling beacon timer on\n");
}

void Server::Pvt::doBeaconsS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Pvt*>(raw)->doBeacons(evt);
    }catch(std::exception& e){
        log_printf(serverio, PLVL_CRIT, "Unhandled error in beacon timer callback: %s\n", e.what());
    }
}

}} // namespace pvxs::server
