/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <cstdlib>
#include <functional>
#include <list>
#include <map>
#include <system_error>

#include <dbDefs.h>
#include <envDefs.h>
#include <epicsGuard.h>
#include <epicsString.h>
#include <epicsThread.h>
#include <epicsTime.h>
#include <signal.h>

#include <pvxs/client.h>
#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/sharedwildcardpv.h>

#include "evhelper.h"
#include "p12filewatcher.h"
#include "serverconn.h"
#include "udp_collector.h"
#include "utilpvt.h"

namespace pvxs {
namespace impl {
ReportInfo::~ReportInfo() {}
}  // namespace impl
namespace server {
using namespace impl;

DEFINE_LOGGER(serversetup, "pvxs.svr.init");
DEFINE_LOGGER(osslsetup, "pvxs.ossl.init");
DEFINE_LOGGER(watcher, "pvxs.cert.mon");
DEFINE_LOGGER(serverio, "pvxs.svr.io");
DEFINE_LOGGER(serversearch, "pvxs.svr.search");

// mimic pvAccessCPP server (almost)
// send a "burst" of beacons, then fallback to a longer interval
static constexpr timeval beaconIntervalShort{15, 0};
static constexpr timeval beaconIntervalLong{180, 0};

#ifndef PVXS_ENABLE_OPENSSL
Server Server::fromEnv()
{
    return Config::fromEnv().build();
}
#else
Server Server::fromEnv(const bool tls_disabled, const ConfigCommon::ConfigTarget target)
{
    return Config::fromEnv(tls_disabled, target).build();
}

Server Server::fromEnv(CertEventCallback &cert_file_event_callback, const bool tls_disabled, const ConfigCommon::ConfigTarget target)
{
    return Config::fromEnv(tls_disabled, target).build(cert_file_event_callback);
}

Server::Server(const Config &conf, CertEventCallback cert_file_event_callback) {
    auto internal(std::make_shared<Pvt>(conf, cert_file_event_callback));
    internal->internal_self = internal;

    // external
    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        auto trash(std::move(internal));
        trash->stop();
    });
}
#endif

Server::Server(const Config& conf)
{
    /* Here be dragons.
     *
     * We keep two different ref. counters.
     * - "external" counter which keeps a server running.
     * - "internal" which only keeps server storage from being destroyed.
     *
     * External refs are held as Server::pvt.  Internal refs are
     * held by various in-progress operations (OpBase sub-classes)
     * Which need to safely access server storage, but should not
     * prevent a server from stopping.
     */
    auto internal(std::make_shared<Pvt>(conf));
    internal->internal_self = internal;

    // external
    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        auto trash(std::move(internal));
        trash->stop();
    });

    // we don't keep a weak_ptr to the external reference.
    // Caller is entirely responsible for keeping this server running
}

Server::~Server() {}

Server& Server::addSource(const std::string& name,
                  const std::shared_ptr<Source>& src,
                  int order)
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    if(!src)
        throw std::logic_error(SB()<<"Attempt to add NULL Source "<<name<<" at "<<order);
    {
        auto G(pvt->sourcesLock.lockWriter());

        auto& ent = pvt->sources[std::make_pair(order, name)];
        if(ent)
            throw std::runtime_error(SB()<<"Source already registered : ("<<name<<", "<<order<<")");
        ent = src;
        pvt->beaconChange++;
    }
    return *this;
}

std::shared_ptr<Source> Server::removeSource(const std::string& name,  int order)
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    auto G(pvt->sourcesLock.lockWriter());

    std::shared_ptr<Source> ret;
    auto it = pvt->sources.find(std::make_pair(order, name));
    if(it!=pvt->sources.end()) {
        ret = it->second;
        pvt->sources.erase(it);
    }
    pvt->beaconChange++;

    return ret;
}

std::shared_ptr<Source> Server::getSource(const std::string& name, int order)
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    auto G(pvt->sourcesLock.lockReader());

    std::shared_ptr<Source> ret;
    auto it = pvt->sources.find(std::make_pair(order, name));
    if(it!=pvt->sources.end()) {
        ret = it->second;
    }

    return ret;
}

std::vector<std::pair<std::string, int> > Server::listSource()
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    std::vector<std::pair<std::string, int> > names;

    auto G(pvt->sourcesLock.lockReader());

    names.reserve(pvt->sources.size());

    for(auto& pair : pvt->sources) {
        names.emplace_back(pair.first.second, pair.first.first);
    }

    return names;
}

#ifdef PVXS_ENABLE_OPENSSL
void Server::reconfigure(const Config& inconf)
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    auto newconf(inconf);
    newconf.expand(); // maybe catch some errors early

    log_info_printf(watcher, "Reconfiguring Server Context%s", "\n");

    // is the current server running?

    Pvt::state_t prev_state;
    pvt->acceptor_loop.call([this, &prev_state]() {
        prev_state = pvt->state;
    });

    bool was_running = prev_state==Pvt::Running || prev_state==Pvt::Starting;

    if(was_running)
        pvt->stop();

    decltype(pvt->sources) transfers;
    decltype(pvt->builtinsrc) builtin;

    // copy all Source, including builtin
    {
        auto G(pvt->sourcesLock.lockReader());

        transfers = pvt->sources;
        builtin = pvt->builtinsrc;
    }

    // completely destroy the current/old server to free up TCP ports
    pvt.reset();

    // build up a new, empty, server
    Server newsrv(newconf);
    pvt = std::move(newsrv.pvt);

    {
        auto G(pvt->sourcesLock.lockWriter());

        pvt->sources = transfers;
        pvt->builtinsrc = builtin;
    }

    if(was_running) {
        pvt->start();
        log_info_printf(watcher, "Resuming Server after Reconfiguration%s", "\n");
    }
}

#endif

const Config& Server::config() const
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    return pvt->effective;
}

client::Config Server::clientConfig() const
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    client::Config ret;
    // do not copy tls_cert_file
    ret.udp_port = pvt->effective.udp_port;
    ret.tcp_port = pvt->effective.tcp_port;
    ret.interfaces = pvt->effective.interfaces;
    ret.addressList = pvt->effective.interfaces;
    ret.autoAddrList = false;

#ifdef PVXS_ENABLE_OPENSSL
    ret.tls_port = pvt->effective.tls_port;
#endif

    return ret;
}

Server& Server::addPV(const std::string& name, const SharedPV& pv)
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->builtinsrc.add(name, pv);
    pvt->beaconChange++;
    return *this;
}

Server& Server::addPV(const std::string& name, const SharedWildcardPV& pv)
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->builtinsrc.add(name, pv);
    pvt->beaconChange++;
    return *this;
}

Server& Server::removePV(const std::string& name)
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->builtinsrc.remove(name);
    pvt->beaconChange++;
    return *this;
}

Server& Server::start()
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->start();
    return *this;
}

//void Server::Pvt::reconfigure() {
//
//}

Server& Server::stop()
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->stop();
    return *this;
}

Server& Server::run()
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    pvt->start();

    {
        SigInt handler([this](){
            pvt->done.signal();
        });

        pvt->done.wait();
    }

    pvt->stop();

    return *this;
}

Server& Server::interrupt()
{
    if(!pvt)
        throw std::logic_error("NULL Server");
    pvt->done.signal();
    return *this;
}

Report Server::report(bool zero) const
{
    if(!pvt)
        throw std::logic_error("NULL Server");

    Report ret;

    pvt->acceptor_loop.call([this, &ret, zero](){

        for(auto& pair : pvt->connections) {
            auto conn = pair.first;

            ret.connections.emplace_back();
            auto& sconn = ret.connections.back();
            sconn.peer = conn->peerName;
            sconn.credentials = conn->cred;
            sconn.tx = conn->statTx;
            sconn.rx = conn->statRx;

            if(zero) {
                conn->statTx = conn->statRx = 0u;
            }

            for(auto& pair : conn->chanBySID) {
                auto& chan = pair.second;

                sconn.channels.emplace_back();
                auto& schan = sconn.channels.back();
                schan.name = chan->name;
                schan.tx = chan->statTx;
                schan.rx = chan->statRx;
                schan.info = chan->reportInfo;

                if(zero) {
                    chan->statTx = chan->statRx = 0u;
                }
            }
        }

    });

    return ret;
}

std::ostream& operator<<(std::ostream& strm, const Server& serv)
{
    auto detail = Detailed::level(strm);

    if(!serv.pvt) {
        strm<<indent{}<<"NULL";

    } else {
        strm<<indent{}<<serv.config();

        {
            auto L(serv.pvt->sourcesLock.lockReader());

            for(auto& pair : serv.pvt->sources) {
                strm<<indent{}<<"Source: "<<pair.first.second<<" prio="<<pair.first.first<<" ";
                if(!pair.second) {
                    strm<<"NULL";

                } else if(detail>0) {
                    Indented I(strm);
                    Detailed D(strm, detail-1);
                    pair.second->show(strm);
                }
                strm<<"\n";
            }
        }

        if(detail<2)
            return strm;

        serv.pvt->acceptor_loop.call([&serv, &strm, detail](){
            strm<<indent{}<<"State: ";
            switch(serv.pvt->state) {
#define CASE(STATE) case Server::Pvt::STATE: strm<< #STATE; break
            CASE(Stopped);
            CASE(Starting);
            CASE(Running);
            CASE(Stopping);
#undef CASE
            }
            if(!serv.pvt->interfaces.empty()) {
                auto& first = serv.pvt->interfaces.front();
                strm<<" TCP_Port: "<<first.bind_addr.port();
            }
            strm<<"\n";

#ifdef PVXS_ENABLE_OPENSSL
            if(serv.pvt->tls_context) {
                auto cert(serv.pvt->tls_context.certificate0());
                assert(cert);
                strm<<indent{}<<"TLS Cert. "<<ossl::ShowX509{cert}<<"\n";
            } else {
                strm<<indent{}<<"TLS Cert. not loaded\n";
            }
#else
            strm<<indent{}<<"TLS Support not enabled\n";
#endif

            Indented I(strm);

            for(auto& pair : serv.pvt->connections) {
                auto conn = pair.first;

                strm<<indent{}<<"Peer"<<conn->peerName
                    <<" backlog="<<conn->backlog.size()
                    <<" TX="<<conn->statTx<<" RX="<<conn->statRx
                    <<" auth="<<conn->cred->method
#ifdef PVXS_ENABLE_OPENSSL
                  <<(conn->iface->isTLS ? " TLS" : "")
#endif
                    <<"\n";

                if(detail<=2)
                    continue;

                Indented I(strm);

                strm<<indent{}<<"Cred: "<<*conn->cred<<"\n";
#ifdef PVXS_ENABLE_OPENSSL
                if(conn->iface->isTLS && conn->connection()) {
                    auto ctx = bufferevent_openssl_get_ssl(conn->connection());
                    assert(ctx);
                    if(auto cert = SSL_get0_peer_certificate(ctx))
                        strm<<indent{}<<"Cert: "<<ossl::ShowX509{cert}<<"\n";
                }
#endif

                for(auto& pair : conn->chanBySID) {
                    auto& chan = pair.second;
                    strm<<indent{}<<chan->name<<" TX="<<chan->statTx<<" RX="<<chan->statRx<<' ';

                    if(chan->state==ServerChan::Creating) {
                        strm<<"CREATING sid="<<chan->sid<<" cid="<<chan->cid<<"\n";
                    } else if(chan->state==ServerChan::Destroy) {
                        strm<<"DESTROY  sid="<<chan->sid<<" cid="<<chan->cid<<"\n";
                    } else if(chan->opByIOID.empty()) {
                        strm<<"IDLE     sid="<<chan->sid<<" cid="<<chan->cid<<"\n";
                    }

                    for(auto& pair : chan->opByIOID) {
                        auto& op = pair.second;
                        if(!op) {
                            strm<<"NULL ioid="<<pair.first<<"\n";
                        } else {
                            strm<<indent{};
                            switch (op->state) {
#define CASE(STATE) case ServerOp::STATE: strm<< #STATE; break
                            CASE(Creating);
                            CASE(Idle);
                            CASE(Executing);
                            CASE(Dead);
#undef CASE
                            }
                            strm<<" ioid="<<pair.first<<" ";
                            op->show(strm);
                        }
                    }
                }
            }
        });
    }

    return strm;
}

#ifndef PVXS_ENABLE_OPENSSL
Server::Pvt::Pvt(const Config &conf)
#else
Server::Pvt::Pvt(const Config& conf, CertEventCallback cert_file_event_callback)
#endif
    : effective(conf)
    , beaconMsg(128)
    , acceptor_loop("PVXTCP", epicsThreadPriorityCAServerLow-2)
    , beaconSender4(AF_INET, SOCK_DGRAM, 0)
    , beaconSender6(AF_INET6, SOCK_DGRAM, 0)
    , beaconTimer(__FILE__, __LINE__,
                 event_new(acceptor_loop.base, -1, EV_TIMEOUT, doBeaconsS, this))
    , searchReply(0x10000)
    , builtinsrc(StaticSource::build())
    , state(Stopped)
#ifdef PVXS_ENABLE_OPENSSL
    , cert_file_event_callback(cert_file_event_callback)
    , cert_file_event_timer(__FILE__, __LINE__,
                            event_new(acceptor_loop.base, -1, EV_TIMEOUT, doCertFileEventhandler, this))
#endif
{
    effective.expand();

#ifdef PVXS_ENABLE_OPENSSL
    if(effective.isTlsConfigured()) {
        try {
            tls_context = ossl::SSLContext::for_server(effective);
            log_info_printf(osslsetup, "TLS enabled for server%s\n", "");
        } catch (std::exception& e) {
            if (effective.tls_stop_if_no_cert) {
                log_err_printf(osslsetup, "***EXITING***: TLS disabled for server: %s\n", e.what());
                exit(1);
            } else {
                log_err_printf(osslsetup, "TLS disabled for server: %s\n", e.what());
            }
        }
    }
#endif

    beaconSender4.set_broadcast(true);

    auto manager = UDPManager::instance(effective.shareUDP());

    evsocket dummy(AF_INET, SOCK_DGRAM, 0);

    const auto cb(std::bind(&Pvt::onSearch, this, std::placeholders::_1));

    bool bindAny = false;
    std::vector<SockAddr> tcpifaces; // may have port zero
    tcpifaces.reserve(effective.interfaces.size());

    for(const auto& iface : effective.interfaces) {
        SockEndpoint addr(iface.c_str());

        if(addr.addr.isAny()) {
            bindAny = true;

        } else if(!addr.addr.isMCast()) {
            tcpifaces.push_back(addr.addr);
        }

        addr.addr.setPort(effective.udp_port);

        listeners.push_back(manager.onSearch(addr, cb));

        // update to allow udp_port==0
        effective.udp_port = addr.addr.port();


        if(addr.addr.isAny()) {
            continue; // special case handling below
        }

        if(addr.addr.family()==AF_INET && addr.addr.isAny()) {
            // if listening on 0.0.0.0, also listen on [::]
            auto any6(addr);
            any6.addr = SockAddr::any(AF_INET6);

            listeners.push_back(manager.onSearch(any6, cb));

        } else if(addr.addr.family()==AF_INET6 && addr.addr.isAny()) {
            // if listening on [::], also listen on 0.0.0.0
            auto any4(addr);
            any4.addr = SockAddr::any(AF_INET);

            listeners.push_back(manager.onSearch(any4, cb));
        }

        if(evsocket::ipstack!=evsocket::Winsock
                && addr.addr.family()==AF_INET && !addr.addr.isAny() && !addr.addr.isMCast()) {
            /* An oddness of BSD sockets (not winsock) is that binding to
             * INADDR_ANY will receive unicast and broadcast, but binding to
             * a specific interface address receives only unicast.  The trick
             * is to bind a second socket to the interface broadcast address,
             * which will then receive only broadcasts.
             */
            for(auto bcast : dummy.broadcasts(&addr.addr)) {
                bcast.setPort(addr.addr.port());
                listeners.push_back(manager.onSearch(bcast, cb));
            }
        }
    }

    if(bindAny) {
        if(evsocket::canIPv6) {
            if(evsocket::ipstack==evsocket::Linsock) {
                /* Linux IP stack disallows binding both 0.0.0.0 and [::] for the same port.
                 * so we must always bind [::]
                 */
                tcpifaces.emplace_back(AF_INET6);
            } else {
                /* Other IP stacks allow binding different sockets.
                 * OSX has the added oddity of ordering dependence.
                 * 0.0.0.0 and then :: is allowed, but not the reverse.
                 *
                 * Always bind both in the OSX allowed order.
                 */
                tcpifaces.emplace_back(AF_INET);
                tcpifaces.emplace_back(AF_INET6);
            }
        } else {
            tcpifaces.emplace_back(AF_INET);
        }
    }

    if(tcpifaces.empty()) {
        log_err_printf(serversetup, "Server Unreachable.  Interface address list includes not TCP interfaces.%s", "\n");
    }

    ignoreList.reserve(effective.ignoreAddrs.size());
    for(const auto& addr : effective.ignoreAddrs) {
        SockAddr temp(addr.c_str());
        ignoreList.push_back(temp);
    }


    acceptor_loop.call([this, &tcpifaces](){
        // from accepter worker

#ifdef PVXS_ENABLE_OPENSSL
        decltype(tcpifaces) tlsifaces(tcpifaces); // copy before any setPort()
#endif

        bool firstiface = true;
        for(auto& addr : tcpifaces) {
            if(addr.port()==0)
                addr.setPort(effective.tcp_port);

            interfaces.emplace_back(addr, this, firstiface, false);

            if(firstiface || effective.tcp_port==0)
                effective.tcp_port = interfaces.back().bind_addr.port();
            firstiface = false;
        }

#ifdef PVXS_ENABLE_OPENSSL
        if(tls_context) {
            firstiface = true;
            for(auto& addr : tlsifaces) {
                // unconditionally set port to avoid clash with plain TCP listener
                addr.setPort(effective.tls_port);

                interfaces.emplace_back(addr, this, firstiface, true);

                if(firstiface || effective.tls_port==0)
                    effective.tls_port = interfaces.back().bind_addr.port();
                firstiface = false;
            }
        }
#endif

        for(const auto& addr : effective.beaconDestinations) {
            beaconDest.emplace_back(addr.c_str(), &effective);
            log_debug_printf(serversetup, "Will send beacons to %s\n",
                             std::string(SB()<<beaconDest.back()).c_str());
        }
    });

    {
        // choose new GUID.
        // treat as 3x 32-bit unsigned.
        union {
            std::array<uint32_t, 3> i;
            std::array<uint8_t, 3*4> b;
        } pun{};
        static_assert (sizeof(pun)==12, "");

        // seed with some randomness to avoid making UUID a vector
        // for information disclosure
        evutil_secure_rng_get_bytes((char*)pun.b.data(), sizeof(pun.b));

        // i[0] (start) time
        epicsTimeStamp now;
        epicsTimeGetCurrent(&now);
        pun.i[0] ^= now.secPastEpoch ^ now.nsec;

        // i[1] host
        // mix together first interface and all local bcast addresses
        pun.i[1] ^= ntohl(osiLocalAddr(dummy.sock).ia.sin_addr.s_addr);
        for(auto& addr : dummy.broadcasts()) {
            if(addr.family()==AF_INET)
                pun.i[1] ^= ntohl(addr->in.sin_addr.s_addr);
        }

        // i[2] process on host
#if defined(_WIN32)
        pun.i[2] ^= GetCurrentProcessId();
#elif !defined(__rtems__) && !defined(vxWorks)
        pun.i[2] ^= getpid();
#else
        pun.i[2] ^= 0xdeadbeef;
#endif
        // and a bit of server instance within this process
        pun.i[2] ^= uint32_t(effective.tcp_port)<<16u;
        // maybe a little bit of randomness (eg. ASLR on Linux)
        pun.i[2] ^= size_t(this);
        if(sizeof(size_t)>4)
            pun.i[2] ^= size_t(this)>>32u;

        std::copy(pun.b.begin(), pun.b.end(), effective.guid.begin());
    }

    // Add magic "server" PV
    {
        auto L = sourcesLock.lockWriter();
        sources[std::make_pair(-1, "__server")] = std::make_shared<ServerSource>(this);
        sources[std::make_pair(-1, "__builtin")] = builtinsrc.source();
    }
}

Server::Pvt::~Pvt()
{
    stop();
}

void Server::Pvt::start()
{
    log_debug_printf(serversetup, "Server Starting\n%s", "");

    // begin accepting connections
    state_t prev_state;
    acceptor_loop.call([this, &prev_state]()
    {
        prev_state = state;
        if(state!=Stopped) {
            // already running
            log_debug_printf(serversetup, "Server not stopped %d\n", state);
            return;
        }
        state = Starting;
        log_debug_printf(serversetup, "Server starting\n%s", "");

        for(auto& iface : interfaces) {
            if(evconnlistener_enable(iface.listener.get())) {
                log_err_printf(serversetup, "Error enabling listener on %s\n", iface.name.c_str());
            }
            log_debug_printf(serversetup, "Server enabled%s listener on %s\n",
#ifdef PVXS_ENABLE_OPENSSL
                               iface.isTLS ? " TLS" :
#endif
                              "", iface.name.c_str());
        }
    });
    if(prev_state!=Stopped)
        return;

    // being processing Searches
    for(auto& L : listeners) {
        L->start();
    }

    // begin sending beacons
    acceptor_loop.call([this]()
    {
        timeval immediate = {0,0};
        // send first beacon immediately
        if(event_add(beaconTimer.get(), &immediate))
            log_err_printf(serversetup, "Error enabling beacon timer on\n%s", "");

        state = Running;
    });

    // begin monitoring status
    acceptor_loop.call([this]()
    {
        // monitor first status with initial delay
        if(event_add(cert_file_event_timer.get(), &statusIntervalInitial))
            log_err_printf(serversetup, "Error enabling monitor on\n%s", "");

        state = Running;
    });


}

void Server::Pvt::stop()
{
    log_debug_printf(serversetup, "Server Stopping\n%s", "");

    // Stop sending Beacons
    state_t prev_state;
    acceptor_loop.call([this, &prev_state]()
    {
        prev_state = state;
        if(state!=Running) {
            log_debug_printf(serversetup, "Server not running %d\n", state);
            return;
        }
        state = Stopping;

        if(event_del(beaconTimer.get()))
            log_err_printf(serversetup, "Error disabling beacon timer on\n%s", "");
    });
    if(prev_state!=Running)
        return;

    // stop processing Search requests
    for(auto& L : listeners) {
        L->stop();
    }

    acceptor_loop.call([this]()
    {
        // stop accepting new TCP connections
        for(auto& iface : interfaces) {
            if(evconnlistener_disable(iface.listener.get())) {
                log_err_printf(serversetup, "Error disabling listener on %s\n", iface.name.c_str());
            }
            log_debug_printf(serversetup, "Server disabled listener on %s\n", iface.name.c_str());
        }

        // close current TCP connections
        auto conns = std::move(connections);
        for(auto& pair : conns) {
            pair.second->disconnect();
            pair.second->cleanup();
        }

        state = Stopped;
    });

    /* Cycle through once more to ensure any callbacks queue during the previous call have completed.
     * TODO: this is partly a crutch as eg. SharedPV::attach() binds strong self references
     *       into on*() lambdas, which indirectly hold references keeping acceptor_loop alive.
     */
    acceptor_loop.sync();
}

void Server::Pvt::onSearch(const UDPManager::Search& msg)
{
    // on UDPManager worker

    for(const auto& addr : ignoreList) { // expected to be a short list
        if(msg.src.family()!=addr.family()) {
            // skip
        } else if(msg.src->in.sin_addr.s_addr != addr->in.sin_addr.s_addr) {
            // skip
        } else if(addr->in.sin_port==0) {
            // ignore all ports
            return;
        } else if(msg.src->in.sin_port == addr->in.sin_port) {
            // ignore specific sender port
            return;
        }
    }

    log_debug_printf(serverio, "%s searching\n", msg.src.tostring().c_str());

    searchOp._names.resize(msg.names.size());
    for(auto i : range(msg.names.size())) {
        searchOp._names[i]._name = msg.names[i].name;
        searchOp._names[i]._claim = false;
    }
    ipAddrToDottedIP(&msg.server->in, searchOp._src, sizeof(searchOp._src));

    {
        auto G(sourcesLock.lockReader());
        for(const auto& pair : sources) {
            try {
                pair.second->onSearch(searchOp);
            }catch(std::exception& e){
                log_exc_printf(serversetup, "Unhandled error in Source::onSearch for '%s' : %s\n",
                           pair.first.second.c_str(), e.what());
            }
        }
    }

    uint16_t nreply = 0;
    for(const auto& name : searchOp._names) {
        log_debug_printf(serverio, "  %sclaim %s\n",
                         name._claim ? "" : "dis",
                         name._name);
        if(name._claim)
            nreply++;
    }

    // "pvlist" breaks unless we honor mustReply flag
    if(nreply==0 && !msg.mustReply && (msg.protoTCP || msg.protoTLS))
        return;

    VectorOutBuf M(true, searchReply);

    M.skip(8, __FILE__, __LINE__); // fill in header after body length known

    _to_wire<12>(M, effective.guid.data(), false, __FILE__, __LINE__);
    to_wire(M, msg.searchID);
    to_wire(M, SockAddr::any(AF_INET));
#ifdef PVXS_ENABLE_OPENSSL
    if(msg.protoTLS && tls_context && effective.tls_port) {
        to_wire(M, uint16_t(effective.tls_port));
        to_wire(M, "tls");
    } else
#endif
    { // protoTCP
        to_wire(M, uint16_t(effective.tcp_port));
        to_wire(M, "tcp");
    }
    // "found" flag
    to_wire(M, uint8_t(nreply!=0 ? 1 : 0));

    to_wire(M, uint16_t(nreply));
    for(auto i : range(msg.names.size())) {
        if(searchOp._names[i]._claim) {
            to_wire(M, uint32_t(msg.names[i].id));
            log_debug_printf(serversearch, "Search claimed '%s'\n", msg.names[i].name);
        }
    }
    auto pktlen = M.save()-searchReply.data();

    // now going back to fill in header
    FixedBuf H(true, searchReply.data(), 8);
    to_wire(H, Header{CMD_SEARCH_RESPONSE, pva_flags::Server, uint32_t(pktlen-8)});

    if(!M.good() || !H.good()) {
        log_crit_printf(serverio, "Logic error in Search buffer fill\n%s", "");
    } else {
        (void)msg.reply(searchReply.data(), pktlen);
    }
}

void Server::Pvt::doBeacons(short evt)
{
    log_debug_printf(serversetup, "Server beacon timer expires\n%s", "");

    VectorOutBuf M(true, beaconMsg);
    M.skip(8, __FILE__, __LINE__); // fill in header after body length known

    _to_wire<12>(M, effective.guid.data(), false, __FILE__, __LINE__);
    to_wire(M, uint8_t(0u)); // flags (aka. QoS, aka. undefined)
    to_wire(M, uint8_t(beaconSeq++)); // sequence
    to_wire(M, uint16_t(beaconChange));// change count

    to_wire(M, SockAddr::any(AF_INET));
    to_wire(M, uint16_t(effective.tcp_port));
    to_wire(M, "tcp");
    // "NULL" serverStatus
    to_wire(M, uint8_t(0xff));

    size_t pktlen = M.save()-beaconMsg.data();

    // now going back to fill in header
    FixedBuf H(true, beaconMsg.data(), 8);
    to_wire(H, Header{CMD_BEACON, pva_flags::Server, uint32_t(pktlen-8)});

    assert(M.good() && H.good());

    for(const auto& dest : beaconDest) {
        auto& sender = dest.addr.family()==AF_INET ? beaconSender4 : beaconSender6;
        sender.mcast_prep_sendto(dest);

        int ntx = sendto(sender.sock, (char*)beaconMsg.data(), pktlen, 0, &dest.addr->sa, dest.addr.size());

        if(ntx<0) {
            int err = evutil_socket_geterror(sender.sock);
            auto lvl = Level::Warn;
            if(err==EINTR || err==EPERM)
                lvl = Level::Debug;
            log_printf(serverio, lvl, "Beacon tx error (%d) %s\n",
                       err, evutil_socket_error_to_string(err));

        } else if(unsigned(ntx)<pktlen) {
            log_warn_printf(serverio, "Beacon truncated %u < %u",
                       unsigned(ntx), unsigned(pktlen));

        } else {
            log_debug_printf(serverio, "Beacon tx to %s\n", std::string(SB()<<dest).c_str());
        }
    }

    // mimic pvAccessCPP server (almost)
    // send a "burst" of beacons, then fallback to a longer interval
    timeval interval(beaconIntervalLong);
    if(beaconCnt<10u) {
        interval = beaconIntervalShort;
        beaconCnt++;
    }
    if(event_add(beaconTimer.get(), &interval))
        log_err_printf(serversetup, "Error re-enabling beacon timer on\n%s", "");
}

void Server::Pvt::doBeaconsS(evutil_socket_t fd, short evt, void *raw)
{
    try {
        static_cast<Pvt*>(raw)->doBeacons(evt);
    }catch(std::exception& e){
        log_exc_printf(serverio, "Unhandled error in beacon timer callback: %s\n", e.what());
    }
}

#ifdef PVXS_ENABLE_OPENSSL
void Server::Pvt::doCertFileEventhandler(evutil_socket_t fd, short evt, void *raw) {
    try {
        timeval interval(statusIntervalShort);
        auto pvt = static_cast<Pvt*>(raw);
        // If a custom file event callback has been set then call it
        auto run_default_file_event_callback = true;
        if ( pvt->cert_file_event_callback) {
            run_default_file_event_callback = pvt->cert_file_event_callback(evt);
        }
        // Running default file event callback can be disabled by custom callback returning false
        if ( run_default_file_event_callback)
            pvt->defaultCertFileEventCallback(evt);

        // Re add the timer
        if(event_add(pvt->cert_file_event_timer.get(), &interval))
            log_err_printf(serversetup, "Error re-enabling cert file event timer on\n%s", "");
    }catch(std::exception& e){
        log_exc_printf(serverio, "Unhandled error in cert file event timer callback: %s\n", e.what());
    }
}

/**
 * @brief The default certificate file event callback
 * @param evt
 * @return false to signify that no more cert file callbacks must be called in this loop
 */
bool Server::Pvt::defaultCertFileEventCallback(short evt) {
    if ( paths_to_watch.empty()) {
        log_debug_printf(watcher, "File Watcher Event: %s\n", "Initializing");
        // Initialize a vector of file paths to watch
        paths_to_watch = {effective.tls_cert_filename, effective.tls_cert_password,
                          effective.tls_private_key_filename, effective.tls_private_key_password};

        // Initialize the last write times
        last_write_times.resize(paths_to_watch.size(), 0);
        for (size_t i = 0; i < paths_to_watch.size(); ++i) {
            if (!paths_to_watch[i].empty()) {
                try {
                    last_write_times[i] =  certs::P12FileWatcher::getFileModificationTime(paths_to_watch[i]);
                } catch (...) {
                }
            }
        }
        log_debug_printf(watcher, "File Watcher Event: %s\n", "Initialised");
    }

    log_debug_printf(watcher, "File Watcher Event: %s\n", "Wake up");
    for (size_t i = 0; i < paths_to_watch.size(); ++i) {
        if (!paths_to_watch[i].empty()) {
            time_t current_write_time;
            try {
                current_write_time = certs::P12FileWatcher::getFileModificationTime(paths_to_watch[i]);
            } catch (...) {
                if (last_write_times[i] != 0) {
                    log_debug_printf(watcher, "File Watcher: %s file was deleted\n", paths_to_watch[i].c_str());
                    reconfigureContext(effective);
                    paths_to_watch.clear();
                    break;
                }
                continue;
            }
            if (current_write_time != last_write_times[i]) {
                log_debug_printf(watcher, "File Watcher: %s file was updated\n", paths_to_watch[i].c_str());
                reconfigureContext(effective);
                paths_to_watch.clear();
                break;
            }
        }
    }
    log_debug_printf(watcher, "File Watcher Event: %s\n", "Sleep");

    return false;
}

X509 * Server::Pvt::getCert(ossl::SSLContext *context_ptr) {
    auto context = context_ptr == nullptr ? &tls_context : context_ptr;
    if (!context->ctx)
        return nullptr;

    return SSL_CTX_get0_certificate(context->ctx);
}


/**
 * @brief Starts two monitors for certificate status
 *
 * One monitors any changes to the configured certs files.  If any of them change
 * then the context is reconfigured.
 *
 * The other monitors any changes to certificate status.  If status becomes VALID,
 * EXPIRES or is REVOKED then the context is reconfigured.
 *
 * @param configuration The config for the certs files
 * @param context the current SSL context
 */

void Server::Pvt::watchStatus(const Config& new_config) {
    auto ctx_cert = getCert();
    if (!ctx_cert)
        return;

    auto cert = ossl_ptr<X509>(X509_dup(ctx_cert));
    auto status_uri = std::string();
    try {
        status_uri = certs::CertStatusManager::getStatusPvFromCert(cert);
    } catch (...) {
        log_debug_printf(watcher, "Status Monitor: %s\n", "Not Required");
        return;
    }
    log_info_printf(watcher, "Status Monitor: %s\n", status_uri.c_str());

    // Configure a status listener to listen for certificate status changes
    server_status_listener_ = std::make_shared<certs::StatusListener>(watcher, sl_stop_flag_, std::move(cert), [this, ctx_cert, new_config]() {
        statusListenerCallback(new_config, ctx_cert);
    });
    // Start the listener
    auto cert_status = server_status_listener_->startListening();

    // If certificate is not valid
    if ( cert_status.status != certs::VALID ) {
        log_debug_printf(watcher, "Invalid certificate state: %s\n", cert_status.status.s.c_str());
        throw std::runtime_error(SB() << "Invalid certificate state: " << cert_status.status.s);
    }
}

void Server::Pvt::statusListenerCallback(const Config &new_config, X509 *ctx_cert) {
    try {
        auto new_context = ossl::SSLContext::for_server(new_config);
        auto new_server = reconfigureContext(new_config); // TODO use new server
        // If no new cert stop listening
        auto new_cert = getCert();
        if ( !new_cert ) {
            log_err_printf(watcher, "TLS Debug Disabled: No certificate%s\n", "");
            // Don't wait for it to finish because we are calling from within it so
            // we need to avoid deadlock
            server_status_listener_->stopListening(false);

            // Note that the listener can be restarted if a cert file changes
        } else if ( certs::CertStatusManager::getSerialNumber(ctx_cert) != certs::CertStatusManager::getSerialNumber(new_cert) ) {
            // If different then change the cert we are listening to
            auto cert = ossl_ptr<X509>(X509_dup(getCert()));
            server_status_listener_->changeCert(std::move(cert));
        }
    } catch (std::exception& e) {
        log_warn_printf(watcher, "TLS disabled for server: %s\n", e.what());
        // If no cert then stop listening
        if (!getCert()) {
            server_status_listener_->stopListening(false);
        }
    }
    auto new_context = ossl::SSLContext::for_server(new_config);
    log_debug_printf(watcher, "Server reconfigure: %s\n", "Status change");
    auto new_server = reconfigureContext(new_config); // TODO use new server
}

Server Server::Pvt::reconfigureContext(const Config& configuration) {
    Pvt::state_t prev_state;
    acceptor_loop.call([this, &prev_state]() {
        prev_state = state;
    });

    bool was_running = prev_state==Pvt::Running || prev_state==Pvt::Starting;

    if(was_running)
        stop();

    decltype(sources) transfers;
    decltype(builtinsrc) builtin;

    // copy all Source, including builtin
    {
        auto G(sourcesLock.lockReader());

        transfers = sources;
        builtin = builtinsrc;
    }

    // build up a new, empty, server
    Server newsrv(configuration);
    {
        auto G(sourcesLock.lockWriter());

        sources = transfers;
        builtinsrc = builtin;
    }

    if(was_running) {
        start();
        log_info_printf(watcher, "Resuming Server after Reconfiguration%s", "\n");
    }
    return newsrv;
}


#endif

Source::~Source() {}

Source::List Source::onList() {
    return Source::List{};
}

void Source::show(std::ostream& strm)
{
    auto list(onList());
    strm<<(list.dynamic ? "Dynamic":"")<<"Source";
    Indented I(strm);
    if(list.names) {
        for(auto& name : *list.names) {
            strm<<"\n"<<indent{}<<name;
        }
    }
}

OpBase::~OpBase() {}

ChannelControl::~ChannelControl() {}

ConnectOp::~ConnectOp() {}
ExecOp::~ExecOp() {}

MonitorControlOp::~MonitorControlOp() {}
MonitorSetupOp::~MonitorSetupOp() {}

}} // namespace pvxs::server
