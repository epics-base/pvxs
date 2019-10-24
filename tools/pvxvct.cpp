/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <event2/event.h>

#include <cstring>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <vector>
#include <set>
#include <tuple>
#include <regex>

#if !defined(_WIN32)
#include <signal.h>
#define USE_SIGNAL
#endif

#include <epicsEvent.h>
#include <epicsGetopt.h>
#include <osiSock.h>

#include <pvxs/log.h>

#include <udp_collector.h>
#include <utilpvt.h>
#include <pvaproto.h>

namespace pva = pvxsimpl;
namespace {

DEFINE_LOGGER(out, "pvxvct");

epicsEvent done;

#ifdef USE_SIGNAL
void alldone(int num)
{
    (void)num;
    done.signal();
}
#endif

// parse hostname, IP, or IP+netmask
std::tuple<uint32_t, uint32_t>
parsePeer(const char *optarg)
{
    // nameorip
    // nameorip/##
    // nameorip/###.###.###.###
    // static is safe as we only use from main() thread
    static std::regex netname("([^/:]*)(?:/([0-9.]+))?");

    std::cmatch match;
    if(!std::regex_match(optarg, match, netname)) {
        throw std::runtime_error(pva::SB()<<"Expected host name or IP range.  not "<<optarg);
    }
    in_addr addr, mask;

    if(hostToIPAddr(match[1].str().c_str(), &addr)) {
        throw std::runtime_error(pva::SB()<<"Expected a host name or IP.  not "<<match[1].str());
    }

    mask.s_addr = INADDR_BROADCAST;
    if(match[2].length()) {
        auto smask = match[2].str();
        if(smask.find_first_of('.')!=smask.npos) {
            if(!evutil_inet_pton(AF_INET, smask.c_str(), &mask)) {
                throw std::runtime_error(pva::SB()<<"Expected netmask.  not "<<smask);
            }

        } else {
            // only # of bits.  eg. "/24"
            std::istringstream strm(match[2].str());
            unsigned nbit=0;
            if((strm>>nbit).good()) {
                throw std::runtime_error(pva::SB()<<"Expected number of bits.  not "<<match[2]);
            }
            mask.s_addr = htonl(0xffffffff<<(32-nbit));
        }
    }

    // 1.2.3.4/24 === 1.2.3.0/24
    addr.s_addr &= mask.s_addr;

    return std::make_tuple(addr.s_addr, mask.s_addr);
}

void usage(const char *name)
{
    std::cerr<<"Usage: "<<name<<" [-C|-S] [-B hostip[:port]] [-H hostip]\n"
               "\n"
               "PV Access Virtual Cable Tester\n"
               "\n"
               "Assist in troubleshooting network (mis)configuration by listening\n"
               "for (some) PVA client/server UDP traffic.\n"
               "\n"
               "  -h               Print this message\n"
               "  -C               Show only client Searches\n"
               "  -S               Show only server Beacons\n"
               "  -B hostip[:port] Listen on the given interface(s).  May be repeated.\n"
               "  -H host          Show only message sent from this peer.  May be repeated.\n"
               "  -P pvname        Show only searches for this PV name.  May be repeated.\n"
              <<std::endl;
}

} // namespace

int main(int argc, char *argv[])
{
    try {
        // group options used from callback
        struct {
            bool client = false, server = false;
            // IP, netmask, port
            // stored in network byte order
            std::vector<std::tuple<uint32_t, uint32_t>> peers;
            std::set<std::string> pvnames;
        } opts;

        std::vector<pva::SockAddr> bindaddrs;

        {
            int opt;
            while ((opt = getopt(argc, argv, "hCSH:B:P:")) != -1) {
                switch(opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                default:
                    usage(argv[0]);
                    std::cerr<<"\nUnknown argument: "<<char(opt)<<std::endl;
                    return 1;
                case 'C':
                    opts.client = true;
                    break;
                case 'S':
                    opts.server = true;
                    break;
                case 'B': {
                    pva::SockAddr addr;
                    int slen = addr.size();
                    if(evutil_parse_sockaddr_port(optarg, &addr->sa, &slen)) {
                        throw std::runtime_error(pva::SB()<<"Expected address[:port] to bind.  Not "<<optarg);
                    }
                    if(addr.port()==0)
                        addr.setPort(5076);
                    bindaddrs.push_back(addr);
                }
                    break;
                case 'P':
                    opts.pvnames.insert(optarg);
                    break;
                case 'H':
                    opts.peers.push_back(parsePeer(optarg));
                    break;
                }
            }
        }

        // apply defaults
        if(!opts.client && !opts.server) {
            opts.client = opts.server = true;
        }
        if(bindaddrs.empty()) {
            bindaddrs.emplace_back(pva::SockAddr::any(AF_INET, 5076));
        }

        pva::logger_level_set("pvxvct", PLVL_INFO);
        pva::logger_config_env(); // from $PVXS_LOG

        log_printf(out, PLVL_DEBUG, "Show Search: %s\nShow Beacon: %s\n", opts.client?"yes":"no", opts.server?"yes":"no");
        if(opts.client && opts.pvnames.empty()) {
            log_printf(out, PLVL_DEBUG, "Show all PV names\n");
        } else {
            for(const auto& name : opts.pvnames) {
                log_printf(out, PLVL_DEBUG, "Show PV: %s\n", name.c_str());
            }
        }
        if(opts.peers.empty()) {
            log_printf(out, PLVL_DEBUG, "No peer filter\n");
        } else if(log_test(out, PLVL_DEBUG)) {
            for(const auto& tup : opts.peers) {
                in_addr addr, netmask;
                std::tie(addr.s_addr, netmask.s_addr) = tup;
                char abuf[16];
                char nbuf[16];
                evutil_inet_ntop(AF_INET, &addr, abuf, sizeof(abuf));
                evutil_inet_ntop(AF_INET, &netmask, nbuf, sizeof(nbuf));
                log_printf(out, PLVL_DEBUG, "Show from %s/%s\n", abuf, nbuf);
            }
        }

        auto cb = [&opts](const pva::UDPMsg& msg)
        {
            // later, from worker thread

            // filter by sender
            if(!opts.peers.empty()) {
                if(msg.src.family()!=AF_INET)
                    return;

                bool match = false;
                for(auto& tup : opts.peers) {
                    uint32_t addr, mask;
                    std::tie(addr, mask) = tup;
                    if((msg.src->in.sin_addr.s_addr&mask)==addr) {
                        match = true;
                        break;
                    }
                }
                if(!match)
                    return;
            }

            bool showpeer=false;
            auto lazypeer = [&showpeer, &msg]() {
                if(!showpeer)
                    log_printf(out, PLVL_INFO, "From %s\n", msg.src.tostring().c_str());
                showpeer = true;
            };

            // allow that one UDP packet may contain several PVA messages
            for(unsigned i=0; !msg.msgs[i].empty(); i++)
            {
                auto M = msg.msgs[i];
                auto be = M[2]&pva::pva_flags::MSB;
                auto cmd = M[3];
                M+=4; // skip header
                uint32_t blen;
                pva::from_wire(M, blen, be);

                switch(cmd) {
                case pva::pva_app_msg::OriginTag:
                    log_printf(out, PLVL_WARN, "Peer sends ORIGIN_TAG by unicast/broadcast.\n");
                    break;

                case pva::pva_app_msg::Search: {
                    uint32_t id;
                    uint8_t flags;
                    pva::SockAddr replyAddr;

                    pva::from_wire(M, id, be);
                    pva::from_wire(M, flags, be);
                    M += 3; // unused/reserved

                    pva::from_wire(M, replyAddr, be);
                    uint16_t port = 0;
                    pva::from_wire(M, port, be);
                    replyAddr.setPort(port);

                    // so far, only "tcp" transport has ever been seen.
                    // however, we will consider and ignore any others which might appear
                    bool foundtcp = false;
                    size_t nproto=0;
                    pva::from_wire(M, pva::Size<size_t>(nproto), be);
                    for(size_t i=0; i<nproto && !M.err; i++) {
                        size_t nchar=0;
                        pva::from_wire(M, pva::Size<size_t>(nchar), be);

                        if(M.size()>=3 && nchar==3 && M[0]=='t' && M[1]=='c' && M[2]=='p') {
                            foundtcp = true;
                            M += 3;
                            break;
                        }
                    }
                    if(!foundtcp && !M.err) {
                        // so far, not something which should actually happen
                        log_printf(out, PLVL_DEBUG, "  Search w/o proto \"tcp\"\n");
                        continue;
                    }

                    // one Search message can include many PV names.
                    uint16_t nchan=0;
                    pva::from_wire(M, nchan, be);

                    for(size_t i=0; i<nchan && !M.err; i++) {
                        uint32_t id=0xffffffff; // poison
                        size_t chlen;

                        pva::from_wire(M, id, be);
                        pva::from_wire(M, pva::Size<size_t>(chlen), be);
                        if(opts.client && chlen<=M.size() && !M.err) {
                            std::string pvname(reinterpret_cast<const char*>(M.pos), chlen);
                            if(opts.pvnames.empty() || opts.pvnames.find(pvname)!=opts.pvnames.end()) {
                                lazypeer();
                                log_printf(out, PLVL_INFO, "  Search 0x%08x '%s' (rsvp %s)\n",
                                           unsigned(id), pvname.c_str(), replyAddr.tostring().c_str());
                            }
                        }
                        M += chlen;
                    }

                    break;
                }

                case pva::pva_app_msg::Beacon: {
                    uint8_t guid[12] = {};
                    uint8_t seq =0;
                    pva::SockAddr addr;
                    uint16_t port = 0;

                    pva::_from_wire<sizeof(guid)>(M, guid, false);
                    M += 1; // flags/qos. unused
                    pva::from_wire(M, seq, be);
                    M += 2; // "change" count.  unused
                    pva::from_wire(M, addr, be);
                    pva::from_wire(M, port, be);
                    addr.setPort(port);

                    size_t protolen=0;
                    pva::from_wire(M, pva::Size<size_t>(protolen), be);
                    M += protolen; // ignore string

                    // ignore remaining "server status" blob

                    if(opts.server && !M.err) {
                        lazypeer();
                        log_printf(out, PLVL_INFO, "  Beacon %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %s seq %u\n",
                                   guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7], guid[8], guid[9], guid[10], guid[11],
                                addr.tostring().c_str(), seq);
                    }
                }
                    break;

                default:
                    log_printf(out, PLVL_WARN, "unknown command 0x%02x\n", cmd);
                }

                if(M.err) {
                    log_printf(out, PLVL_ERR, "  Error while decoding\n");
                }
            }
        };

        std::vector<std::unique_ptr<pva::UDPListener>> listeners;
        listeners.reserve(bindaddrs.size());

        for(auto& baddr : bindaddrs) {
            listeners.push_back(pva::UDPManager::instance()
                                .subscribe(baddr, cb));
            log_printf(out, PLVL_DEBUG, "Bind: %s\n", baddr.tostring().c_str());
        }



#ifdef USE_SIGNAL
        signal(SIGINT, alldone);
        signal(SIGTERM, alldone);
        signal(SIGQUIT, alldone);
#endif

        done.wait();
        log_printf(out, PLVL_INFO, "Done\n");

        errlogFlush();
        return 0;
    }catch(std::runtime_error& e) {
        errlogFlush();
        std::cerr<<"Error: "<<e.what()<<std::endl;
        return 1;
    }
}
