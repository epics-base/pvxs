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

#include <epicsVersion.h>
#include <epicsEvent.h>
#include <epicsGetopt.h>
#include <osiSock.h>

#include <pvxs/log.h>
#include <pvxs/util.h>

#include <udp_collector.h>
#include <utilpvt.h>
#include <pvaproto.h>

namespace pva = pvxs;
namespace {

DEFINE_LOGGER(out, "pvxvct");

// parse hostname, IP, or IP+netmask
std::pair<uint32_t, uint32_t>
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

    return std::make_pair(addr.s_addr, mask.s_addr);
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
               "  -V               Print version and exit.\n"
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
            bool verbose = false;
            bool client = false, server = false;
            // IP, netmask
            // stored in network byte order
            std::vector<std::pair<uint32_t, uint32_t>> peers;
            std::set<std::string> pvnames;

            bool allowPeer(const pva::SockAddr& peer) {
                if(peers.empty())
                    return true;
                if(peer.family()!=AF_INET)
                    return false;
                for(auto& pair : peers) {
                    if((peer->in.sin_addr.s_addr & pair.second) == pair.first) {
                        return true;
                    }
                }
                return false;
            }
        } opts;

        std::vector<pva::SockAddr> bindaddrs;

        {
            int opt;
            while ((opt = getopt(argc, argv, "hVvCSH:B:P:")) != -1) {
                switch(opt) {
                case 'h':
                    usage(argv[0]);
                    return 0;
                case 'V':
                    std::cout<<pvxs::version_information;
                    return 0;
                default:
                    usage(argv[0]);
                    std::cerr<<"\nUnknown argument: "<<char(opt)<<std::endl;
                    return 1;
                case 'v':
                    opts.verbose = true;
                    break;
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

        pva::logger_level_set("pvxvct", opts.verbose ? pvxs::Level::Debug : pvxs::Level::Info);
        pva::logger_config_env(); // from $PVXS_LOG

        log_debug_printf(out, "Show Search: %s\nShow Beacon: %s\n", opts.client?"yes":"no", opts.server?"yes":"no");
        if(opts.client && opts.pvnames.empty()) {
            log_debug_printf(out, "Show all PV names\n%s", "");
        } else {
            for(const auto& name : opts.pvnames) {
                log_debug_printf(out, "Show PV: %s\n", name.c_str());
            }
        }
        if(opts.peers.empty()) {
            log_debug_printf(out, "No peer filter\n%s", "");

        } else if(out.test(pvxs::Level::Debug)) {
            for(const auto& tup : opts.peers) {
                in_addr addr, netmask;
                std::tie(addr.s_addr, netmask.s_addr) = tup;
                char abuf[16];
                char nbuf[16];
                evutil_inet_ntop(AF_INET, &addr, abuf, sizeof(abuf));
                evutil_inet_ntop(AF_INET, &netmask, nbuf, sizeof(nbuf));
                log_debug_printf(out, "Show from %s/%s\n", abuf, nbuf);
            }
        }

        auto searchCB = [&opts](const pva::UDPManager::Search& msg)
        {
            if(!opts.client || !opts.allowPeer(msg.src))
                return;

            if(!opts.pvnames.empty()) {
                bool show = false;
                for(const auto pv : msg.names) {
                    show = opts.pvnames.find(pv.name)!=opts.pvnames.end();
                    if((show = opts.pvnames.find(pv.name)!=opts.pvnames.end()))
                        break;
                }
                if(!show)
                    return;
            }
            log_info_printf(out, "%s Searching for:\n", msg.src.tostring().c_str());
            for(const auto pv : msg.names) {
                log_info_printf(out, "  \"%s\"\n", pv.name);
            }
        };

        auto beaconCB = [&opts](const pva::UDPManager::Beacon& msg)
        {
            if(!opts.server || !opts.allowPeer(msg.src))
                return;

            const auto& guid = msg.guid;
            log_info_printf(out, "%s\n",
                            std::string(pva::impl::SB()<<msg.src<<" Beacon "<<guid<<' '<<msg.server).c_str());

        };

        std::vector<std::pair<std::unique_ptr<pva::UDPListener>, std::unique_ptr<pva::UDPListener>>> listeners;
        listeners.reserve(bindaddrs.size());

        for(auto& baddr : bindaddrs) {
            auto manager = pva::UDPManager::instance();
            listeners.emplace_back(manager.onSearch(baddr, searchCB),
                                   manager.onBeacon(baddr, beaconCB));
            listeners.back().first->start();
            listeners.back().second->start();
            log_debug_printf(out, "Bind: %s\n", baddr.tostring().c_str());
        }


        epicsEvent done;
        pva::SigInt handle([&done](){
            done.signal();
        });

        done.wait();
        log_info_printf(out, "Done\n%s", "");

        errlogFlush();
        return 0;
    }catch(std::runtime_error& e) {
        errlogFlush();
        std::cerr<<"Error: "<<e.what()<<std::endl;
        return 1;
    }
}
