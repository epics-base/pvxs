/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <winsock2.h>
#include <iphlpapi.h>

#include "osiSockExt.h"

#include <mswsock.h>

#include <vector>

#include <pvxs/log.h>
#include "evhelper.h"

#include <epicsThread.h>
#include <cantProceed.h>

#  include <windows.h>
#  include <psapi.h>

static
bool is_wine()
{
    HMODULE nt = GetModuleHandle("ntdll.dll");
    return nt && GetProcAddress(nt, "wine_get_version");
}

namespace pvxs {

DEFINE_LOGGER(log, "pvxs.util");
DEFINE_LOGGER(logiface, "pvxs.iface");

static
LPFN_WSARECVMSG WSARecvMsg;

static
epicsThreadOnceId oseOnce = EPICS_THREAD_ONCE_INIT;

static
void oseDoOnce(void*)
{
    evsocket dummy(AF_INET, SOCK_DGRAM, 0);
    GUID guid      = WSAID_WSARECVMSG;
    DWORD nout;

    if(WSAIoctl(dummy.sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guid, sizeof(guid),
                &WSARecvMsg, sizeof(WSARecvMsg),
                &nout, nullptr, nullptr))
    {
        cantProceed("Unable to get &WSARecvMsg: %d", WSAGetLastError());
    }
    if(!WSARecvMsg)
        cantProceed("Unable to get &WSARecvMsg!!");

    evsocket::canIPv6 = evsocket::init_canIPv6();
    evsocket::ipstack = is_wine() ? evsocket::Linsock : evsocket::Winsock;
}

void osiSockAttachExt()
{
    osiSockAttach();
    epicsThreadOnce(&oseOnce, &oseDoOnce, nullptr);
}

void evsocket::enable_SO_RXQ_OVFL() const {}

void evsocket::enable_IP_PKTINFO() const
{
    if(af==AF_INET) {
        int val = 1;
        if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, (char*)&val, sizeof(val)))
            log_warn_printf(log, "Unable to set IP_PKTINFO: %d\n", SOCKERRNO);

    } else if(af==AF_INET6) {
        int val = 1;
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, (char*)&val, sizeof(val)))
            log_warn_printf(log, "Unable to set IPV6_RECVPKTINFO: %d\n", SOCKERRNO);
    }
}

int recvfromx::call()
{
    ndrop = 0u;
    dstif = -1;

    WSAMSG msg{};

    WSABUF iov = {(ULONG)buflen, (char*)buf};
    msg.lpBuffers = &iov;
    msg.dwBufferCount = 1u;

    msg.name = &(*src)->sa;
    msg.namelen = src->size();

    // will receive either in6_pktinfo or in_pktinfo, not both.  in6_pktinfo is larger
    alignas (WSACMSGHDR) char cbuf[WSA_CMSG_SPACE(sizeof(in6_pktinfo))];
    msg.Control = {sizeof(cbuf), cbuf};

    DWORD nrx=0u;
    if(!WSARecvMsg(sock, &msg, &nrx, nullptr, nullptr)) {
        if(msg.dwFlags & MSG_CTRUNC)
            log_debug_printf(log, "MSG_CTRUNC %lu, %lu\n",
                             (unsigned long)msg.Control.len, (unsigned long)sizeof(cbuf));

        for(WSACMSGHDR *hdr = WSA_CMSG_FIRSTHDR(&msg); hdr ; hdr = WSA_CMSG_NXTHDR(&msg, hdr)) {
            if(hdr->cmsg_level==IPPROTO_IP && hdr->cmsg_type==IP_PKTINFO && hdr->cmsg_len>=WSA_CMSG_LEN(sizeof(in_pktinfo))) {
                if(dst) {
                    (*dst)->in.sin_family = AF_INET;
                    memcpy(&(*dst)->in.sin_addr, WSA_CMSG_DATA(hdr) + offsetof(in_pktinfo, ipi_addr), sizeof(IN_ADDR));
                }

                decltype(in_pktinfo::ipi_ifindex) idx;
                memcpy(&idx, WSA_CMSG_DATA(hdr) + offsetof(in_pktinfo, ipi_ifindex), sizeof(idx));
                dstif = idx;
            }
            else if(hdr->cmsg_level==IPPROTO_IPV6 && hdr->cmsg_type==IPV6_PKTINFO && hdr->cmsg_len>=WSA_CMSG_LEN(sizeof(in6_pktinfo))) {
                if(dst) {
                    (*dst)->in6.sin6_family = AF_INET6;
                    memcpy(&(*dst)->in6.sin6_addr, WSA_CMSG_DATA(hdr) + offsetof(in6_pktinfo, ipi6_addr), sizeof(in6_addr));
                }

                decltype(in6_pktinfo::ipi6_ifindex) idx;
                memcpy(&idx, WSA_CMSG_DATA(hdr) + offsetof(in6_pktinfo, ipi6_ifindex), sizeof(idx));
                dstif = idx;
            }
        }

        return nrx;

    } else {
        return -1;
    }
}

namespace impl {

#ifndef GAA_FLAG_INCLUDE_ALL_INTERFACES
#  define GAA_FLAG_INCLUDE_ALL_INTERFACES 0
#endif

decltype (IfaceMap::byIndex) IfaceMap::_refresh() {
    std::vector<char> ifaces(1024u);
    decltype (byIndex) temp;

    {
        constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST
                |GAA_FLAG_SKIP_MULTICAST
                |GAA_FLAG_SKIP_DNS_SERVER
                |GAA_FLAG_INCLUDE_PREFIX
                |GAA_FLAG_INCLUDE_ALL_INTERFACES;

        ULONG buflen = ifaces.size();
        auto err = GetAdaptersAddresses(AF_INET, flags, 0, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(ifaces.data()), &buflen);

        if(err == ERROR_BUFFER_OVERFLOW) {
            // buflen updated with necessary length, retry
            ifaces.resize(buflen);

            err = GetAdaptersAddresses(AF_INET, flags, 0, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(ifaces.data()), &buflen);
        }

        if(err) {
            log_warn_printf(logiface, "Unable to GetAdaptersAddresses() error=%lu\n", (unsigned long)err);
            return temp;
        }
    }

    for(auto iface = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(ifaces.data()); iface ; iface = iface->Next) {
        const char* ifName = iface->AdapterName;
        if(!ifName)
            ifName = "<AdapterName==NULL>";

        if(!(iface->OperStatus & IfOperStatusUp))
            continue; // not configured, skip...

        // TODO: IfIndex vs. Ipv6IfIndex which one to use?

        bool isLO = iface->IfType==IF_TYPE_SOFTWARE_LOOPBACK;
        auto pair = temp.emplace(std::piecewise_construct,
                                 std::forward_as_tuple(iface->IfIndex),
                                 std::forward_as_tuple(ifName, iface->IfIndex, isLO));

        auto& info = pair.first->second;

        // find the IPv4 broadcast address, if any
        std::set<std::pair<SockAddr, SockAddr>> prefixes;
        for(auto prefix = iface->FirstPrefix; prefix; prefix = prefix->Next) {
            SockAddr addr(prefix->Address.lpSockaddr);
            auto p = prefix->PrefixLength;

            if(addr.family()!=AF_INET || p<=0u || p>=32u)
                continue;

            sockaddr_in mask{AF_INET};
            mask.sin_addr.s_addr = htonl(0xffffffff<<(32u-p));
            auto pair = prefixes.emplace(addr, (sockaddr*)&mask);

            log_debug_printf(logiface, "Prefix %s/%s\n", addr.tostring().c_str(), pair.first->second.tostring().c_str());
        }

        for(auto addr = iface->FirstUnicastAddress; addr; addr = addr->Next) {
            const auto af = addr->Address.lpSockaddr->sa_family;
            if(af!=AF_INET && af!=AF_INET6) {
                log_debug_printf(logiface, "Ignoring interface '%s' address family=%d\n",
                                 ifName, af);
                continue;
            }

            SockAddr iaddr(addr->Address.lpSockaddr);
            SockAddr bcast;
            if(iaddr.family()==AF_INET && !isLO) {
                auto A = ntohl(iaddr->in.sin_addr.s_addr);
                for(auto& pair : prefixes) {
                    auto P = ntohl(pair.first->in.sin_addr.s_addr);
                    auto M = ntohl(pair.second->in.sin_addr.s_addr);
                    if((A&M)==P) {
                        auto B = P | ~M;
                        bcast->in.sin_family = AF_INET;
                        bcast->in.sin_addr.s_addr = htonl(B);
                    }
                }
            }

            auto pair = info.addrs.emplace(iaddr, bcast);

            log_debug_printf(logiface, "Found interface %lu \"%s\" w/ %s/%s\n",
                             (unsigned long)iface->IfIndex, ifName,
                             pair.first->first.tostring().c_str(),
                             pair.first->second.tostring().c_str());
        }
    }

    return temp;
}

} // namespace impl

} // namespace pvxs
