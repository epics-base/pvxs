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
}

void osiSockAttachExt()
{
    osiSockAttach();
    epicsThreadOnce(&oseOnce, &oseDoOnce, nullptr);
}

void enable_SO_RXQ_OVFL(SOCKET sock) {}

void enable_IP_PKTINFO(SOCKET sock)
{
    int val = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, (char*)&val, sizeof(val)))
        log_warn_printf(log, "Unable to set IP_PKTINFO: %d\n", SOCKERRNO);
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

    alignas (alignof (WSACMSGHDR)) char cbuf[WSA_CMSG_SPACE(sizeof(in_pktinfo))];
    msg.Control = {sizeof(cbuf), cbuf};

    DWORD nrx=0u;
    if(!WSARecvMsg(sock, &msg, &nrx, nullptr, nullptr)) {
        if(msg.dwFlags & MSG_CTRUNC)
            log_debug_printf(log, "MSG_CTRUNC %zu, %zu\n", msg.Control.len, sizeof(cbuf));

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

void IfaceMap::refresh() {
    std::vector<char> ifaces(1024u);
    decltype (info) temp;

    {
        constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER|GAA_FLAG_INCLUDE_ALL_INTERFACES;

        ULONG buflen = ifaces.size();
        auto err = GetAdaptersAddresses(AF_INET, flags, 0, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(ifaces.data()), &buflen);

        if(err == ERROR_BUFFER_OVERFLOW) {
            // buflen updated with necessary length, retry
            ifaces.resize(buflen);

            err = GetAdaptersAddresses(AF_INET, flags, 0, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(ifaces.data()), &buflen);
        }

        if(err) {
            log_warn_printf(logiface, "Unable to GetAdaptersAddresses() error=%lld\n", (unsigned long long)err);
            return;
        }
    }

    for(auto iface = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(ifaces.data()); iface ; iface = iface->Next) {
        auto& info = temp[iface->IfIndex];

        //TODO: any flags to check?

        for(auto addr = iface->FirstUnicastAddress; addr; addr = addr->Next) {

            if(addr->Address.lpSockaddr->sa_family!=AF_INET)
                continue;

            auto pair = info.emplace(addr->Address.lpSockaddr, sizeof(sockaddr_in));

            log_debug_printf(logiface, "Found interface %lld \"%s\" w/ %s\n",
                             (long long)iface->IfIndex, iface->AdapterName, pair.first->tostring().c_str());
        }
    }

    info.swap(temp);
}

} // namespace impl

} // namespace pvxs
