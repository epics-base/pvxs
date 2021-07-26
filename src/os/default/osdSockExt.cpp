/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "osiSockExt.h"

#include <string.h>

#include <sys/types.h>
#include <net/if.h>
#include <ifaddrs.h>

#ifdef __rtems__
// missing extern C circa RTEMS 5.1
extern "C" {
#  include <net/if_dl.h>
}
#endif

#include <pvxs/log.h>
#include <evhelper.h>

namespace pvxs {

DEFINE_LOGGER(log, "pvxs.util");
DEFINE_LOGGER(logiface, "pvxs.iface");

void osiSockAttachExt() {}

void enable_SO_RXQ_OVFL(SOCKET sock)
{
#ifdef SO_RXQ_OVFL
    // Linux specific feature exposes OS dropped packet count
    int val = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_RXQ_OVFL, (char*)&val, sizeof(val)))
        log_warn_printf(log, "Unable to set SO_RXQ_OVFL: %d\n", SOCKERRNO);

#endif
}

void enable_IP_PKTINFO(SOCKET sock)
{
    /* linux, some *BSD's (OSX), and winsock package both destination address (from ip header)
     * and receiving interface index (from host) into one IP_PKTINFO control message.
     * Remaining *BSD's can deliver these in separate IP_ORIGDSTADDR and IP_RECVIF messages.
     */
#ifdef IP_PKTINFO
    int val = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, (char*)&val, sizeof(val)))
        log_warn_printf(log, "Unable to set IP_PKTINFO: %d\n", SOCKERRNO);

#else
#  ifdef IP_ORIGDSTADDR
    {
        int val = 1;
        if(setsockopt(sock, IPPROTO_IP, IP_ORIGDSTADDR, (char*)&val, sizeof(val)))
            log_warn_printf(log, "Unable to set IP_ORIGDSTADDR: %d\n", SOCKERRNO);
    }

#  endif
#  ifdef IP_RECVIF
    {
        int val = 1;
        if(setsockopt(sock, IPPROTO_IP, IP_RECVIF, (char*)&val, sizeof(val)))
            log_warn_printf(log, "Unable to set IP_RECVIF: %d\n", SOCKERRNO);
    }
#  endif
#endif
}

int recvfromx::call()
{
    msghdr msg{};

    iovec iov = {buf, buflen};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1u;

    msg.msg_name = &(*src)->sa;
    msg.msg_namelen = src ? src->size() : 0u;

    alignas (alignof (cmsghdr)) char cbuf[0u
#ifdef SO_RXQ_OVFL
            + CMSG_SPACE(sizeof(ndrop))
#endif
#ifdef IP_PKTINFO
            + CMSG_SPACE(sizeof(in_pktinfo))
#else
#  if defined(IP_ORIGDSTADDR)
            + CMSG_SPACE(sizeof(sockaddr_in))
#  endif
#  if defined(IP_RECVIF)
            + CMSG_SPACE(sizeof(sockaddr_dl))
#  endif
#endif
            ];
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    if(dst)
        *dst = SockAddr();
    dstif = -1;
    ndrop = 0u;

    int ret = recvmsg(sock, &msg, 0);

    if(ret>=0) { // on success, check for control messages
        if(msg.msg_flags & MSG_CTRUNC)
            log_warn_printf(log, "MSG_CTRUNC, expand buffer %zu <- %zu\n", msg.msg_controllen, sizeof(cbuf));

        for(cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr ; hdr = CMSG_NXTHDR(&msg, hdr)) {
            if(0) {}
#ifdef SO_RXQ_OVFL
            else if(hdr->cmsg_level==SOL_SOCKET && hdr->cmsg_type==SO_RXQ_OVFL && hdr->cmsg_len>=CMSG_LEN(sizeof(ndrop))) {
                memcpy(&ndrop, CMSG_DATA(hdr), sizeof(ndrop));
            }
#endif
#ifdef IP_PKTINFO
            else if(hdr->cmsg_level==IPPROTO_IP && hdr->cmsg_type==IP_PKTINFO && hdr->cmsg_len>=CMSG_LEN(sizeof(in_pktinfo))) {
                if(dst) {
                    (*dst)->in.sin_family = AF_INET;
                    memcpy(&(*dst)->in.sin_addr, CMSG_DATA(hdr) + offsetof(in_pktinfo, ipi_addr), sizeof(in_addr_t));
                }

                decltype(in_pktinfo::ipi_ifindex) idx;
                memcpy(&idx, CMSG_DATA(hdr) + offsetof(in_pktinfo, ipi_ifindex), sizeof(idx));
                dstif = idx;
            }

#else
#  ifdef IP_ORIGDSTADDR
            else if(dst && hdr->cmsg_level==IPPROTO_IP && hdr->cmsg_type==IP_ORIGDSTADDR && hdr->cmsg_len>=CMSG_LEN(sizeof(sockaddr_in))) {
                memcpy(&(*dst)->in, CMSG_DATA(hdr), sizeof(sockaddr_in));
            }
#  endif
#  ifdef IP_RECVIF
            else if(dst && hdr->cmsg_level==IPPROTO_IP && hdr->cmsg_type==IP_RECVIF && hdr->cmsg_len>=CMSG_LEN(sizeof(sockaddr_dl))) {
                decltype (sockaddr_dl::sdl_index) idx;
                memcpy(&idx, CMSG_DATA(hdr) + offsetof(sockaddr_dl, sdl_index), sizeof(idx));
                dstif = idx;
            }
#  endif
#endif
        }
    }

    return ret;
}

namespace impl {

void IfaceMap::refresh() {
    ifaddrs* addrs = nullptr;

    decltype (info) temp;

    if(getifaddrs(&addrs)) {
        log_warn_printf(logiface, "Unable to getifaddrs() errno=%d\n", errno);
        return;
    }

    try {
        for(const ifaddrs* ifa = addrs; ifa; ifa = ifa->ifa_next) {
            if(ifa->ifa_addr->sa_family!=AF_INET) {
                log_debug_printf(logiface, "Ignoring interface '%s' address !ipv4\n", ifa->ifa_name);
                continue;
            }

            auto idx(if_nametoindex(ifa->ifa_name));
            if(idx<=0) {
                log_warn_printf(logiface, "Unable to find index of interface '%s'\n", ifa->ifa_name);
                continue;
            }

            //TODO: any flags to check?

            auto pair = temp[idx].emplace(ifa->ifa_addr, sizeof(sockaddr_in));

            log_debug_printf(logiface, "Found interface %lld \"%s\" w/ %s\n",
                             (long long)idx, ifa->ifa_name, pair.first->tostring().c_str());
        }

    } catch(...){
        freeifaddrs(addrs);
        throw;
    }
    freeifaddrs(addrs);

    info.swap(temp);
}

} // namespace impl

} // namespace pvxs
