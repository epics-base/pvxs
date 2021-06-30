#ifndef PVXS_NETCOMMON_H
#define PVXS_NETCOMMON_H

#if !defined(PVXS_CLIENT_H) && !defined(PVXS_SERVER_H)
#  error Include <pvxs/client.h> or <pvxs/server.h>  Do not include netcommon.h directly
#endif

#include <string>
#include <list>

#include <pvxs/version.h>

namespace pvxs {
namespace impl {

#ifdef PVXS_EXPERT_API_ENABLED

/** Snapshot of information about a client/server
 *
 * cf. pvxs::server::Server::report()
 *
 * @since UNRELEASED
 */
struct Report {
    //! Info for a single channel (to a particular PV name on a particular server)
    struct Channel {
        //! Channel name.  aka. PV name
        std::string name;
        //! transmit and receive counters in bytes
        size_t tx{}, rx{};
    };

    //! Info for a single connection to remote peer
    struct Connection {
        //! peer endpoint (eg. IPv4 address and port)
        std::string peer;
        //! transmit and receive counters in bytes
        size_t tx{}, rx{};
        //! Channels currently connected through this socket
        std::list<Channel> channels;
    };

    //! Currently open sockets
    std::list<Connection> connections;
};

} // namespace impl
} // namespace pvxs

#endif // PVXS_EXPERT_API_ENABLED

#endif // PVXS_NETCOMMON_H
