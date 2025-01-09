/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_NETCOMMON_H
#define PVXS_NETCOMMON_H

#if !defined(PVXS_CLIENT_H) && !defined(PVXS_SERVER_H) && !defined(PVXS_SRVCOMMON_H)
#  error Do not include netcommon.h directly
#endif

#include <list>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <pvxs/config.h>
#include <pvxs/version.h>

#ifdef PVXS_ENABLE_OPENSSL
using CustomServerCallback = std::function<void(short)>;
static constexpr timeval kCustomCallbackIntervalInitial{0, 0};
static constexpr timeval kCustomCallbackInterval{15, 0};
#endif

namespace pvxs {

/** Credentials presented by a client or server.
 *
 * Primarily a way of presenting peer address and a remote account name.
 * The ``method`` gives the authentication sub-protocol used and is presently one of:
 *
 * - "x509" - Peer certificate.  Common Names of root CA and peer used as authority and account.
 * - "ca" - Client provided account name.
 * - "anonymous" - Client provided no credentials.  account will also be "anonymous".
 *
 * @since UNRELEASED
 */
struct PVXS_API PeerCredentials {
    //! Peer address (eg. numeric IPv4)
    std::string peer;
    //! The local interface address (eg. numeric IPv4) through which this client is connected.
    //! May be a wildcard address (eg. 0.0.0.0) if the receiving socket is so bound.
    std::string iface;
    //! How account was authenticated. ("anonymous", "ca", or "x509")
    std::string method;
    //! Who vouches for this account.
    //!
    //! Empty for "anonymous" and "ca" methods.
    //! For "x509" method, common name of the root CA.
    //! @since UNRELEASED
    std::string authority;
    //! Remote user account name.  Meaning depends upon method.
    std::string account;
    /** Lookup (locally) roles associated with the account.
     *
     * On *nix targets this is the list of primary and secondary groups
     * in which the account is a member.
     * On Windows targets this returns the list of local groups for the account.
     * On other targets, an empty list is returned.
     */
    std::set<std::string> roles() const;

#ifdef PVXS_ENABLE_OPENSSL
    /** Operation over secure transport
     * @since UNRELEASED
     */
    bool isTLS = false;
#endif
};

PVXS_API
std::ostream& operator<<(std::ostream&, const PeerCredentials&);

namespace impl {
struct Report;
struct ReportInfo;
}
namespace server {
struct ClientCredentials;
using impl::Report;
using impl::ReportInfo;
}
namespace client {
using impl::Report;
using impl::ReportInfo;
}
namespace impl {

#ifdef PVXS_EXPERT_API_ENABLED

/** Snapshot of information about a client/server
 *
 * cf. pvxs::server::Server::report() and pvxs::client::Context::report()
 *
 * @since 0.2.0
 */
struct Report {
    //! Info for a single channel (to a particular PV name on a particular server)
    struct Channel {
        //! Channel name.  aka. PV name
        std::string name;
        //! transmit and receive counters in bytes
        size_t tx{}, rx{};
        //! Contextual information (maybe) supplied by the Source
        std::shared_ptr<const ReportInfo> info;
    };

    //! Info for a single connection to remote peer
    struct Connection {
        //! peer endpoint (eg. IPv4 address and port)
        std::string peer;
        //! Credentials presented by peer.  Only from Server::report()
        std::shared_ptr<const server::ClientCredentials> credentials;
        //! transmit and receive counters in bytes
        size_t tx{}, rx{};
        //! Channels currently connected through this socket
        std::list<Channel> channels;
    };

    //! Currently open sockets
    std::list<Connection> connections;
};

struct PVXS_API ReportInfo {
    ReportInfo() = default;
    ReportInfo(const ReportInfo&) = delete;
    ReportInfo& operator=(const ReportInfo&) = delete;
    virtual ~ReportInfo();
};

#endif // PVXS_EXPERT_API_ENABLED

} // namespace impl
} // namespace pvxs

#endif // PVXS_NETCOMMON_H
