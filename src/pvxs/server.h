/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_SERVER_H
#define PVXS_SERVER_H

#include <osiSock.h>

#include <functional>
#include <string>
#include <tuple>
#include <set>
#include <vector>
#include <memory>
#include <array>

#include <pvxs/version.h>
#include <pvxs/util.h>
#include <pvxs/data.h>

namespace pvxs {
namespace server {

struct SharedPV;
struct Source;
class Server;

//! Configuration for a Server
struct Config {
    //! List of network interface addresses (**not** host names) to which this server will bind.
    //! interfaces.empty() treated as an alias for "0.0.0.0", which may also be given explicitly.
    //! Port numbers are optional and unused (parsed and ignored)
    std::vector<std::string> interfaces;
    //! Addresses (**not** host names) to which (UDP) beacons message will be sent.
    //! May include broadcast and/or unicast addresses.
    //! Supplimented iif auto_beacon==true
    std::vector<std::string> beaconDestinations;
    //! TCP port to bind.  Default is 5075.  May be zero.
    unsigned short tcp_port;
    //! UDP port to bind.  Default is 5076.  May be zero, cf. Server::config() to find allocated port.
    unsigned short udp_port;
    //! Whether to populate the beacon address list automatically.  (recommended)
    bool auto_beacon;

    //! Server unique ID.  Only meaningful in readback via Server::config()
    std::array<uint8_t, 12> guid;

    //! Default configuration using process environment
    PVXS_API
    static Config from_env();
    Config() :tcp_port(5075), udp_port(5076), auto_beacon(true), guid{} {}

    //! Short-hand for @code Server(std::move(*this)) @endcode.
    PVXS_API
    Server build();
};

/** PV Access protocol server instance
 *
 * Use a Config to determine how this server will bind, listen,
 * and announce itself.
 *
 * In order to be useful, a Server will have one or more Source instances added
 * to it with addSource().
 *
 * As a convienence, each Server instance automatically contains a "builtin" StaticSource
 * to which SharedPV instances can be directly added.
 * The "builtin" has priority zero, and can be accessed or even removed like any Source
 * explicitly added with addSource().
 */
class PVXS_API Server
{
public:

    //! An empty/dummy Server
    constexpr Server() = default;
    //! Create/allocate, but do not start, a new server with the provided config.
    explicit Server(Config&&);
    ~Server();

    //! Begin serving.  Does not block.
    Server& start();
    //! Stop server
    Server& stop();

    /** start() and then (maybe) stop()
     *
     * run() may be interupted by calling interrupt(),
     * or by SIGINT or SIGTERM (only one Server per process)
     */
    Server& run();
    //! Queue a request to break run()
    Server& interrupt();

    //! effective config
    const Config& config() const;

    //! Add a SharedPV to the builtin StaticSource
    Server& addPV(const std::string& name, const SharedPV& pv);
    //! Remove a SharedPV from the builtin StaticSource
    Server& removePV(const std::string& name);

    //! Add a Source to this server with an arbitrary source name.
    //!
    //! @param name Source name
    //! @param src The Source.  A strong reference to this Source which will be released by removeSource() or ~Server()
    //! @param order Determines the order in which this Source::onCreate() will be called.  Lowest first.
    Server& addSource(const std::string& name,
                      const std::shared_ptr<Source>& src,
                      int order =0);

    //! Disassociate a Source using the name and priority given to addSource()
    std::shared_ptr<Source> removeSource(const std::string& name,
                                         int order =0);

    //! Fetch a previously added Source.
    std::shared_ptr<Source> getSource(const std::string& name,
                                      int order =0);

    //! List all source names and priorities.
    void listSource(std::vector<std::pair<std::string, int> >& names);

    explicit operator bool() const { return !!pvt; }

    struct Pvt;
private:
    std::shared_ptr<Pvt> pvt;
};

}} // namespace pvxs::server

#endif // PVXS_SERVER_H
