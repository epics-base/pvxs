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
#include <vector>
#include <memory>

#include <pvxs/version.h>
#include <pvxs/util.h>

namespace pvxs {
namespace server {
/*
struct Search
{
    struct Op {
        const char *name;
        uint32_t id;

        void claim() const;
    };

    osiSockAddr peer, reply;

    const Op* begin();
    const Op* end();
};

struct Create {};

struct Handler
{
    struct Op {
        osiSockAddr peer;
        // credentials
        void onCancel(std::function<void()>&&);
    };
    template<typename Req, typename Resp>
    struct DataOp : public Op {
        Req req;
        void ok(Resp resp);
        void error(const std::string& msg);
    };
    struct Subscription : public Op {
        void post(data);
        void tryPost(data);
        void close();
        long window() const;
        void onAck(std::function<void(size_t)>&&);
    };

    void onGet(std::function<void(DataOp<void, char>)>&&);

    virtual void handleGet(DataOp<void, char> op);
    virtual void handlePut(DataOp<char, void> op);
    virtual void handleRPC(DataOp<char, char> op);
    virtual void handlePutGet(DataOp<char, char> op);
    virtual void handleMonitor(Subscription op);
};

struct FallbackHandler
{
    virtual void handleSearch(const Search& op) =0;
    virtual std::unique_ptr<Handler> handleCreate(const Create& op) =0;
};

class Attachment {
};
*/
class PVXS_API Server
{
public:
    struct Config {
        //! List of network interface addresses to which this server will bind (list of TCP connections).
        //! interfaces.empty() treated as an alias for "0.0.0.0", which may also be given explicitly.
        //! Port numbers are optional and unused (parsed and ignored)
        std::vector<std::string> interfaces;
        //! Addresses to which (UDP) beacons message will be sent.
        //! May include broadcast and/or unicast addresses.
        //! Special value "*" is expanded with all local interfaces broadcast addresses.
        std::vector<std::string> beaconDestinations;
        unsigned short tcp_port;
        unsigned short default_udp;
        bool auto_beacon;

        PVXS_API static Config from_env();
        Config() :tcp_port(5075), default_udp(5076), auto_beacon(true) {}
    };

    //! An empty/dummy Server
    Server();
    //! Create/allocate, but do not start, a new server with the provided config.
    explicit Server(Config&&);
    ~Server();

    Server& start();
    Server& stop();

    //! effective config
    const Config& config() const;

    /*
    Attachment attach(const std::string& name,
                      std::unique_ptr<Handler>&& handler);

    Attachment attachFallback(std::unique_ptr<FallbackHandler>&& handler);

    void detach(Attachment&& attach);
    */

    explicit operator bool() const { return !!pvt; }

    struct Pvt;
private:
    std::unique_ptr<Pvt> pvt;
};

}} // namespace pvxs::server

#endif // PVXS_SERVER_H
