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
#include <array>

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

struct Handler;
struct Source;

/** PV Access protocol server instance
 *
 * Use a Server::Config to determine how this server will bind, listen,
 * and announce itself.
 */
class PVXS_API Server
{
public:
    struct Config {
        //! List of network interface addresses to which this server will bind.
        //! interfaces.empty() treated as an alias for "0.0.0.0", which may also be given explicitly.
        //! Port numbers are optional and unused (parsed and ignored)
        std::vector<std::string> interfaces;
        //! Addresses to which (UDP) beacons message will be sent.
        //! May include broadcast and/or unicast addresses.
        std::vector<std::string> beaconDestinations;
        unsigned short tcp_port;
        unsigned short udp_port;
        bool auto_beacon;

        std::array<uint8_t, 12> guid;

        PVXS_API static Config from_env();
        Config() :tcp_port(5075), udp_port(5076), auto_beacon(true), guid{} {}

        PVXS_API Server build();
    };

    //! An empty/dummy Server
    Server();
    //! Create/allocate, but do not start, a new server with the provided config.
    explicit Server(Config&&);
    Server(Server&&) noexcept;
    Server(const Server&) = delete;
    Server& operator=(Server&&) noexcept;
    Server& operator=(const Server&) = delete;
    ~Server();

    //! Begin serving.  Does not block.
    Server& start();
    //! Stop server
    Server& stop();

    /** start() and then (maybe) stop()
     *
     * run() may be interupted by calling interrupt(),
     * or by SIGINT SIGTERM (only one Server per process)
     */
    Server& run();
    //! Queue a request to break run()
    Server& interrupt();

    //! effective config
    const Config& config() const;

    Server& addSource(const std::string& name,
                      const std::shared_ptr<Source>& src,
                      int order =0);

    std::shared_ptr<Source> removeSource(const std::string& name,
                                         int order =0);

    std::shared_ptr<Source> getSource(const std::string& name,
                                      int order =0);

    void listSource(std::vector<std::pair<std::string, int> >& names);

    explicit operator bool() const { return !!pvt; }

    struct Pvt;
private:
    std::unique_ptr<Pvt> pvt;
};


struct PVXS_API Source {
    virtual ~Source();

    struct Search {
        class Name {
            const char* _name;
            bool _claim;
            friend struct Server::Pvt;
        public:
            inline const char* name() const { return _name; }
            inline void claim() { _claim = true; }
        };
    private:
        typedef std::vector<Name> _names_t;
        _names_t _names;
        SockAddr _src;
        friend struct Server::Pvt;
    public:

        _names_t::iterator begin() { return _names.begin(); }
        _names_t::iterator end() { return _names.end(); }
        const SockAddr& source() const { return _src; }
    };
    virtual void onSearch(Search& op) =0;

    struct Create {
        std::string& src;
        std::string name;
        // credentials
    };
    virtual std::unique_ptr<Handler> onCreate(const Create& op) =0;
};

struct PVXS_API Handler {
    virtual ~Handler();
};

}} // namespace pvxs::server

#endif // PVXS_SERVER_H
