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
#include <pvxs/data.h>

namespace pvxs {
namespace impl {
struct ServerConn;
}
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
 *
 * In order to be useful, a Server will have one or more Source instances added
 * to it with addSource().
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

    //! Add a Source to this server with an arbitrary source name.
    //!
    //! @param name Source name
    //! @param src The Source.  A strong reference to this Source which will be released by removeSource() or ~Server()
    //! @param order Determines the order in which this Source::onCreate() will be called.
    //!        Lowest first.
    Server& addSource(const std::string& name,
                      const std::shared_ptr<Source>& src,
                      int order =0);

    //! Disociate a Source using the name _and_ priority given to addSource()
    std::shared_ptr<Source> removeSource(const std::string& name,
                                         int order =0);

    //! Fetch an
    std::shared_ptr<Source> getSource(const std::string& name,
                                      int order =0);

    void listSource(std::vector<std::pair<std::string, int> >& names);

    explicit operator bool() const { return !!pvt; }

    struct Pvt;
private:
    std::shared_ptr<Pvt> pvt;
};

struct OpBase {
    //! The Client endpoint address in "X.X.X.X:Y" format.
    const std::string peerName;
    //! The local endpoint address in "X.X.X.X:Y" format.
    const std::string ifaceName;
    //! The Channel name
    const std::string name;
    // TODO credentials

    OpBase(const std::string& peerName,
           const std::string& iface,
           const std::string& name);
    virtual ~OpBase() =0;
};

/** Manipulate an active Channel, and any in-progress Operations through it.
 *
 */
struct PVXS_API ChannelControl : public OpBase {
    ChannelControl(const std::string& peerName,
                   const std::string& iface,
                   const std::string& name)
        :OpBase (peerName, iface, name)
    {}
    virtual ~ChannelControl() =0;

    //! Set/replace Handler associated with this Channel
    //! If called from outside a Handler method, blocks until in-progress Handler methods have returned.
    virtual std::shared_ptr<Handler> setHandler(const std::shared_ptr<Handler>& h) =0;

    //! Force disconnection
    //! If called from outside a Handler method, blocks until in-progress Handler methods have returned.
    //! Reference to currently attached Handler is released.
    virtual void close() =0;

    // TODO: signal Rights?
};

/** Interface through which a Server discovers Channel names and
 *  associates with Handler instances.
 *
 *  User code will sub-class.
 */
struct PVXS_API Source {
    virtual ~Source() =0;

    //! An iteratable of names being sought
    struct Search {
        class Name {
            const char* _name = nullptr;
            bool _claim = false;
            friend struct Server::Pvt;
            friend struct impl::ServerConn;
        public:
            //! The Channel name
            inline const char* name() const { return _name; }
            //! The caller claims to be able to respond to an onCreate()
            inline void claim() { _claim = true; }
            // TODO claim w/ redirect
        };
    private:
        typedef std::vector<Name> _names_t;
        _names_t _names;
        SockAddr _src;
        friend struct Server::Pvt;
        friend struct impl::ServerConn;
    public:

        _names_t::iterator begin() { return _names.begin(); }
        _names_t::iterator end() { return _names.end(); }
        //! The Client endpoint address in "X.X.X.X:Y" format.
        const SockAddr& source() const { return _src; }
    };
    /** Called each time a client polls for the existance of some Channel names.
     *
     * A Source may only Search::claim() a Channel name if it is prepared to
     * immediately accept an onCreate() call for that Channel name.
     * In other situations it should wait for the client to retry.
     */
    virtual void onSearch(Search& op) =0;

    /** A Client is attempting to open a connection to a certain Channel.
     *
     *  This Channel name may not be one which seen or claimed by onSearch().
     *
     *  Callee with either do nothing, or std::move() the ChannelControl and call ChannelControl::setHandler()
     */
    virtual void onCreate(std::unique_ptr<ChannelControl>&& op) =0;
};

//! Token for an in-progress request for Channel data type information.
struct PVXS_API Introspect : public OpBase
{
    //! Positive reply.  Only the type of the provided Value is used.  Any field values are ignored.
    virtual void reply(const Value& prototype) =0;
    //! Negative reply w/ error message
    virtual void error(const std::string& msg) =0;

    Introspect(const std::string& peerName,
                   const std::string& iface,
                   const std::string& name)
        :OpBase (peerName, iface, name)
    {}
    virtual ~Introspect() =0;
};

struct PVXS_API Get : public OpBase
{
    const Value request;

    //! Positive reply w/ data
    virtual void reply(const Value& prototype) =0;
    //! Negative reply w/ error message
    virtual void error(const std::string& msg) =0;

    Get(const std::string& peerName,
        const std::string& iface,
        const std::string& name,
        const Value& request)
        :OpBase (peerName, iface, name)
        ,request(request)
    {}
    virtual ~Get() =0;
};

struct PVXS_API Put : public OpBase
{
    const Value request;
    const Value value;

    //! Positive reply
    virtual void complete() =0;
    //! Negative reply w/ error message
    virtual void error(const std::string& msg) =0;

    Put(const std::string& peerName,
        const std::string& iface,
        const std::string& name,
        const Value& request,
        const Value& value)
        :OpBase (peerName, iface, name)
        ,request(request)
        ,value(value)
    {}
    virtual ~Put() =0;
};

struct PVXS_API RPC : public OpBase
{
    const Value request;
    const Value value;

    //! Positive reply w/ data
    virtual void reply(const Value& prototype) =0;
    //! Negative reply w/ error message
    virtual void error(const std::string& msg) =0;

    RPC(const std::string& peerName,
        const std::string& iface,
        const std::string& name,
        const Value& request,
        const Value& value)
        :OpBase (peerName, iface, name)
        ,request(request)
        ,value(value)
    {}
    virtual ~RPC() =0;
};

/** Requests for a particular Channel are dispatched through me.
 *
 *  User code will sub-class.
 */
struct PVXS_API Handler {
    virtual ~Handler();

    /** Request for Channel data type information
     *
     * Ownership of the Introspect instance is passed to the callee.
     * The request will be implicitly errored if the callee allows
     * the Introspect to be deleted prior to replying.
     */
    virtual void onIntrospect(std::unique_ptr<Introspect>&& op);

    virtual void onGet(std::unique_ptr<Get>&& op);
    virtual void onPut(std::unique_ptr<Put>&& op);
    virtual void onRPC(std::unique_ptr<RPC>&& op);
};

}} // namespace pvxs::server

#endif // PVXS_SERVER_H
