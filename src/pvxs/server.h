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
namespace impl {
struct ServerConn;
}
namespace server {

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
    //! Configuration for a Server
    struct Config {
        //! List of network interface addresses to which this server will bind.
        //! interfaces.empty() treated as an alias for "0.0.0.0", which may also be given explicitly.
        //! Port numbers are optional and unused (parsed and ignored)
        std::vector<std::string> interfaces;
        //! Addresses to which (UDP) beacons message will be sent.
        //! May include broadcast and/or unicast addresses.
        std::vector<std::string> beaconDestinations;
        //! TCP port to bind.  May be zero.
        unsigned short tcp_port;
        //! UDP port to bind.  May not be zero
        unsigned short udp_port;
        //! Whether to populate the beacon address list automatically.  (recommended)
        bool auto_beacon;

        //! Server unique ID.  Only meaningful in readback via Server::config()
        std::array<uint8_t, 12> guid;

        //! Default configuration using process environment
        PVXS_API static Config from_env();
        Config() :tcp_port(5075), udp_port(5076), auto_beacon(true), guid{} {}

        //! Short-hand for @code Server(std::move(*this)) @endcode.
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
     * or by SIGINT or SIGTERM (only one Server per process)
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

//! Base for all operation classes
struct PVXS_API OpBase {
    enum op_t {
        None, //!< invalid
        Info, //!< A GET_FIELD operation
        Get,  //!< A GET operation
        Put,  //!< A PUT operation
        RPC,  //!< A RPC operaton
    };
protected:
    std::string _peerName;
    std::string _ifaceName;
    std::string _name;
    op_t _op;
public:
    //! The Client endpoint address in "X.X.X.X:Y" format.
    const std::string& peerName() const { return _peerName; }
    //! The local endpoint address in "X.X.X.X:Y" format.
    const std::string& ifaceName() const { return _ifaceName; }
    //! The Channel name
    const std::string& name() const { return _name; }
    op_t op() const { return _op; }
    // TODO credentials

    virtual ~OpBase() =0;
};

//! Handle when an operation is being executed
struct PVXS_API ExecOp : public OpBase {

    //! Issue a reply without data.  (eg. to complete a PUT)
    virtual void reply() =0;
    //! Issue a reply with data.  For a GET or RPC  (or PUT/Get)
    virtual void reply(const Value& val) =0;
    //! Indicate the request has resulted in an error.
    virtual void error(const std::string& msg) =0;

    //! Callback invoked if the peer cancels the operation before reply() or error() is called.
    virtual void onCancel(std::function<void()>&&) =0;

    virtual ~ExecOp();
};

//! Handle when an operation is being setup
struct PVXS_API ConnectOp : public OpBase {
    Value pvRequest;

    //! For GET_FIELD, GET, or PUT.  Inform peer of our data-type
    virtual void connect(const Value& prototype) =0;
    //! Indicate that this operation can not be setup
    virtual void error(const std::string& msg) =0;

    virtual ~ConnectOp();

    //! Handler invoked when a peer executes a request for data on a GET o PUT
    virtual void onGet(std::function<void(std::unique_ptr<ExecOp>&&)>&& fn) =0;
    //! Handler invoked when a peer executes a send data on a PUT
    virtual void onPut(std::function<void(std::unique_ptr<ExecOp>&&, Value&&)>&& fn) =0;
    //! Callback when the underlying channel closes
    virtual void onClose(std::function<void(const std::string&)>&&) =0;
};

/** Manipulate an active Channel, and any in-progress Operations through it.
 *
 */
struct PVXS_API ChannelControl : public OpBase {
    virtual ~ChannelControl() =0;

    //! Invoked when a new GET, PUT, or RPC Operation is requested through this Channel
    virtual void onOp(std::function<void(std::unique_ptr<ConnectOp>&&)>&& ) =0;
    //! Invoked when the a peer executes an RPC
    virtual void onRPC(std::function<void(std::unique_ptr<ExecOp>&&, Value&&)>&& fn)=0;

    //! Callback when the channel closes (eg. peer disconnect)
    virtual void onClose(std::function<void(const std::string&)>&&) =0;

    //! Force disconnection
    //! If called from outside a handler method, blocks until in-progress Handler methods have returned.
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
        //! A single name being searched
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

    //! List of channel names
    struct List {
        //! The list
        std::shared_ptr<const std::set<std::string>> names;
        //! True if the list may change at some future time.
        bool dynamic;
    };

    /** A Client is requesting a list of Channel names which we may claim.
     */
    virtual List onList();
};

}} // namespace pvxs::server

#endif // PVXS_SERVER_H
