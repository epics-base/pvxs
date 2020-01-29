/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_SOURCE_H
#define PVXS_SOURCE_H

#include <string>
#include <functional>

#include <pvxs/data.h>
#include <pvxs/server.h>

namespace pvxs {
namespace impl {
struct ServerConn;
}
namespace server {

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
protected:
    Value _pvRequest;
public:
    const Value& pvRequest() const { return _pvRequest; }

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

//! Information about a running monitor
struct MonitorStat {
    //! Number of available elements in the output flow window.
    size_t window;

    //! Number of un-sent updates in the local queue.  Doesn't count updates
    //! serialized and in the TX buffer.
    size_t nQueue, limitQueue;

    bool running;
    bool finished;
    bool pipeline;
};

//! Handle for active subscription
struct PVXS_API MonitorControlOp : public OpBase {
    virtual ~MonitorControlOp();

protected:
    virtual bool doPost(Value&& val, bool maybe, bool force) =0;
public:

    //! Add a new entry to the monitor queue.
    //! If nFree()<=0 the output queue will be over-filled with this element.
    //! Returns @code nFree()>0u @endcode
    bool forcePost(Value&& val) {
        return doPost(std::move(val), false, true);
    }

    //! Add a new entry to the monitor queue.
    //! If nFree()<=0 this element will be "squshed" to the last element in the queue
    //! Returns @code nFree()>0u @endcode
    bool post(Value&& val) {
        return doPost(std::move(val), false, false);
    }

    //! Add a new entry to the monitor queue.
    //! If nFree()<=0 return false and take no other action
    //! Returns @code nFree()>0u @endcode
    bool tryPost(Value&& val) {
        return doPost(std::move(val), true, false);
    }

    //! Signal to subscriber that this subscription will not yield any further events.
    //! This is not an error.  Client should not retry.
    void finish() {
        doPost(Value(), false, false);
    }

    virtual void stats(MonitorStat&) const =0;

    //! Set flow control levels.
    //! onLowMark callback will be invoked when nFree()<=low becomes true, and not again until it has been false.
    //! onHighMark callback will be invoked when nFree()>high becomes true, and not again until it has been false.
    virtual void setWatermarks(size_t low, size_t high) =0;

    //! Callback when client resumes/pauses updates
    virtual void onStart(std::function<void(bool)>&&) =0;
    virtual void onHighMark(std::function<void()>&&) =0;
    virtual void onLowMark(std::function<void()>&&) =0;
};

//! Handle for subscription which is being setup
struct PVXS_API MonitorSetupOp : public OpBase {
protected:
    Value _pvRequest;
public:
    const Value& pvRequest() const { return _pvRequest; }

    //! Inform peer of our data-type and acquire control of subscription queue.
    //! The queue is initially stopped.
    virtual std::unique_ptr<MonitorControlOp> connect(const Value& prototype) =0;
    //! Indicate that this operation can not be setup
    virtual void error(const std::string& msg) =0;

    virtual ~MonitorSetupOp();

    virtual void onClose(std::function<void(const std::string&)>&&) =0;
};

/** Manipulate an active Channel, and any in-progress Operations through it.
 *
 */
struct PVXS_API ChannelControl : public OpBase {
    virtual ~ChannelControl() =0;

    //! Invoked when a new GET, PUT, or RPC Operation is requested through this Channel
    virtual void onOp(std::function<void(std::unique_ptr<ConnectOp>&&)>&& ) =0;
    //! Invoked when the peer executes an RPC
    virtual void onRPC(std::function<void(std::unique_ptr<ExecOp>&&, Value&&)>&& fn)=0;
    //! Invoked when the peer create a new subscription
    virtual void onSubscribe(std::function<void(std::unique_ptr<MonitorSetupOp>&&)>&&)=0;

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

#endif // PVXS_SOURCE_H
