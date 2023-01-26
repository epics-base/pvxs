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
#include "srvcommon.h"

namespace pvxs {
namespace impl {
struct ServerConn;
}
namespace server {

//! Handle when an operation is being setup
struct PVXS_API ConnectOp : public OpBase {
protected:
    Value _pvRequest;
public:
    const Value& pvRequest() const { return _pvRequest; }

    //! For GET_FIELD, GET, or PUT.  Inform peer of our data-type.
    //! @throws std::runtime_error if the client pvRequest() field mask does not select any fields of prototype.
    virtual void connect(const Value& prototype) =0;
    //! Indicate that this operation can not be setup
    virtual void error(const std::string& msg) =0;

    ConnectOp(const std::string& name,
           const std::shared_ptr<const ClientCredentials>& cred, op_t op,
           const Value& pvRequest)
        :OpBase(name, cred, op)
        ,_pvRequest(pvRequest)
    {}
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
    size_t window=0;

    //! Number of un-sent updates in the local queue.  Doesn't include updates
    //! serialized and in the TX buffer.
    size_t nQueue=0;
    //! Highest value of nQueue seen
    //! @since 1.1.0
    size_t maxQueue=0;
    //! Negotiated limit on nQueue
    size_t limitQueue=0;

    bool running=false;
    bool finished=false;
    bool pipeline=false;
};

//! Handle for active subscription
struct PVXS_API MonitorControlOp : public OpBase {
    MonitorControlOp(const std::string& name,
           const std::shared_ptr<const ClientCredentials>& cred, op_t op)
        :OpBase(name, cred, op)
    {}
    virtual ~MonitorControlOp();

protected:
    virtual bool doPost(const Value& val, bool maybe, bool force) =0;
public:

    //! Add a new entry to the monitor queue.
    //! If nFree()<=0 the output queue will be over-filled with this element.
    //! Returns @code nFree()>0u @endcode
    //! @warning Caller must not modify the Value
    bool forcePost(const Value& val) {
        return doPost(val, false, true);
    }

    //! Add a new entry to the monitor queue.
    //! If nFree()<=0 this element will be "squashed" to the last element in the queue
    //! Returns @code nFree()>0u @endcode
    //! @warning Caller must not modify the Value
    bool post(const Value& val) {
        return doPost(val, false, false);
    }

    //! Add a new entry to the monitor queue.
    //! If nFree()<=0 return false and take no other action
    //! Returns @code nFree()>0u @endcode
    //! @warning Caller must not modify the Value
    bool tryPost(const Value& val) {
        return doPost(val, true, false);
    }

    //! Signal to subscriber that this subscription will not yield any further events.
    //! This is not an error.  Client should not retry.
    void finish() {
        doPost(Value(), false, false);
    }

    //! Poll information and statistics for this subscription.
    //! @since 1.1.0 Added 'reset' argument.
    virtual void stats(MonitorStat&, bool reset=false) const =0;

    /** Set flow control levels.
     *
     *  Flow control operations against an outbound "window" size, which is the number of updates which may
     *  be sent before a client ack. must be received.  By default both high and low levels are zero.
     *
     *  onLowMark callback is not currently implemented and the 'low' level is not used.
     *  onHighMark callback will be invoked when a client ack. is received and the window size is above (>) 'high'.
     */
    virtual void setWatermarks(size_t low, size_t high) =0;

    //! Callback when client resumes/pauses updates
    virtual void onStart(std::function<void(bool start)>&&) =0;
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
    //! @throws std::runtime_error if the client pvRequest() field mask does not select any fields of prototype.
    virtual std::unique_ptr<MonitorControlOp> connect(const Value& prototype) =0;

    //! Indicate that this operation can not be setup
    virtual void error(const std::string& msg) =0;

    MonitorSetupOp(const std::string& name,
           const std::shared_ptr<const ClientCredentials>& cred, op_t op,
           const Value& pvRequest)
        :OpBase(name, cred, op)
        ,_pvRequest(pvRequest)
    {}
    virtual ~MonitorSetupOp();

    virtual void onClose(std::function<void(const std::string&)>&&) =0;
};

/** Manipulate an active Channel, and any in-progress Operations through it.
 *
 */
struct PVXS_API ChannelControl : public OpBase {
    ChannelControl(const std::string& name,
           const std::shared_ptr<const ClientCredentials>& cred, op_t op)
        :OpBase(name, cred, op)
    {}
    virtual ~ChannelControl() =0;

    //! Invoked when a new GET or PUT Operation is requested through this Channel
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

#ifdef PVXS_EXPERT_API_ENABLED
    // Store info struct which will be returned with Report::Channel
    inline void updateInfo(const std::shared_ptr<const ReportInfo>& info)
    { this->_updateInfo(info); }
#endif
private:
    virtual void _updateInfo(const std::shared_ptr<const ReportInfo>& info) =0;
};

/** Interface through which a Server discovers Channel names and
 *  associates with Handler instances.
 *
 *  User code will sub-class.
 */
struct PVXS_API Source {
    virtual ~Source() =0;

    /** An iterable of names (Name) being sought.
     *
     * @code
     *   virtual void onSearch(Search& search) {
     *       for(auto& op : search) {
     *           if(strcmp(op.name(), "magic")==0)
     *               op.claim();
     *       }
     *   }
     * @endcode
     */
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
            //! The caller claims to be able to respond to an onCreate() for this name.
            inline void claim() { _claim = true; }
            // TODO claim w/ redirect
        };
    private:
        typedef std::vector<Name> _names_t;
        _names_t _names;
        char _src[24];
        friend struct Server::Pvt;
        friend struct impl::ServerConn;
    public:
        typedef Name value_type;
        typedef _names_t::iterator iterator;

        //! Number of names
        inline size_t size() const { return _names.size(); }
        //! Begin iterator of Name instances
        iterator begin() { return _names.begin(); }
        //! End iterator of Name instances
        iterator end() { return _names.end(); }
        //! The Client endpoint address
        const char* source() const { return _src; }
    };
    /** Called each time a client polls for the existence of some Channel names (Search::Name).
     *
     * A Source may only Search::Name::claim() a Channel name if it is prepared to
     * immediately accept an onCreate() call for that Channel name.
     * In other situations it should wait for the client to retry.
     */
    virtual void onSearch(Search& op) =0;

    /** A Client is attempting to open a connection to a certain Channel.
     *
     *  This Channel name may not be one which was seen or claimed by onSearch().
     *
     *  Callee may:
     *
     *  - Do nothing, allowing some other Source with higher/later order a chance to create.
     *  - Call ChannelControl::close() to explicitly reject the channel.
     *  - std::move() the op and/or call ChannelControl::setHandler() to accept the new channel.
     *  - std::move() the op and allow ChannelControl to be destroyed to implicitly reject the channel.
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

    //! Print status information.
    virtual void show(std::ostream& strm);
};

}} // namespace pvxs::server

#endif // PVXS_SOURCE_H
