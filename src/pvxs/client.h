/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CLIENT_H
#define PVXS_CLIENT_H

#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <ostream>
#include <typeinfo>

#include <epicsTime.h>

#include <pvxs/version.h>
#include <pvxs/data.h>

namespace pvxs {
namespace client {

class Context;
struct Config;

//! Operation failed because of connection to server was lost
struct PVXS_API Disconnect : public std::runtime_error
{
    Disconnect();
    virtual ~Disconnect();

    //! When loss of connection was noticed (when timeout expires).
    const epicsTime time;
};

//! Error condition signaled by server
struct PVXS_API RemoteError : public std::runtime_error
{
    RemoteError(const std::string& msg);
    virtual ~RemoteError();
};

//! For monitor only.  Subscription has completed normally
//! and no more events will ever be received.
struct PVXS_API Finished : public Disconnect
{
    Finished() = default;
    virtual ~Finished();
};

//! For monitor only.  Subscription has (re)connected.
struct PVXS_API Connected : public std::runtime_error
{
    Connected(const std::string& peerName);
    virtual ~Connected();

    const std::string peerName;
    const epicsTime time;
};

struct PVXS_API Interrupted : public std::runtime_error
{
    Interrupted();
    virtual ~Interrupted();
};

struct PVXS_API Timeout : public std::runtime_error
{
    Timeout();
    virtual ~Timeout();
};

//! Holder for a Value or an exception
class Result {
    Value _result;
    std::exception_ptr _error;
    std::string _peerName;
public:
    Result() = default;
    Result(Value&& val, const std::string& peerName) :_result(std::move(val)), _peerName(peerName) {}
    explicit Result(const std::exception_ptr& err) :_error(err) {}

    //! Access to the Value, or rethrow the exception
    Value& operator()() {
        if(_error)
            std::rethrow_exception(_error);
        return _result;
    }

    const std::string peerName() const { return  _peerName; }

    bool error() const { return !!_error; }
    explicit operator bool() const { return _result || _error; }
};

//! Handle for in-progress operation
struct PVXS_API Operation {
    const enum operation_t {
        Info    = 17, // CMD_GET_FIELD
        Get     = 10, // CMD_GET
        Put     = 11, // CMD_PUT
        RPC     = 20, // CMD_RPC
        Monitor = 13, // CMD_MONITOR
    } op;

    explicit constexpr Operation(operation_t op) :op(op) {}
    Operation(const Operation&) = delete;
    Operation& operator=(const Operation&) = delete;
    virtual ~Operation() =0;

    //! Explicitly cancel a pending operation.
    //! Blocks until an in-progress callback has completed.
    virtual void cancel() =0;

    /** @brief Block until Operation completion
     *
     * As an alternative to a .result() callback, wait for operation competion,
     * timeout, or interruption (via. interrupt() ).
     *
     * @param timeout Time to wait prior to throwing TimeoutError.  cf. epicsEvent::wait(double)
     * @return result Value.  Always empty/invalid for put()
     * @throws Timeout Timeout exceeded
     * @throws Interrupted interrupt() called
     */
    virtual Value wait(double timeout) =0;

    //! wait(double) without a timeout
    Value wait() {
        return wait(99999999.0);
    }

    //! Queue an interruption of a wait() or wait(double) call.
    virtual void interrupt() =0;
};

//! Handle for monitor subscription
struct PVXS_API Subscription {

    virtual ~Subscription() =0;

    //! Explicitly cancel a active subscription.
    //! Blocks until any in-progress callback has completed.
    virtual void cancel() =0;

    //! Ask a server to stop sending updates to this Subscription
    virtual void pause(bool p=true) =0;
    //! Shorthand for @code pause(false) @endcode
    inline void resume() { pause(false); }

    /** De-queue update from subscription event queue.
     *
     *  If the queue is empty, return an empty/invalid Value (Value::valid()==false).
     *  A data update is returned as a Value.
     *  An error or special event is thrown.
     *
     * @returns A valid Value until the queue is empty
     * @throws Connected (depending on MonitorBuilder::maskConnected())
     * @throws Disconnect (depending on MonitorBuilder::maskDisconnect())
     * @throws Finished  (depending on MonitorBuilder::maskDisonnect())
     * @throws RemoteError For server signaled errors
     * @throws std::exception For client side failures.
     *
     * @code
     * std::shared_ptr<Subscription> sub(...);
     * try {
     *     while(auto update = sub.pop()) {
     *         ...
     *     }
     * } catch(Connected& con) {
     * } catch(Finished& con) {
     * } catch(Disconnect& con) {
     * } catch(RemoteError& con) {
     * } catch(std::exception& con) {
     * }
     * @endcode
     */
    virtual Value pop() =0;
};

class GetBuilder;
class PutBuilder;
class RPCBuilder;
class MonitorBuilder;

/** An independent PVA protocol client instance
 *
 *  Typically created with Config::build()
 *
 *  @code
 *  Context ctxt(Config::from_env().build());
 *  @endcode
 */
class PVXS_API Context {
public:
    struct Pvt;

    //! An empty/dummy Context
    constexpr Context() = default;
    //! Create/allocate a new client with the provided config.
    //! Config::build() is a convienent shorthand.
    explicit Context(const Config &);
    ~Context();

    //! effective config of running client
    const Config& config() const;

    /** Request the present value of a PV
     *
     * Simple blocking
     *
     * @code
     * Context ctxt(...);
     * auto result = ctxt.get("pv:name")
     *                   .exec()
     *                   ->wait();
     * @endcode
     *
     * With completion callback
     *
     * @code
     * Context ctxt(...);
     * auto op = ctxt.get("pv:name")
     *               .result([](Result&& prototype){
     *                  std::cout<<prototype();
     *               })
     *               .exec();
     * // store op until completion
     * @endcode
     */
    inline
    GetBuilder get(const std::string& pvname);

    /** Request type information from PV.
     *  Results in a Value with no marked fields.
     *
     * Simple blocking
     *
     * @code
     * Context ctxt(...);
     * auto result = ctxt.info("pv:name")
     *                   .exec()
     *                   ->wait();
     * @endcode
     *
     * With completion callback
     *
     * @code
     * Context ctxt(...);
     * auto op = ctxt.info("pv:name")
     *               .result([](Result&& prototype){
     *                  std::cout<<prototype();
     *               })
     *               .exec();
     * // store op until completion
     * @endcode
     */
    inline
    GetBuilder info(const std::string& pvname);

    /** Request change/update of PV.
     *
     * Assign certain values to certain fields and block for completion.
     *
     * @code
     * Context ctxt(...);
     * auto result = ctxt.put("pv:name")
     *                   .set("value", 42)
     *                   .exec()
     *                   ->wait();
     * @endcode
     *
     * Alternately, and more generally, using a .build() callback
     * and use .result() callback for completion notification.
     *
     * @code
     * Context ctxt(...);
     * auto op = ctxt.put("pv:name")
     *               .build([](Value&& prototype) -> Value {
     *                   auto putval = prototype.cloneEmpty();
     *                   putval["value"] = 42;
     *                   return putval;
     *               })
     *               .result([](Result&& prototype){
     *                  try {
     *                      // always returns empty Value on success
     *                      prototype();
     *                      std::cout<<"Success";
     *                  }catch(std::exception& e){
     *                      std::cout<<"Error: "<<e.what();
     *                  }
     *               })
     *               .exec();
     * // store op until completion
     * @endcode
     */
    inline
    PutBuilder put(const std::string& pvname);

    inline
    RPCBuilder rpc(const std::string& pvname);

    /** Execute "stateless" remote procedure call operation.
     *
     * Simple blocking
     *
     * @code
     * Value arg = ...;
     * Context ctxt(...);
     * auto result = ctxt.rpc("pv:name", arg)
     *                   .arg("blah", 5)
     *                   .arg("other", "example")
     *                   .exec()
     *                   ->wait();
     * @endcode
     *
     * With completion callback
     *
     * @code
     * Value arg = ...;
     * Context ctxt(...);
     * auto op = ctxt.rpc("pv:name", arg)
     *               .result([](Result&& prototype){
     *                  std::cout<<prototype();
     *               })
     *               .exec();
     * // store op until completion
     * @endcode
     */
    inline
    RPCBuilder rpc(const std::string& pvname, Value&& arg);

    /** Create a new subscription for changes to a PV.
     *
     * @code
     * auto sub = ctxt.monitor("pv:name")
     *                .event([](Subscription& sub) {
     *                    try {
     *                        while(Value update = sub.pop()) {
     *                            std::cout<<update<<"\n";
     *                        }
     *                     } catch(std::exception& e) {
     *                         std::cerr<<"Error "<<e.what()<<"\n";
     *                     }
     *                })
     *                .exec();
     * // store op until completion
     * @endcode
     */
    inline
    MonitorBuilder monitor(const std::string& pvname);

    /** Request prompt search of any disconnected channels.
     *
     * Optional.  Equivalent to detection of a new server.
     * This method has no effect if called more often than once per 30 seconds.
     */
    void hurryUp();

    explicit operator bool() const { return pvt.operator bool(); }
private:
    std::shared_ptr<Pvt> pvt;
};

namespace detail {
struct PVRParser;

class PVXS_API CommonBase {
protected:
    std::shared_ptr<Context::Pvt> ctx;
    std::string _name;
    std::string _server;
    struct Req;
    std::shared_ptr<Req> req;
    unsigned _prio = 0u;

    CommonBase(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) : ctx(ctx), _name(name) {}
    ~CommonBase();

    void _rawRequest(Value&&);
    void _field(const std::string& s);
    void _record(const std::string& key, const void* value, StoreType vtype);
    void _parse(const std::string& req);
    Value _buildReq() const;

    friend struct PVRParser;
};

class PVXS_API PRBase : public CommonBase {
protected:
    struct Args;
    std::shared_ptr<Args> _args;

    PRBase(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) : CommonBase(ctx, name) {}
    ~PRBase();

    void _set(const std::string& name, const void *ptr, StoreType type, bool required);
    Value _builder(Value&& prototype) const;
    Value _uriArgs() const;
};

//! Options common to all operations
template<typename SubBuilder, typename Base>
class CommonBuilder : public Base {
protected:
    constexpr CommonBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) : Base(ctx, name) {}
    inline SubBuilder& _sb() { return static_cast<SubBuilder&>(*this); }
public:
    //! Add field to pvRequest blob.
    //! A more efficient alternative to @code pvRequest("field(name)") @endcode
    SubBuilder& field(const std::string& fld) { this->_field(fld); return _sb(); }

    /** Add a key/value option to the request.
     *
     * Well known options include:
     *
     * - queueSize : positive integer
     * - block     : bool
     * - process   : bool or string "true", "false", or "passive"
     * - pipeline  : bool
     *
     * A more efficient alternative to @code pvRequest("record[key=value]") @endcode
     */
    template<typename T>
    SubBuilder& record(const std::string& name, const T& val) {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t norm(val);
        this->_record(name, &norm, map_t::code);
        return _sb();
    }

    /** Parse pvRequest string.
     *
     *  Supported syntax is a list of zero or more entities
     *  seperated by zero or more spaces.
     *
     *  - field(<fld.name>)
     *  - record(<key>=\<value>)
     */
    SubBuilder& pvRequest(const std::string& expr) { this->_parse(expr); return _sb(); }

    //! Store raw pvRequest blob.
    SubBuilder& rawRequest(Value&& r) { this->_rawRequest(std::move(r)); return _sb(); }

    SubBuilder& priority(int p) { this->_prio = p; return _sb(); }
    SubBuilder& server(const std::string& s) { this->_server = s; return _sb(); }
};

} // namespace detail

//! Prepare a remote GET or GET_FIELD (info) operation.
class GetBuilder : public detail::CommonBuilder<GetBuilder, detail::CommonBase> {
    std::function<void(Result&&)> _result;
    bool _get;
    PVXS_API
    std::shared_ptr<Operation> _exec_info();
    PVXS_API
    std::shared_ptr<Operation> _exec_get();
public:
    GetBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name, bool get) :CommonBuilder{ctx,name}, _get(get) {}
    //! Callback through which result Value or an error will be delivered.
    //! The functor is stored in the Operation returned by exec().
    GetBuilder& result(std::function<void(Result&&)>&& cb) { _result = std::move(cb); return *this; }

    /** Execute the network operation.
     *  The caller must keep returned Operation pointer until completion
     *  or the operation will be implicitly canceled.
     */
    inline std::shared_ptr<Operation> exec() {
        return _get ? _exec_get() : _exec_info();
    }

    friend struct Context::Pvt;
};
GetBuilder Context::info(const std::string& name) { return GetBuilder{pvt, name, false}; }
GetBuilder Context::get(const std::string& name) { return GetBuilder{pvt, name, true}; }

//! Prepare a remote PUT operation
class PutBuilder : public detail::CommonBuilder<PutBuilder, detail::PRBase> {
    bool _doGet = true;
    std::function<Value(Value&&)> _builder;
    std::function<void(Result&&)> _result;
public:
    PutBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) :CommonBuilder{ctx,name} {}

    /** If fetchPresent is true (the default).  Then the Value passed to
     *  the build() callback will be initialized with a previous value for this PV.
     *
     *  This will be necessary for situation like NTEnum to fetch the choices list.
     *  But may be undesirable when writing to array fields to avoid
     *  the expense of fetching a copy of the array to be overwritten.
     */
    PutBuilder& fetchPresent(bool f) { _doGet = f; return *this; }

    PutBuilder& set(const std::string& name, const void *ptr, StoreType type, bool required) {
        _set(name, ptr, type, required);
        return *this;
    }

    /** Utilize default .build() to assign a value to the named field.
     *
     * @param name The field name to attempt to assign.
     * @param val The value to assign.  cf. Value::from()
     * @param required Whether to fail if this value can not be assigned to this field.
     */
    template<typename T>
    PutBuilder& set(const std::string& name, const T& val, bool required=true)
    {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t norm(val);
        return set(name, &norm, map_t::code, required);
    }

    /** Provide the builder callback.
     *
     *  Once the PV type information is received from the server,
     *  this function will be responsible for populating a Value
     *  which will actually be sent.
     *
     *  The functor is stored in the Operation returned by exec().
     */
    PutBuilder& build(std::function<Value(Value&&)>&& cb) { _builder = std::move(cb); return *this; }

    /** Provide the operation result callback.
     *  This callback will be passed a Result which is either an empty Value (success)
     *  or an exception on error.
     *
     *  The functor is stored in the Operation returned by exec().
     */
    PutBuilder& result(std::function<void(Result&&)>&& cb) { _result = std::move(cb); return *this; }

    /** Execute the network operation.
     *  The caller must keep returned Operation pointer until completion
     *  or the operation will be implicitly canceled.
     */
    PVXS_API
    std::shared_ptr<Operation> exec();

    friend struct Context::Pvt;
};
PutBuilder Context::put(const std::string& name) { return PutBuilder{pvt, name}; }

//! Prepare a remote RPC operation
class RPCBuilder : public detail::CommonBuilder<RPCBuilder, detail::PRBase> {
    Value _argument;
    std::function<void(Result&&)> _result;
    friend class Context;
public:
    RPCBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) :CommonBuilder{ctx,name} {}
    //! Callback through which result Value or an error will be delivered.
    //! The functor is stored in the Operation returned by exec().
    RPCBuilder& result(std::function<void(Result&&)>&& cb) { _result = std::move(cb); return *this; }

    RPCBuilder& arg(const std::string& name, const void *ptr, StoreType type) {
        _set(name, ptr, type, true);
        return *this;
    }

    /** Provide argument value.
     *
     * @param name Argument name
     * @param val The value to assign.  cf. Value::from()
     */
    template<typename T>
    RPCBuilder& arg(const std::string& name, const T& val)
    {
        typedef impl::StorageMap<typename std::decay<T>::type> map_t;
        typename map_t::store_t norm(val);
        _set(name, &norm, map_t::code, true);
        return *this;
    }

    /** Execute the network operation.
     *  The caller must keep returned Operation pointer until completion
     *  or the operation will be implicitly canceled.
     */
    PVXS_API
    std::shared_ptr<Operation> exec();

    friend struct Context::Pvt;
};
RPCBuilder Context::rpc(const std::string& name) { return RPCBuilder{pvt, name}; }
RPCBuilder Context::rpc(const std::string& name, Value&& arg) {
    RPCBuilder ret{pvt, name};
    ret._argument = std::move(arg);
    return ret;
}

//! Prepare a remote subscription
class MonitorBuilder : public detail::CommonBuilder<MonitorBuilder, detail::CommonBase> {
    std::function<void(Subscription&)> _event;
    bool _maskConn = true;
    bool _maskDisconn = false;
public:
    MonitorBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) :CommonBuilder{ctx,name} {}
    //! Install event callback
    //! The functor is stored in the Subscription returned by exec().
    MonitorBuilder& event(std::function<void(Subscription&)>&& cb) { _event = std::move(cb); return *this; }
    //! Include Connected exceptions in queue (default false).
    MonitorBuilder& maskConnected(bool m = true) { _maskConn = m; return *this; }
    //! Include Disconnected exceptiosn in queue (default true).
    MonitorBuilder& maskDisconnected(bool m = true) { _maskDisconn = m; return *this; }

    PVXS_API
    std::shared_ptr<Subscription> exec();

    friend struct Context::Pvt;
};
MonitorBuilder Context::monitor(const std::string& name) { return MonitorBuilder{pvt, name}; }

struct PVXS_API Config {
    //! List of unicast and broadcast addresses
    std::vector<std::string> addressList;

    //! List of interface addresses on which beacons may be received.
    //! Also constrains autoAddrList to only consider broadcast addresses of listed interfaces.
    //! Empty implies wildcard 0.0.0.0
    std::vector<std::string> interfaces;

    //! UDP port to bind.  Default is 5076.  May be zero, cf. Server::config() to find allocated port.
    unsigned short udp_port = 5076;
    //! Whether to extend the addressList with local interface broadcast addresses.  (recommended)
    bool autoAddrList = true;

    //! Default configuration using process environment
    static Config from_env();

    /** Apply rules to translate current requested configuration
     *  into one which can actually be loaded based on current host network configuration.
     *
     *  Explicit use of expand() is optional as the Context ctor expands any Config given.
     *  expand() is provided as a aid to help understand how Context::effective() is arrived at.
     *
     *  @post autoAddrList==false
     */
    void expand();

    //! Create a new client Context using the current configuration.
    inline
    Context build() const {
        return Context(*this);
    }
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Config& conf);

} // namespace client
} // namespace pvxs

#endif // PVXS_CLIENT_H
