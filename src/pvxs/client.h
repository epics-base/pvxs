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

#include <pvxs/version.h>
#include <pvxs/data.h>

namespace pvxs {
namespace client {

class Context;
struct Config;

struct PVXS_API Disconnect : public std::runtime_error
{
    Disconnect();
    virtual ~Disconnect();
};

struct PVXS_API RemoteError : public std::runtime_error
{
    RemoteError(const std::string& msg);
    virtual ~RemoteError();
};

//! Holder for a Value or an exception
class Result {
    Value _result;
    std::exception_ptr _error;
public:
    Result() = default;
    Result(Value&& val) :_result(std::move(val)) {}
    explicit Result(const std::exception_ptr& err) :_error(err) {}

    //! Access to the Value, or rethrow the exception
    Value& operator()() {
        if(_error)
            std::rethrow_exception(_error);
        return _result;
    }

    bool error() const { return !!_error; }
    explicit operator bool() const { return _result || _error; }
};

//! builder for pvRequest blob
struct PVXS_API Request {

    Request& parse(const std::string& expr);

    Request& field(const std::string& name);

private:
    void _record(const std::string& name, const std::type_info& info, const void* val);
public:
    template<typename T>
    Request& record(const std::string& name, const T& v) {
        _record(name, typeid(T), static_cast<const void*>(&v));
        return *this;
    }

    inline explicit operator bool() const { return pvt.operator bool(); }
    struct Pvt;
private:
    std::shared_ptr<Pvt> pvt;
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

    virtual void cancel() =0;
};

//! Handle for monitor subscription
struct PVXS_API Subscription {
    enum Event {
        Error,
        Disconnect,
        NotEmpty,
    };

    virtual ~Subscription() =0;

    virtual void cancel() =0;
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

    //! An empty/dummy Server
    constexpr Context() = default;
    //! Create/allocate, but do not start, a new server with the provided config.
    //! Config::build() is a convienent shorthand.
    explicit Context(const Config &);
    ~Context();

    //! effective config
    const Config& config() const;

    //! Request prompt search of any disconnected channels
    void hurryUp();

    Request request() const;

    inline
    GetBuilder get(const std::string& name);

    /** Request type information from PV.
     *  Results in a Value with no marked fields.
     *
     * @code
     * Context ctxt(...);
     * auto op = ctxt.info("pv:name")
     *               .result([](Result&& prototype){
     *                  std::cout<<prototype();
     *               })
     *               .exec();
     * @endcode
     */
    inline
    GetBuilder info(const std::string& name);

    inline
    PutBuilder put(const std::string& name);

    inline
    RPCBuilder rpc(const std::string& name, Value&& arg);

    inline
    MonitorBuilder monitor(const std::string& name);

    explicit operator bool() const { return pvt.operator bool(); }
private:
    std::shared_ptr<Pvt> pvt;
};

//! Options common to all operations
template<typename SubBuilder>
class CommonBuilder {
protected:
    std::shared_ptr<Context::Pvt> ctx;
    std::string _name;
    Request _pvRequest;
    std::string _server;
    int _prio;
    CommonBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) : ctx(ctx), _name(name), _prio(0) {}
    inline SubBuilder& _sb() { return static_cast<SubBuilder&>(*this); }
public:
    SubBuilder& priority(int p) { _prio = p; return _sb(); }
    SubBuilder& request(const Request& r) { _pvRequest = r; return _sb(); }
    SubBuilder& server(const std::string& s) { _server = s; return _sb(); }
};

class GetBuilder : public CommonBuilder<GetBuilder> {
    std::function<void(Result&&)> _result;
    bool _get;
    PVXS_API
    std::shared_ptr<Operation> _exec_info();
    PVXS_API
    std::shared_ptr<Operation> _exec_get();
public:
    GetBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name, bool get) :CommonBuilder{ctx,name}, _get(get) {}
    //! Callback through which result Value will be delivered
    GetBuilder& result(decltype (_result)&& cb) { _result = std::move(cb); return *this; }

    //! Initiate network operation.
    inline std::shared_ptr<Operation> exec() {
        return _get ? _exec_get() : _exec_info();
    }

    friend struct Context::Pvt;
};
GetBuilder Context::info(const std::string& name) { return GetBuilder{pvt, name, false}; }
GetBuilder Context::get(const std::string& name) { return GetBuilder{pvt, name, true}; }

class PutBuilder : protected CommonBuilder<GetBuilder> {
    bool _doGet = true;
    std::function<Value(Value&&)> _builder;
    std::function<void(Result&&)> _result;
public:
    PutBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) :CommonBuilder{ctx,name} {}
    PutBuilder& result(decltype (_result)&& cb) { _result = std::move(cb); return *this; }

    PVXS_API
    std::shared_ptr<Operation> exec();

    friend struct Context::Pvt;
};
PutBuilder Context::put(const std::string& name) { return PutBuilder{pvt, name}; }

class RPCBuilder : protected CommonBuilder<GetBuilder> {
    Value _argument;
    std::function<void(Result&&)> _result;
public:
    RPCBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name, Value&& arg) :CommonBuilder{ctx,name}, _argument(std::move(arg)) {}
    RPCBuilder& result(decltype (_result)&& cb) { _result = std::move(cb); return *this; }

    PVXS_API
    std::shared_ptr<Operation> exec();

    friend struct Context::Pvt;
};
RPCBuilder Context::rpc(const std::string& name, Value&& arg) { return RPCBuilder{pvt, name, std::move(arg)}; }

class MonitorBuilder : protected CommonBuilder<GetBuilder> {
    std::function<void(const std::shared_ptr<Subscription>&, Subscription::Event)> _event;
public:
    MonitorBuilder(const std::shared_ptr<Context::Pvt>& ctx, const std::string& name) :CommonBuilder{ctx,name} {}

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
