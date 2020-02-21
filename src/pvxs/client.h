/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CLIENT_H
#define PVXS_CLIENT_H

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
        Info,
        Get,
        Put,
        RPC,
        Monitor,
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

    //! Options common to all operations
    template<typename SubBuilder>
    class CommonBuilder {
    protected:
        std::shared_ptr<Pvt> pvt;
        std::string _name;
        Request _pvRequest;
        std::string _server;
        int _prio;
        CommonBuilder(const std::shared_ptr<Pvt>& pvt, const std::string& name) : pvt(pvt), _name(name), _prio(0) {}
        inline SubBuilder& _sb() { return static_cast<SubBuilder&>(*this); }
    public:
        SubBuilder& priority(int p) { _prio = p; return _sb(); }
        SubBuilder& request(const Request& r) { _pvRequest = r; return _sb(); }
        SubBuilder& server(const std::string& s) { _server = s; return _sb(); }
    };

    class GetBuilder : protected CommonBuilder<GetBuilder> {
        std::function<void(Value&&)> _result;
        bool _get;
    public:
        GetBuilder(const std::shared_ptr<Pvt>& pvt, const std::string& name, bool get) :CommonBuilder{pvt,name}, _get(get) {}
        //! Callback through which result Value will be delivered
        GetBuilder& result(decltype (_result)&& cb) { _result = std::move(cb); return *this; }

        //! Initiate network operation.
        PVXS_API
        std::shared_ptr<Operation> exec();

        friend struct Context::Pvt;
    };
    GetBuilder get(const std::string& name) { return GetBuilder{pvt, name, true}; }
    /** Request type information from PV.
     *  Results in a Value with no marked fields.
     *
     * @code
     * Context ctxt(...);
     * auto op = ctxt.info("pv:name")
     *               .result([](Value&& prototype){
     *                  std::cout<<prototype;
     *               })
     *               .exec();
     * @endcode
     */
    GetBuilder info(const std::string& name) { return GetBuilder{pvt, name, false}; }

    struct PutBuilder : protected CommonBuilder<GetBuilder> {
        bool _doGet = true;
        std::function<Value(Value&&)> _builder;
        std::function<void(Value&&)> _result;
    public:
        PutBuilder(const std::shared_ptr<Pvt>& pvt, const std::string& name) :CommonBuilder{pvt,name} {}

        PVXS_API
        std::shared_ptr<Operation> exec();

        friend struct Context::Pvt;
    };
    PutBuilder put(const std::string& name) { return PutBuilder{pvt, name}; }

    struct RPCBuilder : protected CommonBuilder<GetBuilder> {
        Value _argument;
        std::function<void(Value&&)> _result;
    public:
        RPCBuilder(const std::shared_ptr<Pvt>& pvt, const std::string& name, Value&& arg) :CommonBuilder{pvt,name}, _argument(std::move(arg)) {}

        PVXS_API
        std::shared_ptr<Operation> exec();

        friend struct Context::Pvt;
    };
    RPCBuilder rpc(const std::string& name, Value&& arg) { return RPCBuilder{pvt, name, std::move(arg)}; }

    struct MonitorBuilder : protected CommonBuilder<GetBuilder> {
        std::function<void(const std::shared_ptr<Subscription>&, Subscription::Event)> _event;
    public:
        MonitorBuilder(const std::shared_ptr<Pvt>& pvt, const std::string& name) :CommonBuilder{pvt,name} {}

        PVXS_API
        std::shared_ptr<Subscription> exec();

        friend struct Context::Pvt;
    };
    MonitorBuilder monitor(const std::string& name) { return MonitorBuilder{pvt, name}; }

    explicit operator bool() const { return pvt.operator bool(); }
private:
    std::shared_ptr<Pvt> pvt;
};

struct PVXS_API Config {
    std::vector<std::string> addressList;

    //! UDP port to bind.  Default is 5076.  May be zero, cf. Server::config() to find allocated port.
    unsigned short udp_port = 5076;
    //! Whether to populate the beacon address list automatically.  (recommended)
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
