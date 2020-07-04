#ifndef PVXS_SRVCOMMON_H
#define PVXS_SRVCOMMON_H

#if !defined(PVXS_SHAREDPV_H) && !defined(PVXS_SOURCE_H)
#  error Include <pvxs/sharedpv.h> or <pvxs/source.h>  Do not include srvcommon.h directly
#endif

#include <string>
#include <functional>

#include <pvxs/version.h>
#include <pvxs/data.h>

namespace pvxs {
namespace server {

//! Base for all operation classes
struct PVXS_API OpBase {
    enum op_t {
        None, //!< invalid
        Info, //!< A GET_FIELD operation
        Get,  //!< A GET operation
        Put,  //!< A PUT operation
        RPC,  //!< A RPC operation
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

    virtual ~OpBase() =0;

    //! Return authentication method name (eg. "ca") and raw client credentials
    virtual std::pair<std::string, Value> rawCredentials() const=0;
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

}} // namespace pvxs::server

#endif // PVXS_SRVCOMMON_H
