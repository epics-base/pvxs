#ifndef PVXS_SRVCOMMON_H
#define PVXS_SRVCOMMON_H

#if !defined(PVXS_SHAREDPV_H) && !defined(PVXS_SOURCE_H)
#  error Include <pvxs/sharedpv.h> or <pvxs/source.h>  Do not include srvcommon.h directly
#endif

#include <iosfwd>
#include <string>
#include <set>
#include <functional>

#include <pvxs/version.h>
#include <pvxs/util.h>
#include <pvxs/data.h>

namespace pvxs {
namespace server {

/** Credentials presented by a client.
 *
 * Primarily a way of presenting peer address and a remote user account name.
 * The method gives the authentication sub-protocol used and is presently one of:
 *
 * - "ca" - Client provided account name.
 * - "anonymous" - Client provided no credentials.  account will also be "anonymous".
 *
 * @since 0.2.0
 */
struct PVXS_API ClientCredentials {
    //! Peer address (eg. numeric IPv4)
    std::string peer;
    //! The local interface address (eg. numeric IPv4) through which this client is connected.
    //! May be a wildcard address (eg. 0.0.0.0) if the receiving socket is so bound.
    std::string iface;
    //! Authentication "method"
    std::string method;
    //! Remote user account name.  Meaning depends upon method.
    std::string account;
    //! (Copy of) Credentials blob as presented by the client.
    Value raw;
    /** Lookup (locally) roles associated with the account.
     *
     * On *nix targets this is the list of primary and secondary groups
     * in with the account is a member.
     * On Windows targets this returns the list of local groups for the account.
     * On other targets, an empty list is returned.
     */
    std::set<std::string> roles() const;
};

PVXS_API
std::ostream& operator<<(std::ostream&, const ClientCredentials&);

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
    const std::string _name;
    const std::shared_ptr<const ClientCredentials> _cred;
    const op_t _op;
public:
    //! The Client endpoint address in "X.X.X.X:Y" format.
    const std::string& peerName() const { return _cred->peer; }
    //! The Channel name
    const std::string& name() const { return _name; }
    //! Client credentials.  Never NULL.
    //! @since 0.2.0
    const std::shared_ptr<const ClientCredentials>& credentials() const { return _cred; }
    //! Operation type
    op_t op() const { return _op; }

    OpBase(const std::string& name,
           const std::shared_ptr<const ClientCredentials>& cred, op_t op)
        :_name(name)
        ,_cred(cred)
        ,_op(op)
    {}
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

protected:
    const Value _pvRequest;
public:
    //! Access to pvRequest blob
    //! @since 0.2.0
    const Value& pvRequest() const { return _pvRequest; }

    ExecOp(const std::string& name,
           const std::shared_ptr<const ClientCredentials>& cred, op_t op,
           const Value& pvRequest)
        :OpBase(name, cred, op)
        ,_pvRequest(pvRequest)
    {}
    virtual ~ExecOp();

#ifdef PVXS_EXPERT_API_ENABLED
    //! Create/start timer.  cb runs on worker associated with Channel of this Operation.
    //! @since 0.2.0
    Timer timerOneShot(double delay, std::function<void()>&& cb) {
        return _timerOneShot(delay, std::move(cb));
    }
#endif // PVXS_EXPERT_API_ENABLED
private:
    virtual Timer _timerOneShot(double delay, std::function<void()>&& cb) =0;
};

}} // namespace pvxs::server

#endif // PVXS_SRVCOMMON_H
