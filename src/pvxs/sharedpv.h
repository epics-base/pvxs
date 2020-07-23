/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SHAREDPV_H
#define PVXS_SHAREDPV_H

#include <functional>
#include <memory>
#include <map>

#include <pvxs/version.h>
#include "srvcommon.h"

namespace pvxs {
class Value;

namespace server {

struct ChannelControl;
struct Source;

/** A SharedPV is a single data value which may be accessed by multiple clients through a Server.
 *
 * On creation a SharedPV has no associated data structure, or data type.
 * This is set by calling open() to provide a data type, and initial data values.
 * Subsequent calls to post() will update this data structure (and send notifications
 * to subscribing clients).
 *
 * A later call to close() will force disconnect all clients, and discard the data value and type.
 * A further call to open() sets a new data value, which may be of a different data type.
 *
 * The onPut() and onRPC() methods attach functors which will be called each time a Put or RPC
 * operation is executed by a client.
 */
struct PVXS_API SharedPV
{
    //! Create a new SharedPV with a Put handler which post() s any client provided Value.
    static SharedPV buildMailbox();
    //! Create a new SharedPV with a Put handler which rejects any client provided Value.
    static SharedPV buildReadonly();

    ~SharedPV();

    inline explicit operator bool() const { return !!impl; }

    //! Attach this SharedPV with a new client channel.
    //! Not necessary when using StaticSource.
    //! eg. could call from Source::onCreate()
    void attach(std::unique_ptr<ChannelControl>&& op);

    //! Callback when the number of attach()d clients becomes non-zero.
    void onFirstConnect(std::function<void(SharedPV&)>&& fn);
    //! Callback when the number of attach()d clients becomes zero.
    void onLastDisconnect(std::function<void(SharedPV&)>&& fn);
    //! Callback when a client executes a new Put operation.
    void onPut(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);
    //! Callback when a client executes an RPC operation.
    //! @note RPC operations are allowed even when the SharedPV is not opened (isOpen()==false)
    void onRPC(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);

    /** Provide data type and initial value.  Allows clients to begin connecting.
     * @pre !isOpen()
     * @param initial Defines data type, and initial value
     */
    void open(const Value& initial);
    //! Test whether open() has been called w/o matching close()
    bool isOpen() const;
    //! Reverse the effects of open() and force disconnect any remaining clients.
    void close();

    //! Update the internal data value, and dispatch subscription updates to any clients.
    void post(const Value& val);
    //! query the internal data value and update the provided Value.
    void fetch(Value& val) const;
    //! Return a (shallow) copy of the internal data value
    Value fetch() const;

    struct Impl;
private:
    std::shared_ptr<Impl> impl;
};

/** Allow clients to find (through a Server) SharedPV instances by name.
 *
 * A single PV name may only be added once to a StaticSource.
 * However, a single SharedPV may be added multiple times with different PV names.
 */
struct PVXS_API StaticSource
{
    static StaticSource build();

    ~StaticSource();

    inline explicit operator bool() const { return !!impl; }

    //! Fetch the Source interface, which may be used with Server::addSource()
    std::shared_ptr<Source> source() const;

    //! call SharedPV::close() on all PVs
    void close();

    //! Add a new name through which a SharedPV may be addressed.
    StaticSource& add(const std::string& name, const SharedPV& pv);
    //! Remove a single name
    StaticSource& remove(const std::string& name);

    typedef std::map<std::string, SharedPV> list_t;
    list_t list() const;

    struct Impl;
private:
    std::shared_ptr<Impl> impl;
};

} // namespace server
} // namespace pvxs

#endif // PVXS_SHAREDPV_H
