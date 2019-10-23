/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef UDP_COLLECTOR_H
#define UDP_COLLECTOR_H

#include <functional>
#include <memory>
#include <tuple>

#include <pvxs/version.h>
#include "evhelper.h"

namespace pvxsimpl {

struct UDPCollector;
struct UDPManager;

struct UDPMsg {
    //! peer (source) address
    evsockaddr src;
    //! points to the first byte of each message in a packet, followed by an empty message
    const sbuf<const uint8_t>* msgs;

    //! attempt to queue a reply message
    bool reply(const void *msg, size_t msglen) const;

private:
    UDPCollector *collector;
    friend struct UDPCollector;
    explicit UDPMsg(UDPCollector *collector);
};

//! Represents a subscription to the UDPManager
struct PVXS_API UDPListener {
    //! automatically cancel()s
    ~UDPListener();
    //! Stop receiving packets.  Caller blocks until any in-progress callback has returned
    void cancel();
private:
    friend struct UDPCollector;
    friend struct UDPManager;
    evsockaddr dest;
    std::shared_ptr<UDPCollector> collector;
    std::function<void(const UDPMsg& msg)> cb;
};

//! Manage reception, fanout, and reply of UDP PVA on the well known port.
struct PVXS_API UDPManager
{
    //! get process-wide singleton.
    static UDPManager instance();
    virtual ~UDPManager();

    /** Create subscription for UDP packets.
     *
     * The provided callback functor will be invoked from a shared internal worker thread.
     * The callback should not block this worker for an extended period of time.
     *
     * UDPMsg::msgs has already passed basic validation and it may be assumed that
     * for each message:
     *
     * 1. Is at least 8 bytes
     * 2. Is an application message w/o segmentation
     * 3. Payload size field is consistent with total packet length (if decoded with correct endianness)
     *
     * The provided functor will be destroyed during UDPListener::cancel() or ~UDPListener
     *
     * @param dest Address to bind this socket.  Updated with actual address (cf. getsockname() ) after bind().
     * @param cb Called for each valid packet
     */
    std::unique_ptr<UDPListener> subscribe(evsockaddr& dest,
                                           std::function<void(const UDPMsg& msg)>&& cb);

    explicit operator bool() const { return !!pvt; }

    UDPManager();

    struct Pvt;
private:
    explicit inline UDPManager(const std::shared_ptr<Pvt>& pvt) :pvt(pvt) {}
    std::shared_ptr<Pvt> pvt;
    friend struct UDPListener;
    friend struct UDPCollector;
};

} // namespace pvxsimpl

#endif // UDP_COLLECTOR_H
