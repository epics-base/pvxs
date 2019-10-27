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
#include <vector>

#include <pvxs/version.h>
#include "evhelper.h"

namespace pvxsimpl {
struct UDPListener;
} // namespace pvxsimpl

namespace std {
template<>
struct default_delete<pvxsimpl::UDPListener> {
    PVXS_API void operator()(pvxsimpl::UDPListener*);
};
} // namespace std

namespace pvxsimpl {

struct UDPCollector;
struct UDPManager;

//! Manage reception, fanout, and reply of UDP PVA on the well known port.
struct PVXS_API UDPManager
{
    //! get process-wide singleton.
    static UDPManager instance();
    ~UDPManager();

    struct Beacon {
        SockAddr& src;
        SockAddr server;
        std::vector<uint8_t> guid;
        Beacon(SockAddr& src) :src(src) {}
    };
    std::unique_ptr<UDPListener> onBeacon(SockAddr& dest,
                                          std::function<void(const Beacon&)>&& cb);

    struct PVXS_API Search {
        SockAddr src;
        SockAddr server;
        std::vector<const char*> names;

        virtual bool reply(const void *msg, size_t msglen) const =0;
        virtual ~Search();
    };
    std::unique_ptr<UDPListener> onSearch(SockAddr& dest,
                                          std::function<void(const Search&)>&& cb);

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
