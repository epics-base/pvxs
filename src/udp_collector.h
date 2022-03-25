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
#include <array>

#include <pvxs/version.h>
#include "evhelper.h"

namespace pvxs {namespace impl {
class UDPListener;
struct UDPCollector;
struct UDPManager;

//! Manage reception, fanout, and reply of UDP PVA on the well known port.
struct PVXS_API UDPManager
{
    SockAttach attach;

    //! get process-wide singleton.
    static UDPManager instance();
    static void cleanup();
    ~UDPManager();

    evbase& loop();

    struct Beacon {
        SockAddr& src;
        SockAddr server;
        ServerGUID guid;
        Beacon(SockAddr& src) :src(src) {}
    };
    //! Create subscription for Beacon messages.
    //! Must call UDPListener::start()
    std::unique_ptr<UDPListener> onBeacon(SockAddr& dest,
                                          std::function<void(const Beacon&)>&& cb);

    struct PVXS_API Search {
        SockAddr src;
        SockAddr server;
        uint32_t searchID;
        bool mustReply;
        struct Name {
            const char *name;
            uint32_t id;
        };

        std::vector<Name> names;

        decltype (names)::const_iterator begin() const { return names.begin(); }
        decltype (names)::const_iterator end() const   { return names.end(); }

        virtual bool reply(const void *msg, size_t msglen) const =0;
        virtual ~Search();
    };
    //! Create subscription for Search messages.
    //! Must call UDPListener::start()
    std::unique_ptr<UDPListener> onSearch(SockAddr& dest,
                                          std::function<void(const Search&)>&& cb);

    void sync();

    explicit operator bool() const { return !!pvt; }

    UDPManager();

    struct Pvt;
private:
    explicit inline UDPManager(const std::shared_ptr<Pvt>& pvt) :pvt(pvt) {}
    std::shared_ptr<Pvt> pvt;
    friend class UDPListener;
    friend struct UDPCollector;
};

class PVXS_API UDPListener
{
    std::function<void(UDPManager::Search&)> searchCB;
    std::function<void(UDPManager::Beacon&)> beaconCB;
    const std::shared_ptr<UDPManager::Pvt> manager;
    std::shared_ptr<UDPCollector> collector;
    const SockAddr dest;
    bool active;

    INST_COUNTER(UDPListener);

    friend struct UDPCollector;
    friend struct UDPManager;

public:
    UDPListener(const std::shared_ptr<UDPManager::Pvt>& manager, SockAddr& dest);
    ~UDPListener();

    void start(bool s=true);
    inline void stop() { start(false); }
};

}} // namespace pvxs::impl

#endif // UDP_COLLECTOR_H
