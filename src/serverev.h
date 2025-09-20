/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SERVEREV_H
#define PVXS_SERVEREV_H

#include <functional>
#include <memory>
#include <string>

#include <osiSock.h>

#include <pvxs/server.h>

#include "serverconn.h"
#include "wildcardpv.h"

namespace pvxs {
namespace certs {
class Config;
}

namespace server {

using CustomServerCallback = std::function<timeval(short)>;
static constexpr timeval kCustomCallbackIntervalInitial{0, 0};
static constexpr timeval kCustomCallbackInterval{15, 0};

struct EnhancedConfig;

class PVXS_API ServerEv {
public:
    constexpr ServerEv() = default;
    ServerEv(const certs::Config &config, const CustomServerCallback &custom_cert_event_callback);
    ServerEv(const ServerEv&) = default;
    ServerEv(ServerEv&& o) = default;
    ServerEv& operator=(const ServerEv&) = default;
    ServerEv& operator=(ServerEv&& o) = default;
    ~ServerEv() = default;

    static ServerEv fromEnv(CustomServerCallback &custom_event_callback);
    ServerEv& start()     { startCb(); base_.start();                 return *this; }
    ServerEv& stop()      { stopCb();  base_.stop();                  return *this; }
    ServerEv& run()       { startCb(); base_.run();       stopCb();   return *this; }
    ServerEv& interrupt() {            base_.interrupt();             return *this; }
    void reconfigure(const Config&) { stopCb();  base_.reconfigure(Config()); startCb(); }
    const Config& config() const {return base_.config();}
    client::Config clientConfig() const;
    ServerEv& addPV(const std::string& name, const SharedPV& pv) { base_.addPV(name, pv); return *this; }
    ServerEv& removePV(const std::string& name) { base_.removePV(name); return *this;}
    ServerEv& addSource(const std::string& name, const std::shared_ptr<Source>& src, int order =0) { base_.addSource(name, src, order); return *this; }
    std::shared_ptr<Source> removeSource(const std::string& name, int order =0) { return base_.removeSource(name, order); }
    std::shared_ptr<Source> getSource(const std::string& name, int order =0) { return base_.getSource(name, order); }
    std::vector<std::pair<std::string, int> > listSource() { return base_.listSource(); }

#ifdef PVXS_EXPERT_API_ENABLED
    Report report(bool zero=true) const { return base_.report(zero);}
#endif

    explicit operator bool() const { return !!base_;}

    friend PVXS_API std::ostream& operator<<(std::ostream& strm, const ServerEv& serv) { return strm<<serv.base_;}

    struct Pvt;
private:
    Server base_;
    std::shared_ptr<Pvt> pvt;
    void startCb();
    void stopCb();
};

struct ServerEv::Pvt {
    std::weak_ptr<Pvt> self;
    evbase acceptor_loop;
    CustomServerCallback custom_server_callback;
    evevent custom_server_callback_timer;
    Pvt(ServerEv &svr, const CustomServerCallback &custom_cert_event_callback = nullptr );
    static void doCustomServerCallback(evutil_socket_t fd, short evt, void* raw);
};

} // serverx
} // pvxs

#endif //PVXS_SERVEREV_H
