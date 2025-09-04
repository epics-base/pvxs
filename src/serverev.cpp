/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "serverev.h"

#include <atomic>
#include <cstdlib>
#include <functional>

#include <dbDefs.h>
#include <envDefs.h>
#include <epicsString.h>
#include <signal.h>

#include <pvxs/log.h>
#include <pvxs/server.h>

#include "configcerts.h"
#include "certstatusmanager.h"
#include "evhelper.h"
#include "serverconn.h"

namespace pvxs {
namespace server {

DEFINE_LOGGER(serverio, "pvxs.svr.io");
DEFINE_LOGGER(serversetup, "pvxs.svr.init");

ServerEv ServerEv::fromEnv(CustomServerCallback &custom_event_callback)
{
    return certs::Config::fromEnv().build(custom_event_callback);
}

ServerEv::ServerEv(const certs::Config &config, const CustomServerCallback &custom_cert_event_callback) : base_(config) {
    auto internal(std::make_shared<Pvt>(*this, custom_cert_event_callback));
    internal->self = internal;

    // external
    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        const auto trash(std::move(internal));
    });
}

void ServerEv::startCb() {
    // begin running custom server callback if configured
    if ( pvt->custom_server_callback )
        pvt->acceptor_loop.call([this]() {
             // Trigger the first custom server callback, with the initial interval period
             if(event_add(pvt->custom_server_callback_timer.get(), &kCustomCallbackIntervalInitial))
                 log_err_printf(serversetup, "Error enabling file monitor\n%s", "");
        });
}

void ServerEv::stopCb() {
    pvt->acceptor_loop.call([this]() {
        if (pvt->custom_server_callback_timer) {
            if (event_del(pvt->custom_server_callback_timer.get()))
                log_warn_printf(serversetup, "Error disabling custom server callback timer\n%s", "");
        }
    });
}

ServerEv::Pvt::Pvt(ServerEv &svr, const CustomServerCallback &custom_cert_event_callback)
    : acceptor_loop("PVXTCP", epicsThreadPriorityCAServerLow - 2)
    , custom_server_callback(custom_cert_event_callback)
    , custom_server_callback_timer(__FILE__, __LINE__, event_new(acceptor_loop.base, -1, EV_TIMEOUT, doCustomServerCallback, this)) {

    // Cast away constness as this is constructor and we know it is ok
    auto& cfg = const_cast<Config&>(svr.config());

    // Clean out GUID created by the base constructor
    cfg.guid.fill(0);

    // simplified GUID.
    // treat as 3x 32-bit unsigned.
    union {
        std::array<uint32_t, 3> i;
        std::array<uint8_t, 3*4> b;
    } pun{};
    static_assert (sizeof(pun)==12, "");

    // For PVACMS, generate a deterministic GUID based on "secure/PVAccess"
    const std::string input = "secure/PVAccess";

    // Simple deterministic hash function
    for (size_t idx = 0; idx < input.size(); idx++) {
        pun.b[idx % pun.b.size()] ^= input[idx];
        // Rotate bits to spread the entropy
        if ((idx + 1) % 4 == 0) {
            uint32_t& val = pun.i[idx / 4];
            val = (val << 13) | (val >> 19);
        }
    }

    // Add some fixed bits to ensure uniqueness from random GUIDs
    pun.b[0] |= 0x80; // Set high bit to mark as deterministic
    pun.b[11] = 0x42; // Magic number for PVACMS

    std::copy(pun.b.begin(), pun.b.end(), cfg.guid.begin());
}


void ServerEv::Pvt::doCustomServerCallback(evutil_socket_t fd, short evt, void* raw) {
    try {
        const auto pvt = static_cast<Pvt*>(raw);
        if (pvt && pvt->custom_server_callback) {
            auto next_timeval = pvt->custom_server_callback(evt);
            if (next_timeval.tv_sec == 0 && next_timeval.tv_usec == 0) {
                next_timeval = kCustomCallbackInterval;
            }
            if (next_timeval.tv_sec > 0 || next_timeval.tv_usec > 0) {
                if (event_add(pvt->custom_server_callback_timer.get(), &next_timeval))
                    log_err_printf(serverio, "Error re-enabling custom server callback%s\n", "");
            }
        }
    } catch (std::exception& e) {
        log_err_printf(serverio, "Unhandled error in custom server callback: %s\n", e.what());
    }
}

} // serverx
} // pvxs
