// Created on 25/08/2024.
//

#ifndef PVXS_STATUS_LISTENER_H_
#define PVXS_STATUS_LISTENER_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <functional>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>

#include <sys/stat.h>

#include "certstatus.h"
#include "certstatusmanager.h"
#include "ownedptr.h"
#include "utilpvt.h"
#include "openssl.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

namespace pvxs {
namespace certs {

template<typename T>
class StatusListener {
   public:
    StatusListener() = default;

    static void handleStatusUpdates(CertificateStatus &new_status,
                                    CertificateStatus &current_status,
                                    logger &logger,
                                    std::function<T()> get_context_fn,
                                    std::function<void(T)> reconfigure_fn) {
        // If CMS is unavailable (UNKNOWN) and the prior status is still valid then fast return
        if (new_status == certs::UNKNOWN && current_status.isValid()) {
            log_debug_printf(logger, "Status Monitor: %s Status Still Valid\n", current_status.status.s.c_str());
            return;
        }

        // If the OCSP status went from GOOD to BAD or BAD to GOOD then reconfigure
        if (new_status == certs::OCSP_CERTSTATUS_GOOD || current_status == certs::OCSP_CERTSTATUS_GOOD) {
            log_warn_printf(logger, "Certificate Validity has changed: %s ==> %s\n", current_status.status.s.c_str(), new_status.status.s.c_str());
            T new_context;
            try {
                new_context = get_context_fn();
                if (new_status == certs::VALID) {
                    log_info_printf(logger, "TLS enabled for client: %s\n", "reconfiguring");
                } else {
                    log_info_printf(logger, "TLS Disabled for client: %s\n", "reconfiguring");
                }
            } catch (std::exception& e) {
                log_warn_printf(logger, "TLS disabled for client: reconfiguring: %s\n", e.what());
            }
            reconfigure_fn(new_context);
        }
        current_status = new_status;
    }
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_STATUS_LISTENER_H_
