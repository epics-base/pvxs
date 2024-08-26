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

#define STATUS_LISTENER_PERIOD_MS 500

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

namespace pvxs {
namespace certs {

class Semaphore {
  public:
    explicit Semaphore(int count = 0)
      : count(count) {}

    void signal() {
        std::unique_lock<std::mutex> lock(mtx);
        ++count;
        cv.notify_one();
    }

    void wait(std::atomic<bool> &stop_flag) {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this, &stop_flag]() { return stop_flag.load() || count > 0; });
        --count;
    }

  private:
    std::mutex mtx;
    std::condition_variable cv;
    int count;
};

template <typename T>
class StatusListener {
    StatusListener(logger &logger, const T &config, std::atomic<bool> &stop_flag, std::function<void(const T &)> &&reconfigure_fn)
        : config_(config), reconfigure_fn_(std::move(reconfigure_fn)), stop_flag_(stop_flag), logger_(logger) {}

    inline ~StatusListener() { stopListening(); }

    inline void stopListening() {
        stop_flag_.store(true);  // Flag all listeners to stop - including others
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    inline CertificateStatus startListening(logger &logger,
                                            const T &config,
                                            const ossl_ptr<X509> &cert,  // Cert only has to remain in scope until this function returns as by then data will have been read to start subscription
                                            const std::function<void(const T &)> &&reconfigure_fn) {
        config_ = config;
        reconfigure_fn_ = std::move(reconfigure_fn);
        stop_flag_.store(false);
        worker_ = std::thread([this, &logger, &cert]() {
            // The certificate status subscription picks up all changes to the certificate status
            // It returns the first result
            // It reconfigures the connection if it gets UNKNOWN, EXPIRED, REVOKED or VALID
            // It will ignore changes from PENDING_APPROVAL to PENDING
            // Other transitions are not possible
            //  PENDING and PENDING APPROVAL can only be starting states (except as noted above)

            log_info_printf(logger, "Status Monitor: %s\n", "Starting");
            auto cert_status_manager = CertStatusManager::subscribe(cert, [this, &logger](const CertificateStatus&status) {
                if ( is_first_update_) {
                    // Just return this value
                    Guard G(lock_);
                    status_ = status;
                    status_valid_until_ = status.status_valid_until_date.t;
                    is_first_update_ = false;
                } else {
                    switch (status.status.i) {
                        case UNKNOWN:
                        case EXPIRED:
                        case REVOKED:
                        case VALID:
                            log_err_printf(logger, "Status Monitor: certificate transitioned from %s => %s: reconfiguring", status_.status.s, status.status.s);
                            handleStatusChange(status);
                            break;
                        case PENDING:
                            if ( status_ == PENDING_APPROVAL ) {
                                // ignore changes from PENDING_APPROVAL to PENDING (cert not yet valid because of date)
                                Guard G(lock_);
                                status_ = status;
                                status_valid_until_ = status.status_valid_until_date.t;
                                break;
                            }
                        default:
                            break;
                    }
                }
            });

            // Check for availability of CMS service by periodically polling
            // at intervals corresponding to the certificate state valid until time
            // if it is not available then we reconfigure the connection but if its
            // available we just continue to poll
            // State changes are handled in the subscription
            while (!stop_flag_.load()) {
                Guard G(lock_);
                auto time_to_wait_until = status_valid_until_;
                UnGuard U(G);
                time_t time_to_wait = time_to_wait_until - std::time(nullptr) - 1;
                std::this_thread::sleep_for(std::chrono::seconds(time_to_wait));
                try {
                    auto status = cert_status_manager.get()->getStatus();
                    if (  status_valid_until_ == time_to_wait_until && status_ == status) {
                        // if the time to wait has not been updated and the status has not changed then just wait
                        // again until the next validity time in the newly read status.
                        // If the status has been updated by the subscription we ignore it here
                        Guard G1(lock_);
                        status_valid_until_ = status.status_valid_until_date.t;
                    }
                } catch (std::exception &e) {
                    // If the PVACMS is unavailable we will fall into this case
                    // Just reconfigure: unavailability of service will mean a downgraded or
                    // closed connection depending on configuration
                    log_err_printf(logger, "Status Monitor: PVACMS unavailable: %s", e.what());
                    handleStatusChange(UNKNOWN);
                }
            }
            cert_status_manager.get()->unsubscribe();
            log_info_printf(logger, "Status Monitor: %s\n", "Stopping");
        });
        // Wait for first status to be available (or stopping)
        first_status_available_.wait(stop_flag_);
        return status_;
    }

   private:
    const T &config_;
    const std::function<void(const T &config)> reconfigure_fn_;
    std::atomic<bool> &stop_flag_;
    Semaphore first_status_available_{0};
    logger &logger_;
    epicsMutex lock_;

    std::thread worker_;
    bool is_first_update_{true};
    CertificateStatus status_;
    time_t &status_valid_until_;

    /**
     * @brief Handles the status changes by reconfiguring the connection
     *
     * We need to exit this status listener first because the reconfigure function may
     * start a new status listener.
     *
     * But as this status listener and its thread will no longer exist once it is exited,
     * we need to run in a detached thread and we need to make sure
     * we have copied or moved versions of the parameters from its members
     */
    inline void handleStatusChange(const CertificateStatus&status) {
        stopListening();
        auto reconfigure_fn = std::move(reconfigure_fn_);
        auto config_copy = config_;
        std::thread([reconfigure_fn, config_copy]() mutable { reconfigure_fn(config_copy); }).detach();
    }
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_STATUS_LISTENER_H_
