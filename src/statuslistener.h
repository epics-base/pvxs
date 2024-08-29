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
    explicit Semaphore(int count = 0) : count(count) {}

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
   public:
    StatusListener(logger &logger, const T &config, std::atomic<bool> &stop_flag, ossl_ptr<X509> &&cert)
        : config_(config), cert_(std::move(cert)), stop_flag_(stop_flag), logger_(logger) {}

    inline ~StatusListener() { stopListening(); }

    /**
     * @brief Call to stop monitoring certificate status
     */
    inline void stopListening() {
        log_debug_printf(logger_, "Status Monitor: %s\n", "Stop Listening Called");
        stop_flag_.store(true);  // Flag listeners to stop
        try {
            if (worker_.joinable()) {
                log_debug_printf(logger_, "Status Monitor: %s\n", "Waiting for Worker Thread to Stop ...");
                worker_.join();
            }
            log_debug_printf(logger_, "Status Monitor: %s\n", "Stopped");
        } catch (...) {
        }
    }

    /**
     * @brief Start listening and responding to certificate status changes
     *
     * Each OCSP status change's signature is verified for authenticity.
     * It returns the first result so the caller can determine if the certificate is
     *
     * It reconfigures the connection if it gets UNKNOWN, EXPIRED, REVOKED or VALID
     * It will ignore changes from PENDING_APPROVAL to PENDING
     * Other transitions are not possible
     *  PENDING and PENDING APPROVAL can only be starting states (except as noted above)
     * @param reconfigure_fn
     * @return
     */
    inline CertificateStatus startListening(const std::function<void(const T &)> &&reconfigure_fn) {
        if (!CertStatusManager::shouldMonitor(cert_)) {
            return {};
        }

        reconfigure_fn_ = std::move(reconfigure_fn);
        stop_flag_.store(false);
        worker_ = std::thread([this]() {
            // The certificate status subscription picks up all changes to the certificate status
            // It returns the first result
            // It reconfigures the connection if it gets UNKNOWN, EXPIRED, REVOKED or VALID
            // It will ignore changes from PENDING_APPROVAL to PENDING
            // Other transitions are not possible
            //  PENDING and PENDING APPROVAL can only be starting states (except as noted above)

            log_debug_printf(logger_, "Status Monitor: %s\n", "Starting");
            try {
                // Subscribe to status changes and react
                auto && cert_status_manager = reactToStatusChanges();

                // Wait for first status to be available (or stopping)
                first_status_available_.wait(stop_flag_);

                // Start the status validity verification loop.
                verifyStatusValidity(std::move(cert_status_manager));
                log_debug_printf(logger_, "Status Monitor: %s\n", "Stopped");
            } catch (std::exception &e) {
                log_err_printf(logger_, "Status Monitor: Failed to Start: %s\n", e.what());
                stopListening();
            }
        });
        return status_;
    }

   private:
    const T &config_;
    std::function<void(const T &config)> reconfigure_fn_;
    const ossl_ptr<X509> &cert_;
    std::atomic<bool> &stop_flag_;
    logger &logger_;
    Semaphore first_status_available_{0};
    epicsMutex lock_;

    std::thread worker_;
    bool is_first_update_{true};
    CertificateStatus status_;
    std::time_t status_valid_until_{0};

    /**
     * @brief Respond to certificate status changes
     *
     * Create the subscription two certificates latest changes, and respond appropriately
     *
     * @return a CertStatusManager that could be used to get statuses periodically
     */
    inline cert_status_ptr<CertStatusManager> reactToStatusChanges() {
        auto cert_status_manager =  CertStatusManager::subscribe(cert_, [this](const CertificateStatus &status) {
            if (is_first_update_) {
                // Just return this value
                Guard G(lock_);
                status_ = status;
                status_valid_until_ = status.status_valid_until_date.t;
                is_first_update_ = false;
                first_status_available_.signal();
            } else {
                switch (status.status.i) {
                    case UNKNOWN:
                    case EXPIRED:
                    case REVOKED:
                    case VALID:
                        log_debug_printf(logger_, "Status Monitor: certificate transitioned from %s => %s: reconfiguring", status_.status.s.c_str(),
                                       status.status.s.c_str());
                        reconfigure_fn_(config_);
                        stop_flag_.store(true);
                        break;
                    case PENDING:
                        if (status_ == PENDING_APPROVAL) {
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
        return std::move(cert_status_manager);
    }

    /**
     * @brief Verify that the status  validity period is valid while the certificate
     * is being used
     *
     * We poll for new status at the end of the period and if the status is not available
     * (indicating that PVACMS is unavailable) then we call the reconfiguration
     * function that will create the appropriate new context.
     *
     * If any status changes happen in the meanwhile then they will be handled by
     * reactToStatusChanges.
     *
     * @param cert_status_manager the configured status manager to use to get status
     * @see reactToStatusChanges
     */
    inline void verifyStatusValidity(cert_status_ptr<CertStatusManager>  &&cert_status_manager) {
        while (!stop_flag_.load()) {
            Guard G(lock_);
            auto time_to_wait_until = status_valid_until_;
            UnGuard U(G);
            time_t time_to_wait = time_to_wait_until - std::time(nullptr) - 1;
            std::this_thread::sleep_for(std::chrono::seconds(time_to_wait));
            try {
                auto status = cert_status_manager->getStatus();
                if (status_valid_until_ == time_to_wait_until && status_ == status) {
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
                log_err_printf(logger_, "Status Monitor: PVACMS unavailable: %s\n", e.what());
                reconfigure_fn_(config_);
                break;
            }
        }
        cert_status_manager->unsubscribe();
        log_debug_printf(logger_, "Status Monitor: %s\n", "Exiting");
    }
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_STATUS_LISTENER_H_
