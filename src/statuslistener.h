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

    bool wait_for(const std::chrono::milliseconds &duration) {
        std::unique_lock<std::mutex> lock(mtx);
        bool result = cv.wait_for(lock, duration, [this]() { return count > 0; });
        if (result && count > 0) {
            --count;
        }
        return result;
    }

   private:
    std::mutex mtx;
    std::condition_variable cv;
    int count;
};

struct StatusListenerParams {
    StatusListenerParams(logger &logger, ossl_ptr<X509> &&new_cert, const std::function<void()> &&reconfigure_fn, std::atomic<bool> &stop_flag)
        : logger(logger), cert(std::move(new_cert)), reconfigure_fn(std::move(reconfigure_fn)), stop_flag(stop_flag) {}

    logger &logger;
    ossl_ptr<X509> cert{nullptr, false};
    const std::function<void()> reconfigure_fn;
    std::atomic<bool> &stop_flag;

    Semaphore first_status_available{0};
    epicsMutex lock;
    ossl_ptr<X509> new_cert;
    std::condition_variable change_cert;
    bool is_first_update{true};
    CertificateStatus status{};
    std::time_t status_valid_until{0};
};

class StatusListener : public std::enable_shared_from_this<StatusListener> {
   public:
    StatusListener(logger &logger, std::atomic<bool> &stop_flag, ossl_ptr<X509> &&cert, const std::function<void()> &&reconfigure_fn)
        : status_listener_params_(logger, std::move(cert), std::move(reconfigure_fn), stop_flag) {}

    inline ~StatusListener() { stopListening(); }

    inline void changeCert(ossl_ptr<X509> &&new_cert) {
        {
            Guard G(status_listener_params_.lock);
            // Complicated
            status_listener_params_.new_cert = std::move(new_cert);
        }
        status_listener_params_.change_cert.notify_one();  // Notify the processing thread

        // Wait for the certificate change to be taken
        {
            Guard G(status_listener_params_.lock);
            //            status_listener_params_.change_cert.wait(status_listener_params_.lock);
        }
    }

    /**
     * @brief Call to stop monitoring certificate status
     */
    inline void stopListening(bool do_wait = true) {
        log_debug_printf(status_listener_params_.logger, "Status Monitor: %s\n", "Stop Listening Called");
        status_listener_params_.stop_flag = true;  // Flag listeners to stop
        if (do_wait) {
            epicsThreadMustJoin(status_listener_thread_id_);
            log_debug_printf(status_listener_params_.logger, "Status Monitor: %s\n", "Stopped");
        } else
            log_debug_printf(status_listener_params_.logger, "Status Monitor: %s\n", "Will stop asynchronously");
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
    inline CertificateStatus startListening() {
        epicsThreadOpts status_listener_thread_options{epicsThreadPriorityLow, epicsThreadGetStackSize(epicsThreadStackSmall), 1};
        status_listener_thread_id_ = epicsThreadCreateOpt("Status Listener", &workerThread, (void *)&status_listener_params_, &status_listener_thread_options);

        // Wait for first status to be available (or stopping)
        status_listener_params_.first_status_available.wait(status_listener_params_.stop_flag);
        return status_listener_params_.status;
    }

   private:
    static inline void workerThread(void *raw) {
        auto status_listener_params = static_cast<StatusListenerParams *>(raw);
        worker(status_listener_params);
    }

    static inline void worker(StatusListenerParams *status_listener_params) {
        status_listener_params->stop_flag = false;  // Make sure

        // The certificate status subscription picks up all changes to the certificate status
        // It returns the first result
        // It reconfigures the connection if it gets UNKNOWN, EXPIRED, REVOKED or VALID
        // It will ignore changes from PENDING_APPROVAL to PENDING
        // Other transitions are not possible
        //  PENDING and PENDING APPROVAL can only be starting states (except as noted above)

        log_debug_printf(status_listener_params->logger, "Status Monitor: %s\n", "Starting");
        try {
            // Subscribe to status changes and react
            auto &&cert_status_manager = reactToStatusChanges(status_listener_params);

            // Wait for first status to be available (or timeout)
            bool status_available = status_listener_params->first_status_available.wait_for(std::chrono::seconds(3));
            if (status_available) {
                // Start the status validity verification loop.
                log_debug_printf(status_listener_params->logger, "Status Validity Monitor: %s\n", "Starting");
                verifyStatusValidity(status_listener_params, std::move(cert_status_manager));
            }
            cert_status_manager->unsubscribe();
            log_debug_printf(status_listener_params->logger, "Status Validity Monitor: %s\n", "Stopped");
            log_debug_printf(status_listener_params->logger, "Status Monitor: %s\n", "Stopped");
        } catch (std::exception &e) {
            log_err_printf(status_listener_params->logger, "Status Monitor: Failed to Start: %s\n", e.what());
        }
    }

    StatusListenerParams status_listener_params_;
    epicsThreadOSD *status_listener_thread_id_;
    std::thread worker_;

    /**
     * @brief Respond to certificate status changes
     *
     * Create the subscription two certificates latest changes, and respond appropriately
     *
     * @return a CertStatusManager that could be used to get statuses periodically
     */
    static inline cert_status_ptr<CertStatusManager> reactToStatusChanges(StatusListenerParams *status_listener_params) {
        auto cert_status_manager = CertStatusManager::subscribe(
            std::move(status_listener_params->cert), status_listener_params->stop_flag, [status_listener_params](const CertificateStatus &status) {
                log_debug_printf(status_listener_params->logger, "Status Monitor: %s\n", "Started");
                if (status_listener_params->is_first_update) {
                    // Just return this value
                    Guard G(status_listener_params->lock);
                    status_listener_params->status = status;
                    status_listener_params->status_valid_until = status.status_valid_until_date.t;
                    status_listener_params->is_first_update = false;
                    status_listener_params->first_status_available.signal();
                } else {
                    switch (status.status.i) {
                        case UNKNOWN:
                        case EXPIRED:
                        case REVOKED:
                        case VALID:
                            log_debug_printf(status_listener_params->logger, "Status Monitor: certificate transitioned from %s => %s: reconfiguring",
                                             status_listener_params->status.status.s.c_str(), status.status.s.c_str());
                            status_listener_params->reconfigure_fn();
                            status_listener_params->stop_flag = true;
                            break;
                        case PENDING:
                            if (status_listener_params->status == PENDING_APPROVAL) {
                                // ignore changes from PENDING_APPROVAL to PENDING (cert not yet valid because of date)
                                Guard G(status_listener_params->lock);
                                status_listener_params->status = status;
                                status_listener_params->status_valid_until = status.status_valid_until_date.t;
                                break;
                            }
                        default:
                            break;
                    }
                }
            });
        return cert_status_manager;
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
    static inline void verifyStatusValidity(StatusListenerParams *status_listener_params, cert_status_ptr<CertStatusManager> &&cert_status_manager) {
        log_debug_printf(status_listener_params->logger, "Status Validity Monitor: %s\n", "Started");
        while (!status_listener_params->stop_flag) {
            Guard G(status_listener_params->lock);
            auto time_to_wait_until = status_listener_params->status_valid_until;
            UnGuard U(G);
            time_t time_to_wait = time_to_wait_until - std::time(nullptr) - 1;
            std::this_thread::sleep_for(std::chrono::seconds(time_to_wait));
            try {
                auto status = cert_status_manager->getStatus();
                if (status_listener_params->status_valid_until == time_to_wait_until && status_listener_params->status == status) {
                    // if the time to wait has not been updated and the status has not changed then just wait
                    // again until the next validity time in the newly read status.
                    // If the status has been updated by the subscription we ignore it here
                    Guard G1(status_listener_params->lock);
                    status_listener_params->status_valid_until = status.status_valid_until_date.t;
                }
            } catch (std::exception &e) {
                // If the PVACMS is unavailable we will fall into this case
                // Just reconfigure: unavailability of service will mean a downgraded or
                // closed connection depending on configuration
                log_err_printf(status_listener_params->logger, "Status Monitor: PVACMS unavailable: %s\n", e.what());
                status_listener_params->reconfigure_fn();
                break;
            }
        }
        log_debug_printf(status_listener_params->logger, "Status Monitor: %s\n", "Exiting");
    }
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_STATUS_LISTENER_H_
