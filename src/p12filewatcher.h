#ifndef PVXS_P12FILEWATCHER_H_
#define PVXS_P12FILEWATCHER_H_

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

#ifdef _WIN32
#include <windows.h>
#endif
#include <pvxs/config.h>
#include <pvxs/log.h>

#include <sys/stat.h>

#include "utilpvt.h"

#define FILE_WATCHER_PERIOD_MS 500

namespace pvxs {
namespace certs {
template <typename T>
class P12FileWatcher {
   public:
    P12FileWatcher(logger &logger, const T &config, std::atomic<bool> &stop_flag, std::function<void(const T &)> &&reconfigure_fn)
        : config_(config), reconfigure_fn_(std::move(reconfigure_fn)), stop_flag_(stop_flag), logger_(logger) {}

    inline ~P12FileWatcher() { stopWatching(); }

    inline void startWatching() {
        worker_ = std::thread([this]() {
            log_info_printf(logger_, "File Watcher: %s\n", "Starting");

            if (auto config = dynamic_cast<const impl::ConfigCommon *>(&config_)) {
                // Initialize a vector of file paths to watch
                const std::vector<std::string> paths_to_watch = {config->tls_cert_filename, config->tls_cert_password, config->tls_private_key_filename,
                                                                 config->tls_private_key_password};

                // Initialize the last write times
                std::vector<time_t> last_write_times(paths_to_watch.size(), 0);
                for (size_t i = 0; i < paths_to_watch.size(); ++i) {
                    if (!paths_to_watch[i].empty()) {
                        try {
                            last_write_times[i] = getFileModificationTime(paths_to_watch[i]);
                        } catch (...) {
                            last_write_times[i] = 0;
                        }
                    }
                }

                // Start the file watching loop
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(FILE_WATCHER_PERIOD_MS));

                    for (size_t i = 0; i < paths_to_watch.size(); ++i) {
                        if (!paths_to_watch[i].empty()) {
                            time_t current_write_time;
                            try {
                                current_write_time = getFileModificationTime(paths_to_watch[i]);
                            } catch (...) {
                                if (last_write_times[i] != 0) {
                                    log_err_printf(logger_, "File Watcher: %s file was deleted\n", paths_to_watch[i].c_str());
                                    handleFileChange();
                                    return;
                                }
                                continue;
                            }
                            if (current_write_time != last_write_times[i]) {
                                log_info_printf(logger_, "File Watcher: %s file was updated\n", paths_to_watch[i].c_str());
                                handleFileChange();
                                return;
                            }
                        }
                    }
                }

                log_info_printf(logger_, "File Watcher: %s\n", "Stopping");
            } else {
                throw std::invalid_argument("Expected Config instance");
            }
        });
    }

    inline void stopWatching() {
        stop_flag_.store(true);  // Flag all listeners to stop - including others
        if (worker_.joinable()) { // wait for this one to stop
            worker_.join();
        }
    }

   private:
    const T &config_;
    const std::function<void(const T &config)> reconfigure_fn_;
    std::atomic<bool> &stop_flag_;
    logger &logger_;

    std::thread worker_;

    inline time_t getFileModificationTime(const std::string &path) const {
#ifdef _WIN32
        WIN32_FILE_ATTRIBUTE_DATA file_info;
        if (GetFileAttributesEx(path.c_str(), GetFileExInfoStandard, &file_info)) {
            SYSTEMTIME st;
            FileTimeToSystemTime(&file_info.ftLastWriteTime, &st);
            std::tm t = {};
            t.tm_year = st.wYear - 1900;
            t.tm_mon = st.wMonth - 1;
            t.tm_mday = st.wDay;
            t.tm_hour = st.wHour;
            t.tm_min = st.wMinute;
            t.tm_sec = st.wSecond;
            return std::mktime(&t);
        } else {
            throw std::runtime_error("Could not get file attributes");
        }
#else
        struct stat file_info {};
        if (stat(path.c_str(), &file_info) == 0) {
            return file_info.st_mtime;
        } else {
            throw std::runtime_error("Could not stat file");
        }
#endif
    }

    /**
     * @brief Handles the file changes by reconfiguring the connection
     *
     * We need to exit this file watcher first because the reconfigure function may
     * start a new file watcher.
     *
     * But as this file watcher and its thread will no longer exist once it is exited,
     * we need to run in a detached thread and we need to make sure
     * we have copied or moved versions of the parameters from its members
     */
    inline void handleFileChange() {
        stopWatching();
        auto reconfigure_fn = std::move(reconfigure_fn_);
        auto config_copy = config_;
        std::thread([reconfigure_fn, config_copy]() mutable { reconfigure_fn(config_copy); }).detach();
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_P12FILEWATCHER_H_
