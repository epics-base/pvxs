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

    /**
     * @brief Start watching all certificate files associated with the TLS connection
     */
    inline void startWatching() {
        worker_ = std::thread([this]() {
            std::vector<std::string> paths_to_watch;
            std::vector<time_t> last_write_times;
            try {
                init(paths_to_watch, last_write_times);
            } catch (std::exception &e) {
                // Start the file watching loop
                log_err_printf(logger_, "File Watcher: Error in startup: %s\n", e.what());
                return; // Exit thread - File Watching is abandoned
            }

            // Start the file watcher until something changes, then handle change and exit
            task(paths_to_watch, last_write_times);
            log_info_printf(logger_, "File Watcher: %s\n", "Exited");
        });
    }

    /**
     * @brief Initialise the File watcher.
     *
     * Get an initial read of the file modification times and which files exist
     *
     * @param paths_to_watch reference for vector to store the files to watch
     * @param last_write_times reference for vector to store initial modification times
     */
    inline void init(std::vector<std::string> &paths_to_watch, std::vector<time_t> &last_write_times) {
        log_debug_printf(logger_, "File Watcher: %s\n", "Initializing");
        auto config = dynamic_cast<const impl::ConfigCommon *>(&config_);
        if (!config) {
            throw std::invalid_argument("Expected Config instance");
        }

        // Initialize a vector of file paths to watch
        paths_to_watch = {config->tls_cert_filename, config->tls_cert_password,
                          config->tls_private_key_filename,
                          config->tls_private_key_password};

        // Initialize the last write times
        last_write_times.resize(paths_to_watch.size(), 0);
        for (size_t i = 0; i < paths_to_watch.size(); ++i) {
            if (!paths_to_watch[i].empty()) {
                try {
                    last_write_times[i] = getFileModificationTime(paths_to_watch[i]);
                } catch (...) {}
            }
        }
        log_info_printf(logger_, "File Watcher: %s\n", "Initialised");
    }

    /**
     * @brief The File watcher task
     *
     * @param paths_to_watch the paths to watch
     * @param last_write_times the initial set of modification times that we are looking at
     */
    inline void task(const std::vector<std::string> &paths_to_watch, std::vector<time_t>
    &last_write_times) {
        while (!stop_flag_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(
              FILE_WATCHER_PERIOD_MS));

            for (size_t i = 0; i < paths_to_watch.size(); ++i) {
                if (!paths_to_watch[i].empty()) {
                    time_t current_write_time;
                    try {
                        current_write_time = getFileModificationTime(paths_to_watch[i]);
                    } catch (...) {
                        if (last_write_times[i] != 0) {
                            log_debug_printf(logger_,
                                           "File Watcher: %s file was deleted\n",
                                           paths_to_watch[i].c_str());
                            reconfigure_fn_(config_);
                            stop_flag_.store(true);
                            break;
                        }
                        continue;
                    }
                    if (current_write_time != last_write_times[i]) {
                        log_debug_printf(logger_,
                                        "File Watcher: %s file was updated\n",
                                        paths_to_watch[i].c_str());
                        reconfigure_fn_(config_);
                        stop_flag_.store(true);
                        break;
                    }
                }
            }
        }
    }

    inline void stopWatching() {
        log_debug_printf(logger_, "File Watcher: %s\n", "Stop Called");
        stop_flag_.store(true);  // Flag all listeners to stop
        if (worker_.joinable()) { // wait for this to stop
            log_debug_printf(logger_, "File Watcher: %s\n", "Stopping ...");
            worker_.join();
        }
        log_debug_printf(logger_, "File Watcher: %s\n", "Stopped");
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
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_P12FILEWATCHER_H_
