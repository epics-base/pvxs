#ifndef PVXS_P12FILEWATCHER_H_
#define PVXS_P12FILEWATCHER_H_

#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <vector>
#include <stdexcept>
#include <chrono>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif
#include <sys/stat.h>
#include <pvxs/config.h>
#include <pvxs/log.h>

#include "utilpvt.h"

#define FILE_WATCHER_PERIOD_MS 500

namespace pvxs {
namespace certs {

template <typename T>
class P12FileWatcher {
  public:
    P12FileWatcher(logger &logger, const T &config, const std::function<void(const T &)> &reconfigure_fn)
      : config_(config), reconfigure_fn_(reconfigure_fn), stop_flag_(false), logger_(logger) {}

    inline ~P12FileWatcher() {
        stopWatching();
    }

    inline void startWatching() {
        std::unique_lock<std::mutex> lock(mtx_);
        auto worker = [this]() {
            log_info_printf(logger_, "File Watcher: %s\n", "Starting");


            if (auto config = dynamic_cast<const impl::ConfigCommon*>(&config_)) {
                // Initialize a vector of file paths to watch
                const std::vector<std::string> paths_to_watch = {
                  config->tls_cert_filename,
                  config->tls_cert_password,
                  config->tls_private_key_filename,
                  config->tls_private_key_password
                };

                // Initialize the last write times
                std::vector<time_t> last_write_times(paths_to_watch.size(), 0);
                try {
                    for (size_t i = 0; i < paths_to_watch.size(); ++i) {
                        if (!paths_to_watch[i].empty()) {
                            last_write_times[i] = getFileModificationTime(paths_to_watch[i]);
                        }
                    }
                } catch (const std::runtime_error& e) {
                    log_err_printf(logger_, "File Watcher: %s\n", e.what());
                    return;
                }

                // Start the file watching loop
                while (!stop_flag_.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(FILE_WATCHER_PERIOD_MS));

                    try {
                        for (size_t i = 0; i < paths_to_watch.size(); ++i) {
                            if (!paths_to_watch[i].empty()) {
                                const time_t current_write_time = getFileModificationTime(paths_to_watch[i]);
                                if (current_write_time != last_write_times[i]) {
                                    last_write_times[i] = current_write_time;
                                    handleFileChange();
                                    return;
                                }
                            }
                        }
                    } catch (const std::runtime_error& e) {
                        log_err_printf(logger_, "File Watcher: A cert file was deleted: %s\n", e.what());
                        handleFileChange();
                        return;
                    }
                }

                log_info_printf(logger_, "File Watcher: %s\n", "Stopping");
            } else {
                throw std::invalid_argument("Expected Config instance");
            }
        };

        worker_ = std::thread(worker);
    }

    inline void stopWatching() {
        stop_flag_.store(true);
        cv_.notify_one();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

  private:
    const T &config_;
    const std::function<void(const T& config)> reconfigure_fn_;
    std::atomic<bool> stop_flag_;
    logger &logger_;

    std::thread worker_;
    std::mutex mtx_;
    std::condition_variable cv_;

    inline time_t getFileModificationTime(const std::string& path) const {
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
        struct stat file_info{};
        if (stat(path.c_str(), &file_info) == 0) {
            return file_info.st_mtime;
        } else {
            throw std::runtime_error("Could not stat file");
        }
#endif
    }

    inline void handleFileChange() {
        stopWatching();
        std::thread([this](){
            reconfigure_fn_(config_);
        }).detach();
    }
};

} // namespace certs
} // namespace pvxs

#endif // PVXS_P12FILEWATCHER_H_
