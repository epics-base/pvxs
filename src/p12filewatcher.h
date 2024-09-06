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

#define FILE_WATCHER_PERIOD_MS 1000

namespace pvxs {
namespace certs {

struct FileWatcherParams {
    FileWatcherParams(logger &logger, const std::string &tls_private_key_filename, const std::string &tls_private_key_password,
                      const std::string &tls_cert_filename, const std::string &tls_cert_password, std::function<void()> &&reconfigure_fn,
                      std::atomic<bool> &stop_flag)
        : logger_(logger),
          tls_private_key_filename(tls_private_key_filename),
          tls_private_key_password(tls_private_key_password),
          tls_cert_filename(tls_cert_filename),
          tls_cert_password(tls_cert_password),
          reconfigure_fn(std::move(reconfigure_fn)),
          stop_flag(stop_flag) {}

    logger &logger_;
    const std::string &tls_private_key_filename;
    const std::string &tls_private_key_password;
    const std::string &tls_cert_filename;
    const std::string &tls_cert_password;
    const std::function<void()> reconfigure_fn;
    std::atomic<bool> &stop_flag;
};

class P12FileWatcher {
   public:
    P12FileWatcher(logger &logger, const std::string &tls_private_key_filename, const std::string &tls_private_key_password,
                   const std::string &tls_cert_filename, const std::string &tls_cert_password, std::atomic<bool> &stop_flag,
                   std::function<void()> &&reconfigure_fn)
        : file_watcher_params_(logger, tls_private_key_filename, tls_private_key_password, tls_cert_filename, tls_cert_password, std::move(reconfigure_fn),
                               stop_flag) {}

    inline ~P12FileWatcher() { stopWatching(); }

   private:
    const FileWatcherParams file_watcher_params_;
    epicsThreadOSD *file_watcher_thread_id_;

   public:
    /**
     * @brief Start watching all certificate files associated with the TLS connection
     */
    inline void startWatching() {
        epicsThreadOpts file_watcher_thread_options{epicsThreadPriorityLow, epicsThreadGetStackSize(epicsThreadStackSmall), 1};
        file_watcher_thread_id_ = epicsThreadCreateOpt("File Watcher", &workerThread, (void *)&file_watcher_params_, &file_watcher_thread_options);
    }

    inline void stopWatching() {
        log_debug_printf(file_watcher_params_.logger_, "File Watcher: %s\n", "Stop Called");
        file_watcher_params_.stop_flag = true;  // Flag watcher to stop
        epicsThreadMustJoin(file_watcher_thread_id_);
        log_debug_printf(file_watcher_params_.logger_, "File Watcher: %s\n", "Stopped");
    }

   private:
    static inline void workerThread(void *raw) {
        auto file_watcher_params = static_cast<FileWatcherParams *>(raw);
        worker(file_watcher_params);
    }

    static inline void worker(FileWatcherParams *file_watcher_params) {
        std::vector<std::string> paths_to_watch;
        std::vector<time_t> last_write_times;
        try {
            workerInit(file_watcher_params, paths_to_watch, last_write_times);
        } catch (std::exception &e) {
            // Start the file watching loop
            log_err_printf(file_watcher_params->logger_, "File Watcher: Error in startup: %s\n", e.what());
            return;  // Exit thread - File Watching is abandoned
        }

        // Start the file watcher
        workerTask(file_watcher_params, paths_to_watch, last_write_times);

        log_debug_printf(file_watcher_params->logger_, "File Watcher: %s\n", "Exited");
    }

    /**
     * @brief Initialise the File watcher.
     *
     * Get an initial read of the file modification times and which files exist
     *
     * @param paths_to_watch reference for vector to store the files to watch
     * @param last_write_times reference for vector to store initial modification times
     */
    static inline void workerInit(FileWatcherParams *file_watcher_params, std::vector<std::string> &paths_to_watch, std::vector<time_t> &last_write_times) {
        log_debug_printf(file_watcher_params->logger_, "File Watcher: %s\n", "Initializing");
        // Initialize a vector of file paths to watch
        paths_to_watch = {file_watcher_params->tls_cert_filename, file_watcher_params->tls_cert_password, file_watcher_params->tls_private_key_filename,
                          file_watcher_params->tls_private_key_password};

        // Initialize the last write times
        last_write_times.resize(paths_to_watch.size(), 0);
        for (size_t i = 0; i < paths_to_watch.size(); ++i) {
            if (!paths_to_watch[i].empty()) {
                try {
                    last_write_times[i] = getFileModificationTime(paths_to_watch[i]);
                } catch (...) {
                }
            }
        }
        log_debug_printf(file_watcher_params->logger_, "File Watcher: %s\n", "Initialised");
    }

    /**
     * @brief The File watcher task
     *
     * @param paths_to_watch the paths to watch
     * @param last_write_times the initial set of modification times that we are looking at
     */
    static inline void workerTask(FileWatcherParams *file_watcher_params, const std::vector<std::string> &paths_to_watch,
                                  std::vector<time_t> &last_write_times) {
        while (!file_watcher_params->stop_flag) {
            std::this_thread::sleep_for(std::chrono::milliseconds(FILE_WATCHER_PERIOD_MS));

            for (size_t i = 0; i < paths_to_watch.size(); ++i) {
                if (!paths_to_watch[i].empty()) {
                    time_t current_write_time;
                    try {
                        current_write_time = getFileModificationTime(paths_to_watch[i]);
                    } catch (...) {
                        if (last_write_times[i] != 0) {
                            log_debug_printf(file_watcher_params->logger_, "File Watcher: %s file was deleted\n", paths_to_watch[i].c_str());
                            file_watcher_params->reconfigure_fn();
                            break;
                        }
                        continue;
                    }
                    if (current_write_time != last_write_times[i]) {
                        log_debug_printf(file_watcher_params->logger_, "File Watcher: %s file was updated\n", paths_to_watch[i].c_str());
                        file_watcher_params->reconfigure_fn();
                        break;
                    }
                }
            }
        }
    }

    static inline time_t getFileModificationTime(const std::string &path) {
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
