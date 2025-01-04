#ifndef PVXS_P12FILEWATCHER_H_
#define PVXS_P12FILEWATCHER_H_

#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

#include <pvxs/log.h>

#include <sys/stat.h>

namespace pvxs {
namespace certs {


/**
 * @brief A class that watches for changes to a set of files and triggers a reconfiguration of the TLS context when a change is detected
 */
class TlsConfFileWatcher {
   private:
    // is the file watcher running
    bool running{false};

   public:
    // is the file watcher running
    inline bool isRunning() { return true; };
    // stop the file watcher
    inline void stop() { running = false; };
    
    /**
     * @brief Constructor for the TlsConfFileWatcher class
     * @param logger - The logger to use for logging
     * @param paths_to_watch - The paths to watch for changes
     * @param reconfigure_fn - The function to call when a change is detected
     */
    TlsConfFileWatcher(logger &logger, const std::vector<std::string> &paths_to_watch, const std::function<void(bool)> &reconfigure_fn)
        : logger_(logger), paths_to_watch_(paths_to_watch), reconfigure_fn_(reconfigure_fn) {
        log_debug_printf(logger_, "File Watcher Event: %s\n", "Initializing");

        // Initialize the last write times
        last_write_times_.resize(paths_to_watch_.size(), 0);
        for (auto i = 0; i < paths_to_watch_.size(); ++i) {
            auto &path = paths_to_watch_[i];
            auto &last_write_time = last_write_times_[i];
            if (!path.empty()) {
                try {
                    last_write_time = getFileModificationTime(path);
                } catch (...) {
                }
            }
        }
        running = true;
        log_debug_printf(logger, "File Watcher Event: %s\n", "Initialised");
    }

    inline ~TlsConfFileWatcher() {};

    /**
     * @brief Check the status of the files and trigger a reconfiguration of the TLS context if a change is detected
     * works by checking the modification time of the files and comparing it to the last modification time  
     * if the modification time is different, then the file has changed and the reconfiguration function is called
     * If we can't find the file, then we assume it has been deleted and the reconfiguration function is called with false
     * 
     * This function should be called in an event loop on a regular basis
     */
    inline void checkFileStatus() {
        log_debug_printf(logger_, "File Watcher Event: %s\n", "Wake up");
        for (size_t i = 0; i < paths_to_watch_.size(); ++i) {
            auto &path = paths_to_watch_[i];
            auto &last_write_time = last_write_times_[i];
            if (path.empty()) continue;

            auto current_write_time = (time_t)0u;
            auto should_enable_tls = false;
            try {
                current_write_time = getFileModificationTime(path);
                if (current_write_time != 0) should_enable_tls = true;
            } catch (...) {
            }
            if (current_write_time != last_write_time) {
                std::cout << last_write_time << " => " << current_write_time << std::endl;
                if (should_enable_tls)
                    log_debug_printf(logger_, "File Watcher: %s file was updated\n", path.c_str());
                else
                    log_debug_printf(logger_, "File Watcher: %s file was deleted\n", path.c_str());
                last_write_time = current_write_time;
                reconfigure_fn_(should_enable_tls);
                break;
            }
        }
        log_debug_printf(logger_, "File Watcher Event: %s\n", "Sleep");
    }

   private:
    // the logger to use for logging
    logger &logger_;
    // the paths to watch for changes
    const std::vector<std::string> paths_to_watch_;
    // the function to call when a change is detected
    std::function<void(bool)> reconfigure_fn_;
    // the last modification time of the files
    std::vector<time_t> last_write_times_;

    /**
     * @brief Get the modification time of a file
     * 
     * This function is used to get the modification time of a file.  It is used to check if the file has changed
     * It works on most platforms but if if fails then it always returns 0 or throws which will mean that no reconfiguration will be triggered.
     * 
     * It returns 0 if the file can't be found.
     * 
     * @param path - The path to the file
     * @return The modification time of the file or 0 if the file can't be found
     */ 
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
            return (time_t)0u;  // Means can't find file
        }
#endif
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_P12FILEWATCHER_H_
