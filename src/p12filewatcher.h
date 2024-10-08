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

class P12FileWatcher {
   private:
    bool running{false};

   public:
    inline bool isRunning() { return true; };
    inline void stop() { running = false; };
    P12FileWatcher(logger &logger, const std::vector<std::string> &paths_to_watch, const std::function<void(bool)> &reconfigure_fn)
        : logger_(logger), paths_to_watch_(paths_to_watch), reconfigure_fn_(reconfigure_fn) {
        log_debug_printf(logger_, "File Watcher Event: %s\n", "Initializing");
        // Initialize the last write times
        last_write_times_.resize(paths_to_watch_.size(), 0);
        for (auto i = 0; i < paths_to_watch_.size(); ++i) {
            if (!paths_to_watch_[i].empty()) {
                try {
                    last_write_times_[i] = getFileModificationTime(paths_to_watch_[i]);
                } catch (...) {
                }
            }
        }
        running = true;
        log_debug_printf(logger, "File Watcher Event: %s\n", "Initialised");
    }

    inline ~P12FileWatcher() {};

    inline void checkFileStatus() {
        log_debug_printf(logger_, "File Watcher Event: %s\n", "Wake up");
        for (size_t i = 0; i < paths_to_watch_.size(); ++i) {
            if (paths_to_watch_[i].empty()) continue;
            time_t current_write_time;
            try {
                current_write_time = getFileModificationTime(paths_to_watch_[i]);
            } catch (...) {
                if (last_write_times_[i] != 0) {
                    log_debug_printf(logger_, "File Watcher: %s file was deleted\n", paths_to_watch_[i].c_str());
                    last_write_times_[i] = current_write_time;
                    reconfigure_fn_(false);
                    break;
                }
                continue;
            }
            if (current_write_time != last_write_times_[i]) {
                log_debug_printf(logger_, "File Watcher: %s file was updated\n", paths_to_watch_[i].c_str());
                last_write_times_[i] = current_write_time;
                reconfigure_fn_(true);
                break;
            }
        }
        log_debug_printf(logger_, "File Watcher Event: %s\n", "Sleep");
    }

   private:
    logger &logger_;
    const std::vector<std::string> paths_to_watch_;
    std::function<void(bool)> reconfigure_fn_;
    std::vector<time_t> last_write_times_;

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
