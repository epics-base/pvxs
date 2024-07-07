/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERTCONFIG_H_
#define PVXS_CERTCONFIG_H_

#include <cctype>
#include <climits>
#include <fstream>
#include <iostream>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>

#include <libgen.h>
#include <unistd.h>

#include <sys/stat.h>

#include "osiFileName.h"

class Config {
  public:
    virtual ~Config() = 0;

    /** Path to PKCS#12 file containing key and/or certificates. */
    std::string tls_keychain_filename;

    /** Path to PKCS#12 file containing password for keychain file. */
    std::string tls_keychain_password;

    inline std::string getFileContents(const std::string &file_name) {
        std::ifstream ifs(file_name);
        std::string contents((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

        if (!contents.empty() && contents.back() == '\n') {
            contents.pop_back();
        }

        return contents;
    }

/**
 * @brief Ensure that the directory specified in the path exist
 * @param filepath the file path containing an optional directory component
 */
    void inline ensureDirectoryExists(std::string &filepath, bool convert_path = true) {
        std::string temp_path = convert_path ? convertPath(filepath) : filepath;

        std::string delimiter = std::string(OSI_PATH_SEPARATOR);
        size_t pos = 0;
        std::string token;
        std::string path = "";
        struct stat info;
        while ((pos = temp_path.find(delimiter)) != std::string::npos) {
            token = temp_path.substr(0, pos);
            path += token + delimiter;
            temp_path.erase(0, pos + delimiter.length());
            if (stat(path.c_str(), &info) != 0 || !(info.st_mode & S_IFDIR)) {
                mkdir(path.c_str(), S_IRWXU);
            }
        }
    }

  private:
    /**
     * @brief Convert given path to expand tilde, dot and dot-dot at beginning
     * @param path the containing tilde, dot and/or dot-dot
     * @return the expanded path
     */
    std::string inline convertPath(std::string &path) {
        std::string abs_path;

        if (!path.empty()) {
            if (path[0] == '~') {
                char const *home = getenv("HOME");
                if (home || ((home = getenv("USERPROFILE")))) {
                    abs_path = home + path.substr(1);
                }
#ifdef __unix__
                else {
                    auto pw = getpwuid(getuid());
                    if (pw) abs_path = pw->pw_dir + path.substr(1);
                }
#endif
            } else if (path[0] == '.') {
                char temp[PATH_MAX];
                if (getcwd(temp, sizeof(temp)) != NULL) {
                    if (path.size() > 1 && path[1] == '.') {
                        // Handle '..' to get parent directory
                        abs_path = dirname(temp);
                        // Append the rest of the path after the '..'
                        abs_path += path.substr(2);
                    } else {
                        // Handle '.'
                        abs_path = temp + path.substr(1);  // remove '.' then append
                    }
                }
            }
        }

        if (abs_path.empty()) {
            abs_path = path;
        }

        return (path = abs_path);
    }
};

// This is the interface to create Config objects
class ConfigFactoryInterface {
   public:
    virtual std::unique_ptr<Config> create() = 0;
};

#endif  // PVXS_CERTCONFIG_H_
