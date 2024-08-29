/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CONFIG_H
#define PVXS_CONFIG_H

#ifdef __linux__
#include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>

#endif

#include <cctype>
#include <climits>
#include <fstream>
#include <iostream>
#include <iterator>
#include <list>
#include <map>

#include <libgen.h>

#ifdef __unix__
#include <pwd.h>
#endif
#include <regex>
#include <sstream>
#include <string>

#include <unistd.h>

#include <pvxs/version.h>

#include <sys/stat.h>

#include "osiFileName.h"

namespace pvxs {
namespace impl {

struct PVXS_API ConfigCommon {
    enum ConfigTarget { CLIENT, SERVER, GATEWAY } config_target = CLIENT;

    virtual ~ConfigCommon() = 0;

#ifdef PVXS_ENABLE_OPENSSL
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

    /**
     * @brief Ensure that the directory specified in the path exist
     * @param filepath the file path containing an optional directory component
     */
    void inline PVXS_API ensureDirectoryExists(std::string &filepath, bool convert_path = true) {
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
#endif  // EVENT2_HAS_OPENSSL

    //! TCP port to bind.  Default is 5075.  May be zero.
    unsigned short tcp_port = 5075;
    //! UDP port to bind.  Default is 5076.  May be zero, cf. Server::config()
    //! to find allocated port.
    unsigned short udp_port = 5076;

    //! Inactivity timeout interval for TCP connections.  (seconds)
    //! @since 0.2.0
    double tcpTimeout = 40.0;

#ifdef PVXS_ENABLE_OPENSSL
    //! TCP port to bind for TLS traffic.  Default is 5076
    //! @since UNRELEASED
    unsigned short tls_port = 5076;

    /**
     * @brief If TLS is disabled this is set to true.  This can happen
     * if no certificate file is found and can't be configured and this is a
     * server
     */
    bool tls_disabled = false;

    /** Path to PKCS#12 file containing certificates.
     *  @since UNRELEASED
     */
    std::string tls_cert_filename;

    /** Path to file containing password for certificate file.
     *  @since UNRELEASED
     */
    std::string tls_cert_password;

    /** Path to PKCS#12 file containing key.
     *  @since UNRELEASED
     */
    std::string tls_private_key_filename;

    /** Path to PKCS#12 file containing password for pkey file.
     *  @since UNRELEASED
     */
    std::string tls_private_key_password;

    /** Client certificate request during TLS handshake.
     *
     *  - Default.   Currently equivalent to Optional
     *  - Optional.  Server will ask for a client cert.  But will continue if none is provided.
     *               If a client cert. is provided, then it is validated.  An invalid cert.
     *               will fail the handshake.
     *  - Require.   Server will require a valid client cert. or the TLS handshake will fail.
     *
     *  @since UNRELEASED
     */
    enum CertificateRequiredness {
        Default,
        Optional,
        Require,
    } tls_client_cert_required = Default;

    /**
     * @brief Behaviour of server and client if the certificate expires
     * during the long running session.
     *  - FallbackToTCP.  Only for clients, this will reinitialise the
     * connection but in server-only authentication mode.
     *  - Shutdown.       This will stop the process immediately
     *  - Standby.        For servers, this will keep the server running but will reject all connections until the certificate has been renewed.
     */
    enum OnExpirationBehaviour {
        FallbackToTCP,
        Shutdown,
        Standby,
    } expiration_behaviour = FallbackToTCP;

    /**
     * True if the environment is configured for TLS.  All this means is that
     * the location of the certificate file has been specified in
     * EPICS_PVA_TLS_KEYCHAIN, and EPICS_PVA_TLS_PKEY.
     *
     * @return true if the location of the certificate file has been specified,
     * false otherwise
     */
    inline bool isTlsConfigured() const { return !tls_disabled && !tls_cert_filename.empty() && !tls_private_key_filename.empty(); }
#endif  // PVXS_ENABLE_OPENSSL

    inline std::string getFileContents(const std::string &file_name) {
        std::ifstream ifs(file_name);
        std::string contents((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

        if (!contents.empty() && contents.back() == '\n') {
            contents.pop_back();
        }

        return contents;
    }

    struct PickOne {
        const std::map<std::string, std::string> &defs;
        bool useenv;

        std::string name, val;

        bool operator()(std::initializer_list<const char *> names) {
            for (auto candidate : names) {
                if (useenv) {
                    if (auto eval = getenv(candidate)) {
                        name = candidate;
                        val = eval;
                        return true;
                    }

                } else {
                    auto it = defs.find(candidate);
                    if (it != defs.end()) {
                        name = candidate;
                        val = it->second;
                        return true;
                    }
                }
            }
            return false;
        }
    };
};
}  // namespace impl
}  // namespace pvxs

#endif  // PVXS_CONFIG_H
