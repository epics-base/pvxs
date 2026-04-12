/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "statuscache.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <direct.h>
#  include <io.h>
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/file.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <pvxs/log.h>

#include "utilpvt.h"

DEFINE_LOGGER(cachelog, "pvxs.certs.cache");

namespace pvxs {
namespace certs {

namespace {

std::string cacheFilePath(const std::string &cert_id) {
    return getStatusCacheDir() + "/" + cert_id + ".ocsp";
}

std::string cacheTempPath(const std::string &cert_id) {
    return getStatusCacheDir() + "/" + cert_id + ".ocsp.tmp";
}

bool ensureCacheDirExists() {
    const auto dir = getStatusCacheDir();
    // ensureDirectoryExists expects a filepath (directory + trailing sep + dummy)
    std::string probe = dir + "/x";
    try {
        ensureDirectoryExists(probe, false);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

std::string getStatusCacheDir() {
    const char *env = std::getenv("EPICS_PVA_STATUS_CACHE_DIR");
    if (env && env[0] != '\0')
        return env;
    return getXdgPvaDataHome() + "/status_cache";
}

bool isStatusCacheEnabled() {
    const char *env = std::getenv("EPICS_PVA_NO_STATUS_CACHE");
    if (!env)
        return true;
    try {
        return !parseTo<bool>(std::string(env));
    } catch (...) {
        return true;
    }
}

bool writeCacheFile(const std::string &cert_id, const uint8_t *data, size_t len) {
    if (cert_id.empty() || !data || len == 0)
        return false;

    if (!ensureCacheDirExists()) {
        log_debug_printf(cachelog, "Cannot create cache directory: %s\n",
                         getStatusCacheDir().c_str());
        return false;
    }

    const auto tmp = cacheTempPath(cert_id);
    const auto dst = cacheFilePath(cert_id);

    std::unique_ptr<FILE> fp(std::fopen(tmp.c_str(), "wb"));
    if (!fp) {
        log_debug_printf(cachelog, "Cannot open temp cache file %s: %s\n",
                         tmp.c_str(), std::strerror(errno));
        return false;
    }

    {
#ifndef _WIN32
        flock(fileno(fp.get()), LOCK_EX);
#endif
        if (std::fwrite(data, 1, len, fp.get()) != len) {
            log_debug_printf(cachelog, "Short write to %s\n", tmp.c_str());
            fp.reset();
            std::remove(tmp.c_str());
            return false;
        }
#ifndef _WIN32
        flock(fileno(fp.get()), LOCK_UN);
#endif
    }

    fp.reset(); // close before rename

    if (std::rename(tmp.c_str(), dst.c_str()) != 0) {
        log_debug_printf(cachelog, "Cannot rename %s -> %s: %s\n",
                         tmp.c_str(), dst.c_str(), std::strerror(errno));
        std::remove(tmp.c_str());
        return false;
    }

    log_debug_printf(cachelog, "Cached OCSP status for %s\n", cert_id.c_str());
    return true;
}

std::vector<uint8_t> readCacheFile(const std::string &cert_id) {
    if (cert_id.empty())
        return {};

    const auto path = cacheFilePath(cert_id);

    std::unique_ptr<FILE> fp(std::fopen(path.c_str(), "rb"));
    if (!fp)
        return {};

#ifndef _WIN32
    flock(fileno(fp.get()), LOCK_SH);
#endif

    if (std::fseek(fp.get(), 0, SEEK_END) != 0)
        return {};
    const long sz = std::ftell(fp.get());
    if (sz <= 0)
        return {};
    std::rewind(fp.get());

    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (std::fread(buf.data(), 1, buf.size(), fp.get()) != buf.size())
        return {};

#ifndef _WIN32
    flock(fileno(fp.get()), LOCK_UN);
#endif

    return buf;
}

void deleteCacheFile(const std::string &cert_id) {
    if (cert_id.empty())
        return;
    const auto path = cacheFilePath(cert_id);
    std::remove(path.c_str());
}

} // namespace certs
} // namespace pvxs
