/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * Disk-based caching of signed OCSP response bytes.
 *
 *   statuscache.h
 *
 * @since UNRELEASED
 */
#ifndef PVXS_STATUSCACHE_H_
#define PVXS_STATUSCACHE_H_

#include <cstdint>
#include <string>
#include <vector>

namespace pvxs {
namespace certs {

/**
 * @brief Get the status cache directory path.
 *
 * Resolves EPICS_PVA_STATUS_CACHE_DIR environment variable.
 * Falls back to ${XDG_DATA_HOME}/pva/<version>/status_cache/.
 *
 * @return cache directory path (without trailing separator)
 * @since UNRELEASED
 */
std::string getStatusCacheDir();

/**
 * @brief Check whether disk caching of certificate status is enabled.
 *
 * Returns false when EPICS_PVA_NO_STATUS_CACHE is set to a truthy
 * value (YES, TRUE, 1, ...).
 *
 * @return true if caching is enabled
 * @since UNRELEASED
 */
bool isStatusCacheEnabled();

/**
 * @brief Write OCSP response bytes to the cache atomically.
 *
 * Writes to a temporary file then renames, so readers never see a
 * partial file.  Creates the cache directory (mode 0700) on first
 * call.  Uses advisory file locking for additional safety.
 *
 * @param cert_id  certificate identifier (issuer_id:serial)
 * @param data     raw signed OCSP response bytes
 * @param len      byte count
 * @return true on success
 * @since UNRELEASED
 */
bool writeCacheFile(const std::string &cert_id,
                    const uint8_t *data, size_t len);

/**
 * @brief Read cached OCSP response bytes.
 *
 * Returns an empty vector on any failure (missing file, I/O error).
 * Uses advisory file locking for read safety.
 *
 * @param cert_id  certificate identifier (issuer_id:serial)
 * @return raw bytes, or empty on failure
 * @since UNRELEASED
 */
std::vector<uint8_t> readCacheFile(const std::string &cert_id);

/**
 * @brief Delete a cached OCSP response file if it exists.
 *
 * @param cert_id  certificate identifier (issuer_id:serial)
 * @since UNRELEASED
 */
void deleteCacheFile(const std::string &cert_id);

} // namespace certs
} // namespace pvxs

#endif // PVXS_STATUSCACHE_H_
