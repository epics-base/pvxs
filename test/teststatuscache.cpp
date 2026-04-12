/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include <epicsUnitTest.h>
#include <testMain.h>
#include <envDefs.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>

#include "statuscache.h"

namespace {
using namespace pvxs;
using namespace pvxs::certs;

void cleanup(const std::string &cert_id)
{
    deleteCacheFile(cert_id);
}

void testWriteRead()
{
    testShow()<<__func__;

    const std::string cert_id("test_write_read");
    cleanup(cert_id);

    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    const size_t len = sizeof(data);

    bool ok = writeCacheFile(cert_id, data, len);
    testOk(ok, "writeCacheFile succeeds");

    auto result = readCacheFile(cert_id);
    testOk(result.size() == len, "readCacheFile returns correct size (%zu == %zu)",
           result.size(), len);
    testOk(std::equal(result.begin(), result.end(), data),
           "readCacheFile returns correct content");

    cleanup(cert_id);
}

void testReadMissing()
{
    testShow()<<__func__;

    auto result = readCacheFile("nonexistent_cert_id_xyz");
    testOk(result.empty(), "readCacheFile returns empty for missing file");
}

void testDeleteRemovesFile()
{
    testShow()<<__func__;

    const std::string cert_id("test_delete");
    const uint8_t data[] = {0x01, 0x02};
    writeCacheFile(cert_id, data, sizeof(data));

    auto before = readCacheFile(cert_id);
    testOk(!before.empty(), "file exists before delete");

    deleteCacheFile(cert_id);

    auto after = readCacheFile(cert_id);
    testOk(after.empty(), "file absent after delete");
}

void testDisabledByEnvVar()
{
    testShow()<<__func__;

    epicsEnvSet("EPICS_PVA_NO_STATUS_CACHE", "YES");
    testOk(!isStatusCacheEnabled(), "cache disabled when env=YES");

    epicsEnvSet("EPICS_PVA_NO_STATUS_CACHE", "TRUE");
    testOk(!isStatusCacheEnabled(), "cache disabled when env=TRUE");

    epicsEnvSet("EPICS_PVA_NO_STATUS_CACHE", "1");
    testOk(!isStatusCacheEnabled(), "cache disabled when env=1");

    epicsEnvSet("EPICS_PVA_NO_STATUS_CACHE", "NO");
    testOk(isStatusCacheEnabled(), "cache enabled when env=NO");

    epicsEnvSet("EPICS_PVA_NO_STATUS_CACHE", "");
    testOk(isStatusCacheEnabled(), "cache enabled when env is empty string");

#ifdef _WIN32
    _putenv_s("EPICS_PVA_NO_STATUS_CACHE", "");
#else
    unsetenv("EPICS_PVA_NO_STATUS_CACHE");
#endif
    testOk(isStatusCacheEnabled(), "cache enabled when env is unset");
}

void testAtomicWrite()
{
    testShow()<<__func__;

    const std::string cert_id("test_atomic");
    cleanup(cert_id);

    const uint8_t data[] = {0xCA, 0xFE};
    bool ok = writeCacheFile(cert_id, data, sizeof(data));
    testOk(ok, "writeCacheFile succeeds");

    auto result = readCacheFile(cert_id);
    testOk(!result.empty(), "final file is readable (no leftover .tmp)");
    testOk(result.size() == sizeof(data), "content size matches");

    cleanup(cert_id);
}

void testWriteEmptyInputs()
{
    testShow()<<__func__;

    const uint8_t data[] = {0x01};
    testOk(!writeCacheFile("", data, 1), "empty cert_id rejected");
    testOk(!writeCacheFile("x", nullptr, 1), "null data rejected");
    testOk(!writeCacheFile("x", data, 0), "zero length rejected");
}

void testReadEmptyCertId()
{
    testShow()<<__func__;

    auto result = readCacheFile("");
    testOk(result.empty(), "empty cert_id returns empty");
}

void testOverwrite()
{
    testShow()<<__func__;

    const std::string cert_id("test_overwrite");
    cleanup(cert_id);

    const uint8_t first[] = {0x01, 0x02};
    writeCacheFile(cert_id, first, sizeof(first));

    const uint8_t second[] = {0xAA, 0xBB, 0xCC};
    writeCacheFile(cert_id, second, sizeof(second));

    auto result = readCacheFile(cert_id);
    testOk(result.size() == sizeof(second), "overwritten file has new size");
    testOk(std::equal(result.begin(), result.end(), second),
           "overwritten file has new content");

    cleanup(cert_id);
}

void testCustomCacheDir()
{
    testShow()<<__func__;

    std::string custom_dir = getStatusCacheDir() + "_custom_test";
    epicsEnvSet("EPICS_PVA_STATUS_CACHE_DIR", custom_dir.c_str());

    testOk(getStatusCacheDir() == custom_dir,
           "getStatusCacheDir returns custom dir");

    const std::string cert_id("test_custom_dir");
    const uint8_t data[] = {0xFF};
    bool ok = writeCacheFile(cert_id, data, sizeof(data));
    testOk(ok, "writeCacheFile succeeds with custom dir");

    auto result = readCacheFile(cert_id);
    testOk(!result.empty(), "readCacheFile succeeds with custom dir");

    cleanup(cert_id);

#ifdef _WIN32
    _putenv_s("EPICS_PVA_STATUS_CACHE_DIR", "");
#else
    unsetenv("EPICS_PVA_STATUS_CACHE_DIR");
#endif
}

} // namespace

MAIN(teststatuscache)
{
    testPlan(24);
    testSetup();
    logger_config_env();
    testWriteRead();
    testReadMissing();
    testDeleteRemovesFile();
    testDisabledByEnvVar();
    testAtomicWrite();
    testWriteEmptyInputs();
    testReadEmptyCertId();
    testOverwrite();
    testCustomCacheDir();
    cleanup_for_valgrind();
    return testDone();
}
