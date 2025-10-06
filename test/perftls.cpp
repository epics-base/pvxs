/*
 * Minimal performance test harness.
 * Starts pvacms from project_root/bin, prints progress messages, then stops it.
 * C++11, helpers in anonymous namespace inside pvxs namespace as requested.
 */

#include "perftls.h"

#include <algorithm>
#include <csignal>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <atomic>
#include <epicsThread.h>

#ifdef __linux__
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <time.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <ctime>

#include <ifaddrs.h>

#include <mach/mach.h>
#include <net/if.h>
#include <sys/resource.h>
#endif

#include <libgen.h>
#include <osiFileName.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <epicsTime.h>
#include <epicsVersion.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>

// Enable expert API (Timer, evbase)
#define PVXS_ENABLE_EXPERT_API
#include "evhelper.h"
#include "openssl.h"
// Internal wire helpers for computing encoded Value sizes (test-only)
#include "pvaproto.h"
#include "dataimpl.h"

// CLI11 for command-line parsing
#include <CLI/CLI.hpp>

#if defined(__APPLE__)
#include <pcap.h>
#endif

namespace pvxs {
namespace perf {

// Compute the PVA wire size (bytes) of a Value (type + data), for throughput calculations.
// Performance Test only: uses internal wire encoder.
static double wireSizeBytes(const Value& val) {
    using namespace pvxs::impl;
    std::vector<uint8_t> buf;
    buf.reserve(4096000);
    VectorOutBuf M(true, buf);
    to_wire_full(M, val);
    return static_cast<double>(M.consumed());
}

DEFINE_LOGGER(perflog, "pvxs.perf");
DEFINE_LOGGER(producerlog, "pvxs.perf.scenario.producer");
DEFINE_LOGGER(consumerlog, "pvxs.perf.scenario.consumer");

using namespace pvxs::members;

#ifdef __linux__
/**
 * Retrieve the current RSS (Resident Set Size) memory usage of the process
 *
 * @return The RSS memory usage in bytes
 */
std::uint64_t getRssBytes() {
    // Fast path: /proc/self/statm (field 2 = resident pages)
    FILE* f = std::fopen("/proc/self/statm", "r");
    if (!f)
        return 0;
    long pages_res = 0;
    long pages_total = 0;
    if (std::fscanf(f, "%ld %ld", &pages_total, &pages_res) != 2) {
        std::fclose(f);
        return 0;
    }
    std::fclose(f);
    const long page_size = sysconf(_SC_PAGESIZE);  // bytes per page
    return static_cast<std::uint64_t>(pages_res) * static_cast<std::uint64_t>(page_size);
}

// Return process CPU time (user+sys) in seconds
/**
 *
 * @return
 */
double procCPUSeconds() {
    timespec ts{};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0)
        return 0.0;
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

#elif defined(__APPLE__) || defined(__FreeBSD__)

// Return resident set size in bytes
std::uint64_t getRssBytes() {
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) !=
        KERN_SUCCESS) {
        return 0;
        }
    return info.resident_size;
}

// Return process CPU time (user+sys) in seconds
double procCPUSeconds() {
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    double user = static_cast<double>(ru.ru_utime.tv_sec) + ru.ru_utime.tv_usec / 1e6;
    double sys = static_cast<double>(ru.ru_stime.tv_sec) + ru.ru_stime.tv_usec / 1e6;
    return user + sys;
}

#endif

// Return wall clock (monotonic) in seconds
double wallSeconds() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
}

// Sample CPU usage since prior reading (percentage of one core)
double cpuPercentSince(const double w0, const double c0) {
    const double w1 = wallSeconds();
    const double c1 = procCPUSeconds();
    const double dw = w1 - w0;
    const double dc = c1 - c0;
    return dw > 0.0 ? dc / dw * 100.0 : 0.0;
}

/**
 * Add a value to the result
 * @param value The value to add
 */
int32_t Result::add(const double value) {
    if (value <= 0.0)
        return -1;

    Guard G(lock);

    const double delta = value - mean;
    mean += delta / static_cast<double>(++n);
    const double delta2 = value - mean;
    M2 += delta * delta2;

    // Update max and min transmission times
    if (value < min) min = value;
    if (value > max) max = value;

    return n;
}

/**
 * Print the results.
 * The results are printed in a table format with the following columns:
 * - The connection type of the test.
 * - The Transmission Rate.
 * - The Throughput.
 * - The PVAccess Payload.
 * - The minimum transmission time for the updates per second of the test.
 * - The maximum transmission time for the updates per second of the test.
 * - The CPU% of 1 Core during the test.
 * - The Memory Used.
 * - The Network Load.
 * - The Transmission Times per second of the test.
 * - The Dropped updates per second of the test.
 *
 *  @param scenario_type The scenario type of the test.
 *  @param payload_type The payload type of the test.
 *  @param payload_label The label of the payload type.
 *  @param rate The rate of the test.
 *  @param rate_label The label of the rate.
 *  @param cpu_percent The CPU% of 1 Core during the test.
 *  @param rss_mb The memory used during the test.
 *  @param bytes_captured The number of bytes captured during the test.
 *  @param cpu_percent The CPU% of 1 Core during the test.
 *  @param rss_mb The memory used during the test.
 *  @param bytes_captured The number of bytes captured during the test.
 */
void Result::print(const ScenarioType scenario_type, const PayloadType payload_type, const std::string &payload_label,
    const uint32_t rate, const std::string &rate_label, const double cpu_percent, const double rss_mb, uint64_t bytes_captured) const {
    // Wipe the progress bar
    std::cout << std::right << std::setw(155) <<" \r";

    // 1) Connection Type
    std::cout  << std::right << std::setw(15)
               << (scenario_type == TLS_CMS_STAPLED ? "TLS_CMS_STAPLED"
                  : scenario_type == TLS_CMS       ? "TLS_CMS"
                  : scenario_type == TLS           ? "TLS"
                                                   : "TCP")
               << ", ";

    // 2) PVAccess Payload
    std::cout << std::right << std::setw(13) << payload_label << ", ";

    // 3) Tx Rate
    std::cout << std::right << std::setw(13) << rate_label << ", ";

    // 4) Throughput
    std::string throughput_units = " bps";
    auto throughput = (payload_type == LARGE_2MB ? large_size : payload_type == MEDIUM_1KB ? medium_size : small_size) * 8.0 * static_cast<double>(rate);
    if      ( throughput >= 1000000000 ) { throughput /= 1000000000; throughput_units = "Gbps"; }
    else if ( throughput >= 1000000    ) { throughput /= 1000000;    throughput_units = "Mbps"; }
    else if ( throughput >= 1000       ) { throughput /= 1000;       throughput_units = "Kbps"; }
    std::cout << std::right << std::setw(9) << throughput << throughput_units << ", ";

    // 5) n, minimum / maximum transmission time
    std::cout << std::right << std::setw(8) << n << ", ";
    if (min < std::numeric_limits<double>::max())    std::cout << std::right << std::setw(10) << min*1000.0 << ", "; else std::cout << " , ";
    if (max > std::numeric_limits<double>::lowest()) std::cout << std::right << std::setw(10) << max*1000.0 << ", "; else std::cout << " ,  ";

    // 6) Mean, StdDev
    std::cout << std::right << std::setw(10) << mean*1000.0 << ", ";
    std::cout << std::right << std::setw(10) << stddev()*1000.0 <<  ", ";

    // 7) CPU% of 1 Core
    std::cout << std::right << std::setw(12) << cpu_percent << ", " ;

    // 8) Memory used
    std::cout << std::right << std::setw(12) << rss_mb << ", " ;

    // 9) Network load
    std::cout << std::right << std::setw(19) << bytes_captured;
}

void SubscriptionMonitor::run() {
    // Start a monitor subscription for the given payload type and set an appropriate queue size to avoid coalescing.
    self.startMonitor(payload, rate);

    auto end = std::time(nullptr);
    end += 67; // add 10% extra time to read everything

    // Wait until everything has finished
    while (end > std::time(nullptr)) {
        epicsThreadSleep(-1);
        if (self.stop_early.load(std::memory_order_relaxed)) break;
    }
}

void UpdateProducer::run() {
    const auto total = static_cast<uint32_t>(rate * window);
    const auto time_per_update = 1.0 / static_cast<double>(rate);
    for (auto counter = 0; counter < total; ++counter) {
        if (self.stop_early.load(std::memory_order_relaxed)) break;
        // Post 1 update
        self.postValue(payload, counter);

        // Sleep until the next emission time
        epicsTimeStamp now{};
        epicsTimeGetCurrent(&now);
        const double elapsed_since_start = epicsTimeDiffInSeconds(&now, &start);
        const double next_emission_secs_from_start = static_cast<double>(counter + 1)  * time_per_update ;
        auto time_till_next_emission = next_emission_secs_from_start - elapsed_since_start;
        if (self.stop_early.load(std::memory_order_relaxed)) break;
        // while (time_till_next_emission > 1e-3) {
        //     epicsThreadSleep(1e-3); time_till_next_emission -= 1e-3;
        // }
        if (time_till_next_emission > 0.0) epicsThreadSleep(time_till_next_emission);
    }
}

void UpdateConsumer::run() {
    const auto window_count = static_cast<int32_t>(rate * window);
    const auto total_receive_ticks = static_cast<int32_t>(receive_window * rate);
    const auto time_per_update = 1.0 / static_cast<double>(rate);
    int32_t running_count{-1}; // Keeps track of actual counted packets consumed
    auto tick = 0;
    while (tick < total_receive_ticks && running_count < window_count) {
        if (self.stop_early.load(std::memory_order_relaxed)) break;
        // Get any available updates
        running_count = self.processPendingUpdates(result, start);
        if (self.stop_early.load(std::memory_order_relaxed)) break;
        tick = std::max(++tick, running_count);

        epicsTimeStamp now{};
        epicsTimeGetCurrent(&now);
        const double elapsed_since_start = epicsTimeDiffInSeconds(&now, &start);

        // Update the progress bar once per percentage change
        const auto progress_percentage = elapsed_since_start >= window ? 100.00 : static_cast<uint32_t>(100 * (elapsed_since_start / window));
        if (progress_percentage != prior_percentage) {
            prior_percentage = progress_percentage;
            printProgressBar(progress_percentage);
        }

        // Poll network capture
        sniffer->poll();

        // Sleep until the tick
        const auto next_tick_secs_from_start = time_per_update * tick ;
        const auto time_till_next_tick = next_tick_secs_from_start - elapsed_since_start;
        if (time_till_next_tick > 0.0) epicsThreadSleep(time_till_next_tick);
    }
    // Flag everyone else to stop early too
    self.stop_early.store(true, std::memory_order_relaxed);
}

/**
 * Print a progress bar to the console
 * @param progress_percentage The percentage done
 */
void UpdateConsumer::printProgressBar(double progress_percentage) {
    // 1) Connection Type
    const std::string bps_placeholder = SB() << (static_cast<uint32_t>(progress_percentage) % 2 ? "\\" : "/") << " bps";
    std::ostringstream oss;
    oss << std::right << std::setw(15)
        << ( self.scenario_type == TLS_CMS_STAPLED ? "TLS_CMS_STAPLED"
           : self.scenario_type == TLS_CMS         ? "TLS_CMS"
           : self.scenario_type == TLS             ? "TLS"
                                                   : "TCP")
        << ", "

    // 2) PVAccess Payload
    << std::right << std::setw(13) << payload_label << ", "

    // 3) Tx Rate
    << std::right << std::setw(13) << rate_label << ", "

    // 4) Throughput
    << std::right << std::setw(13) << bps_placeholder << ", "

    // 5) N
    << std::right << std::setw(8) << result.n << ": ";
    auto prefix = oss.str();

    if (progress_percentage > 100.0)
        progress_percentage = 100.0;
    std::string bar;
    bar.reserve(170);
    bar += prefix;
    bar += "▏";  // left cap
    const double bar_len = 167.0 - static_cast<double>(prefix.size()) - 2.0;
    uint32_t i;
    for (i = 0; i < 0.01 * progress_percentage * bar_len; ++i)
        bar += "█";
    for (; i < bar_len; ++i)
        bar += "░";
    bar += "▕";  // right cap
    std::cout << bar << "\r" << std::flush;
}

// Helpers for CLI parsing and labels

/**
 * Convert a string to uppercase
 * @param s The string to convert
 * @return The uppercase string
 */
inline std::string toUpperStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

/**
 * Parse a scenario type from a string
 * @param name The string to parse
 * @param out The output scenario type
 * @return True if the string was parsed successfully, false otherwise
 */
bool parseScenarioType(const std::string& name, ScenarioType& out) {
    const auto uppercase_name = toUpperStr(name);
    if (uppercase_name == "TCP") {
        out = TCP;
        return true;
    }
    if (uppercase_name == "TLS") {
        out = TLS;
        return true;
    }
    if (uppercase_name == "TLS_CMS" || uppercase_name == "TLS-CMS" || uppercase_name == "TLSCMS") {
        out = TLS_CMS;
        return true;
    }
    if (uppercase_name == "TLS_CMS_STAPLED" || uppercase_name == "TLS-CMS-STAPLED" || uppercase_name == "TLSSTAPLED" || uppercase_name == "TLSCMSSTAPLED") {
        out = TLS_CMS_STAPLED;
        return true;
    }
    return false;
}

/**
 * Parse a payload type from a string
 * @param name The string to parse
 * @param out The output payload type
 * @return True if the string was parsed successfully, false otherwise
 */
bool parsePayloadType(const std::string& name, PayloadType& out) {
    auto n = toUpperStr(name);
    if (n == "SMALL") {
        out = SMALL_32B;
        return true;
    }
    if (n == "MEDIUM") {
        out = SMALL_32B;
        return true;
    }
    if (n == "LARGE") {
        out = LARGE_2MB;
        return true;
    }
    return false;
}

/**
 * Format a rate label
 * @param rate The rate to format
 * @return The formatted rate label
 */
std::string formatRateLabel(long rate) {
    if (rate >= 1000000 && rate % 1000000 == 0) {
        long v = rate / 1000000;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%3ldMHz", v);
        return std::string(buf);
    }
    if (rate >= 1000 && rate % 1000 == 0) {
        long v = rate / 1000;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%3ldKHz", v);
        return std::string(buf);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%3ld Hz", rate);
    return std::string(buf);
}

/**
 * Constructor for the Scenario
 * @param scenario_type The type of scenario to build.
 * - TCP: Plain TCP connection.
 * - TLS: TLS connection.
 * - TLS_CMS: TLS connection with CMS status checking.
 * - TLS_CMS_STAPLED: TLS connection with CMS status checking and stapling.
 */
Scenario::Scenario(const ScenarioType scenario_type) : scenario_type(scenario_type) {
    // Configure the server
    configureServer();

    // Initialise scenarios
    initSmallScenarios();
    initMediumScenarios();
    initLargeScenarios();

    // Start the server
    startServer();
    // Configure a client that is compatible with the server
    buildClientContext();
}

/**
 * Initialize the SMALL payload type test and add its PV to the server
 */
void Scenario::initSmallScenarios() {
    // Build PV
    small_pv = server::SharedPV::buildReadonly();
    server.addPV("PERF:SMALL", small_pv);

    // Build data
    // 4 byte data payload (plus NT scaffolding)
    auto s_def(nt::NTScalar{TypeCode::Int32}.build());
    s_def += {Int32("counter")};

    small_value = s_def.create();
    small_value["counter"] = -1; // Set an initial value.  This will be ignored
    small_pv.open(small_value);
}

/**
 * Initialize the MEDIUM payload type test and add its PV to the server
 */
void Scenario::initMediumScenarios() {
    medium_pv = server::SharedPV::buildReadonly();
    server.addPV("PERF:MEDIUM", medium_pv);

    // Build data
    // 1k payloads (plus NT scaffolding)
    auto def(nt::NTNDArray{}.build());
    def += {Int32("counter")};
    def += {
        StructA("dimensions",
                {
                    Int32("value"),
                }),
    };

    medium_value = def.create();
    {
        constexpr int d0 = 32, d1 = 32;
        shared_array<uint8_t> buf(d0 * d1);
        for (size_t i = 0u; i < buf.size(); ++i)
            buf[i] = static_cast<uint8_t>(i);
        shared_array<const uint8_t> medium_data(buf.freeze());
        shared_array<Value> small_dimensions;
        small_dimensions.resize(2);
        small_dimensions[0] = medium_value["dimension"].allocMember().update("size", d0);
        small_dimensions[1] = small_dimensions[0].cloneEmpty().update("size", d1);

        medium_value["value->ubyteValue"] = medium_data;
        medium_value["dimension"] = small_dimensions.freeze();
    }
    medium_value["counter"] = -1; // Set an initial value.  This will be ignored
    medium_pv.open(medium_value);
}

/**
 * Initialize the LARGE payload type test and add its PV to the server
 */
void Scenario::initLargeScenarios() {
    // Build PV
    auto def(nt::NTNDArray{}.build());
    def += {Int32("counter")};
    def += {
        StructA("dimensions",
                {
                    Int32("value"),
                }),
    };

    large_pv = server::SharedPV::buildReadonly();
    server.addPV("PERF:LARGE", large_pv);

    // 2MB = 4 Mega-Pixels: 2000 x 2000 mono (4 Mpx), 4 bits/pixel => 2,000,000 bytes
    // Create the value
    large_value = def.create();
    constexpr int height = 2000;
    constexpr int width = 2000;
    constexpr size_t n_pixels = static_cast<size_t>(height) * static_cast<size_t>(width);
    constexpr size_t n_bytes = (n_pixels + 1u) / 2u;  // two pixels per byte

    // allocate packed buffer (each byte holds two 4-bit pixels)
    shared_array<uint8_t> buf(n_bytes);

    // ---- dimensions (pixel sizes) ----
    shared_array<Value> dims;
    dims.resize(2);
    dims[0] = large_value["dimension"]
                  .allocMember()
                  .update("size", height)
                  .update("offset", 0)
                  .update("fullSize", height)
                  .update("binning", 1)
                  .update("reverse", false);
    dims[1] = dims[0].cloneEmpty().update("size", width).update("fullSize", width);
    large_value["dimension"] = dims.freeze();

    // ---- data ----
    large_value["value->ubyteValue"] = shared_array<const uint8_t>(buf.freeze());

    // ---- sizes / codec ----
    large_value["uncompressedSize"] = static_cast<int64_t>(n_bytes);
    large_value["compressedSize"] = static_cast<int64_t>(n_bytes);  // raw
    large_value["codec.name"] = "raw";

    // ---- attributes: at least ColorMode and BitsPerPixel ----
    auto mkAttr = [&](const char* name, const uint32_t n) {
        auto attribute = large_value["attribute"].allocMember();
        attribute["name"] = name;
        attribute["value"] = n;
        attribute["descriptor"] = "auto";
        attribute["sourceType"] = 0;
        attribute["source"] = "";
        return attribute;
    };

    pvxs::shared_array<Value> attrs;
    attrs.resize(2);
    attrs[0] = mkAttr("ColorMode", 0);  // 0 = Mono (convention)
    attrs[1] = mkAttr("BitsPerPixel", 4);
    large_value["attribute"] = attrs.freeze();
    large_value["counter"] = -1; // Set an initial value.  This will be ignored
    large_pv.open(large_value);
}

/**
 * Configure the server for the performance test scenario
 * The server is configured to use the isolated configuration and the TLS keychain file is set to the server1.p12
 * file that has been generated for the other tls tests.
 */
void Scenario::configureServer() {
    // Build Server
    auto serv_conf = server::Config::isolated();
    serv_conf.tls_keychain_file = "server1.p12";
    serv_conf.udp_port = 55076;

    // Use ephemeral port to avoid conflicts with pvacms child process
    serv_conf.tls_disabled = scenario_type == TCP;
    serv_conf.tls_disable_status_check = scenario_type < TLS_CMS;
    serv_conf.tls_disable_stapling = scenario_type < TLS_CMS_STAPLED;
    server = serv_conf.build();
}

/**
 * Start the server and query the effective bound ports.  These will be used to build a compatible client.
 */
void Scenario::startServer() {
    server.start();
    // After the server starts, query effective bound ports
    {
        const auto& config = server.config();
        udp_port = config.udp_port;
        tcp_port = config.tcp_port;
    }
}

/**
 * Build the client and configure it to use the server's effective ports.
 * The client is configured to use the isolated configuration, and the TLS keychain file is set to the client1.p12
 * file that has been generated for the other tls tests.
 */
void Scenario::buildClientContext() {
    {
        auto cli_conf = server.clientConfig();
        cli_conf.tls_keychain_file = "client1.p12";
        client = cli_conf.build();
    }
}

/**
 * Run the performance test Scenario for the given payload type.  This method runs tests for all the different rates
 * for the given payload type. The rates are 1 Hz, 10 Hz, 100 Hz, 1 KHz, 10 KHz, and 1 MHz. For the Large payload
 * type, the rates are 1 Hz, 10 Hz, 100 Hz, and 1 KHz. Each rate test runs for 60 seconds.
 * @param scenario_type
 * @param payload_type The type of payload to test.
 */
void Scenario::run(const ScenarioType &scenario_type, PayloadType payload_type) {
    const auto payload_label =
        (payload_type == LARGE_2MB  ? "LARGE(2MB)"
       : payload_type == MEDIUM_1KB ? "MEDIUM(1KB)"
       :                              "SMALL(32B)");
    Scenario {scenario_type}.run(payload_type,           1, payload_label, "   1Hz");
    Scenario {scenario_type}.run(payload_type,          10, payload_label, "  10Hz");
    Scenario {scenario_type}.run(payload_type,         100, payload_label, " 100Hz");
    Scenario {scenario_type}.run(payload_type,        1000, payload_label, "  1KHz");
    if (payload_type != LARGE_2MB) {
        Scenario {scenario_type}.run(payload_type,   10000, payload_label, " 10KHz");
        Scenario {scenario_type}.run(payload_type,  100000, payload_label, "100KHz");
        Scenario {scenario_type}.run(payload_type, 1000000, payload_label, "  1MHz");
    }
}

/**
 * Run the performance test Scenario for the given payload type and rate.
 * This method runs a single test for the given payload type and rate.  Each test runs for 60 seconds.
 * The method does both sides of the communication - the server and the client. A single `event` is used for both.
 * - A timer is set on the `event`, based on the specified rate, and when it expires a value is Posted to the
 * server's SharedPV. A special test is made to ensure that we don't Post anything after the test window has expired
 * when we're waiting for tardy packets.
 * - At the same time whenever the client monitor receives an update it signals the same `event` thus interrupting
 * the timer. In this case the queue of received updates is processed, and a new timer is set with the remaining
 * time to the next Post.
 * - The loop continues until the test window expires.
 *
 * @param payload_type The type of payload to test - SMALL, MEDIUM, or LARGE.
 * @param rate The rate to test - 1 Hz, 10 Hz, 100 Hz, 1 KHz, 10 KHz, or 1 MHz.
 * @param payload_label The label for the payload type - SMALL, MEDIUM, or LARGE.
 * @param rate_label The label for the rate - 1 Hz, 10 Hz, 100 Hz, 1 KHz, 10 KHz, or 1 MHz.
 */
void Scenario::run(const PayloadType payload_type,
         const uint32_t rate,
         const std::string& payload_label,
         const std::string& rate_label) {
    if (payload_type == LARGE_2MB && rate > 100) return;

    // To collect the results of the test
    Result result{
        wireSizeBytes(small_value),
        wireSizeBytes(medium_value),
        wireSizeBytes(large_value)};

    // Collect Data
    const double w0 = wallSeconds();
    const double c0 = procCPUSeconds();
    std::uint64_t bytes_captured = 0;
    {
        // Three-threaded execution
        // - Producer: posts updates on a fixed cadence (Main thread)
        // - Monitor: responds to subscription updates and posts to consumer's queue
        // - Consumer: drains monitor updates, computes transit times, polls sniffer, and prints progress on a fixed cadence

        // This is used to collect the network traffic appearing on the test ports.
        const auto sniffer = std::make_shared<PortSniffer>(tcp_port, udp_port);
        sniffer->startCapture();

        // Start a monitor subscription for the given payload type and set an appropriate queue size to avoid coalescing.
        SubscriptionMonitor subscription_monitor{*this, payload_type, rate};
        epicsThread subscription_thread(subscription_monitor, "PERF-Monitor", epicsThreadGetStackSize(epicsThreadStackMedium), epicsThreadPriorityHigh);
        subscription_thread.start();

        // quiesce before test
        epicsThreadSleep(1.0);

        // Mark the start time for this sequence, and quiesce before the test
        epicsTimeStamp start{};
        epicsTimeGetCurrent(&start);

        // Reset the early-stop flag for this run
        stop_early.store(false, std::memory_order_relaxed);

        // Create and start threads
        UpdateProducer update_producer{*this, payload_type, rate, start};
        UpdateConsumer update_consumer{*this, result, rate,  start, sniffer, payload_label, rate_label};

        epicsThread consumer_thread(update_consumer, "PERF-Consumer", epicsThreadGetStackSize(epicsThreadStackBig), epicsThreadPriorityMedium);

        consumer_thread.start();   // Run in the background
        update_producer.run();     // Block this thread

        // Wait for consumer to complete
        subscription_thread.exitWait();
        consumer_thread.exitWait();

        // Final drain/capture
        sniffer->poll();
        bytes_captured = sniffer->endCapture();
    }

    const double rss_mb = static_cast<double>(getRssBytes()) / (1024 * 1024);
    const auto cpu_percent = cpuPercentSince(w0, c0);

    result.print(scenario_type, payload_type, payload_label, rate, rate_label, cpu_percent, rss_mb, bytes_captured);
    std::cout << std::endl;
}

/**
 * Start a monitor subscription for the given payload type.
 * The PV to monitor is based on the payload type.
 * @param payload_type The type of payload to monitor.
 * @param rate the rate at which we expect to get
 */
void Scenario::startMonitor(const PayloadType payload_type, const uint32_t rate) {
    const char* pv_name = (payload_type == LARGE_2MB)    ? "PERF:LARGE"
                          : (payload_type == MEDIUM_1KB) ? "PERF:MEDIUM"
                                                         : "PERF:SMALL";

    // Heuristic to limit coalescing: ensure a large enough client-side queue.
    // Larger queues reduce bias where only the newest updates are delivered at high rates.
    auto queue_size = 0u;
    switch (payload_type) {
        case SMALL_32B:
            // Allow up to ~100k small updates buffered, but not less than 2*rate
            queue_size = std::max<unsigned>(std::min<unsigned>(rate * 2u, 100000u), 1000u);
            break;
        case MEDIUM_1KB:
            // Medium payloads: cap at 20k to bound memory; but allow at least 2*rate
            queue_size = std::max<unsigned>(std::min<unsigned>(rate * 2u, 20000u), 100u);
            break;
        case LARGE_2MB:
            // Large payloads are expensive; queue just a small number
            queue_size = std::max<unsigned>(std::min<unsigned>(rate * 2u, 10u), 2u);
            break;
    }

    // Set up a subscription monitor
    sub = client.monitor(pv_name).record("queueSize", queue_size).record("pipeline", true).
        record("ackAny", std::string("50%")).maskConnected(true) // suppress Connected events from throwing
        .maskDisconnected(true).event([this](client::Subscription &) {
            // Drain all currently queued updates from the subscription and enqueue locally.
            // Important: only signaling when the client queue transitions from empty->non-empty.
            // If we leave entries in the subscription queue, further events may not be delivered.
            try {
                while (const auto value = sub->pop()) {
                    epicsTimeStamp receive_time{};
                    epicsTimeGetCurrent(&receive_time);
                    update_queue.push(Update{value, receive_time});
                }
            } catch (const std::exception &e) {
                // log and stop draining to avoid tight loop on errors
                log_warn_printf(consumerlog, "Monitor pop() error: %s\n", e.what());
            }
        }).exec();
}

/**
 * Post a value to the appropriate PV based on the payload type.
 * This function creates a new value, updates the counter-field, and timestamps the value.
 * It then marks all fields as updated so that the server will send the full data to the client.
 * It then posts the value to the appropriate PV.
 *
 * @param payload_type The type of payload to post.
 * @param counter the counter to embed in the value posted
 */
void Scenario::postValue(const PayloadType payload_type, const int32_t counter) {
    try {
        auto value = (payload_type == SMALL_32B) ? small_value : (payload_type == MEDIUM_1KB) ? medium_value : large_value;
        value["counter"] = counter;
        auto timestamp = value["timeStamp"];
        epicsTimeStamp sent_time{};
        epicsTimeGetCurrent(&sent_time);
        timestamp["secondsPastEpoch"] = sent_time.secPastEpoch;
        timestamp["nanoseconds"] = sent_time.nsec;
        value.mark(true);
        (payload_type == SMALL_32B ? small_pv : payload_type == MEDIUM_1KB ? medium_pv : large_pv).post(value);
    } catch (std::exception& e) {
        log_warn_printf(producerlog, "post_once error: %s\n", e.what());
    }
}

/**
 * Process the pending updates from the update_queue.
 * This method is called when the event is signaled by the monitor subscription or when this is the first time.
 * It processes the queue of received updates, updating the result object with the delta between the send-time and
 * the received-time (transit time)
 *
 * @param result The result object to update with the received updates.
 * @param start The start time of the test.
 * @return the next expected counter
 */
int32_t Scenario::processPendingUpdates(Result &result, const epicsTimeStamp &start) {
    epicsTimeStamp now{};
    epicsTimeGetCurrent(&now);
    int32_t count{result.n};

    while (update_queue.size()) {
        try {
            epicsTimeGetCurrent(&now);
            const auto update = update_queue.pop();

            // Get the timestamp that shows when the data was sent
            const auto timestamp = update.value["timeStamp"];
            const auto received_count = update.value["counter"].as<int32_t>();
            epicsTimeStamp sent{timestamp["secondsPastEpoch"].as<epicsUInt32>(),
                                timestamp["nanoseconds"].as<epicsUInt32>()};
            if (received_count < 0)
                continue;

            if (received_count != count) {
                // Stop this test early on the first detected-drop
                stop_early.store(true, std::memory_order_relaxed);
                break;
            }

            // Determine how much time has elapsed from the beginning of the test sequence
            const double elapsed = epicsTimeDiffInSeconds(&sent, &start);
            // Determine how much time the data was in transit
            const double transit_time = epicsTimeDiffInSeconds(&update.receive_time, &sent);

            // We should never get anything sent after the end of the window, but out of an abundance of caution we break if so
            constexpr double window = 60.0;
            if (elapsed >= window)
                break;

            // Calculate the 0-based bucket index based on the seconds since the beginning of the test
            const auto bucket_index = static_cast<uint32_t>(elapsed);

            // Another check to make sure that we are not beyond the end of the results buffer and then add the results
            if (bucket_index < 60)
                count = result.add(transit_time);
        } catch (const client::Connected&) {
            // ignore
        } catch (const client::Disconnect&) {
            // ignore
        }
        epicsThreadSleep(-1);
    }
    return count;
}

/**
 * Extract target architecture from the given test executable path name
 *
 * @param path
 * @return
 */
std::string extractTargetArch(const std::string& path) {
    if (path.empty())
        return std::string();
    const auto terminated_by_path_separator = (path.back() == '/');
    const auto base_path = path.substr(0, std::string::npos - (terminated_by_path_separator ? 1 : 0));
    const std::string target_arch = basename(const_cast<char*>(base_path.c_str()));
    const auto ta = target_arch.substr(2, std::string::npos);
    log_debug_printf(perflog, "Target architecture: %s\n", ta.c_str());
    return ta;
}

/**
 * Start the PVACMS process
 * @param pvacms_executable_path The path to the PVACMS executable
 * @param pvacms_subprocess The child process struct
 * @return True if the process was started successfully, false otherwise
 */
bool startPVACMS(const std::string& pvacms_executable_path, Child& pvacms_subprocess) {
    const pid_t pid = fork();
    if (pid < 0) {
        // Failure to create the subprocess
        return false;
    }

    if (pid == 0) {
        // Child process
        // Detach from any controlling terminal group so signals don't propagate unexpectedly
        setsid();

        // Apply environment setup
        std::string key{};
        for (const auto& env_part : pvacms_subprocess.env) {
            if (key.empty()) {
                key = env_part;
            } else {
                if (env_part.empty()) {
                    if (unsetenv(key.c_str()) != 0) {
                        log_err_printf(perflog, "Failed to unset environment variable: %s \n", key.c_str());
                    }
                } else {
                    if (setenv(key.c_str(), env_part.c_str(), 1) != 0) {
                        log_err_printf(perflog,
                                       "Failed to set environment variable: %s = \"%s\"\n",
                                       key.c_str(),
                                       env_part.c_str());
                    }
                }
                key = {};
            }
        }

        const char* argv0 = pvacms_executable_path.c_str();
        log_info_printf(perflog, "Starting child process: %s %s\n", pvacms_executable_path.c_str(), "pvacms");
        execlp(argv0, "pvacms", "--preload-cert", "server1.p12", "client1.p12", nullptr);

        // If exec fails
        log_err_printf(perflog, "Failed to start child process: %s %s\n", pvacms_executable_path.c_str(), "pvacms");
        _exit(127);
    }

    // Parent process
    pvacms_subprocess.pid = pid;
    return true;
}

/**
 * Stop the PVACMS process
 * @param child The child process struct
 */
void stopPVACMS(Child& child) {
    if (child.pid > 0) {
        // Try SIGTERM first
        kill(child.pid, SIGTERM);
        // Wait briefly
        for (int i = 0; i < 30; ++i) {
            int status = 0;
            pid_t r = waitpid(child.pid, &status, WNOHANG);
            if (r == child.pid) {
                child.pid = -1;
                return;
            }
            usleep(100000);  // 100ms
        }
        // Force kill if still running
        kill(child.pid, SIGKILL);
        waitpid(child.pid, nullptr, 0);
        child.pid = -1;
    }
}

// Global child process struct to store the process ID and environment variables.
Child pvacms_subprocess;

/**
 * Simple Ctrl-C (SIGINT) trap: print the exit message, stop PVACMS, then exit
 * @param sig The signal number
 */
void onSigint(int) {
    std::cerr << std::endl << "Exiting..." << std::endl;
    stopPVACMS(pvacms_subprocess);
    _exit(130);
}

}  // namespace perf
}  // namespace pvxs

int main(int argc, char* argv[]) {
    using namespace pvxs::perf;
#if defined(EPICS_VERSION_INT) && EPICS_VERSION_INT >= VERSION_INT(7, 0, 3, 1)
    (void)argc;
    (void)argv;
    pvxs::logger_level_set(perflog.name, pvxs::Level::Info);
    pvxs::logger_config_env();
    // Install simple Ctrl-C trap
    signal(SIGINT, onSigint);

    // CLI argument parsing
    std::vector<std::string> opt_scenarios;
    std::vector<std::string> opt_payloads;
    std::vector<long> opt_rates;

    CLI::App app{"PVXS TLS performance tests"};
    app.add_option("-s,--scenario-type",
                   opt_scenarios,
                   "Scenario type(s): TCP, TLS, TLS_CMS, TLS_CMS_STAPLED. May be repeated.");
    app.add_option("-p,--payload-type", opt_payloads, "Payload type(s): SMALL, MEDIUM, LARGE. May be repeated.");
    app.add_option("-r,--rate", opt_rates, "Update rate(s) in Hz. May be repeated.");
    CLI11_PARSE(app, argc, argv);

    // Build selected lists (defaults to all if no selection)
    std::vector<ScenarioType> scenarios_sel;
    if (opt_scenarios.empty()) {
        scenarios_sel = {TCP, TLS, TLS_CMS, TLS_CMS_STAPLED};
    } else {
        for (const auto& s : opt_scenarios) {
            ScenarioType st{};
            if (!parseScenarioType(s, st)) {
                std::cerr << "Unknown scenario type: " << s << std::endl;
                return 2;
            }
            scenarios_sel.push_back(st);
        }
    }

    // Build selected lists (defaults to all if no selection)
    std::vector<PayloadType> payloads_sel;
    if (opt_payloads.empty()) {
        payloads_sel = {SMALL_32B, MEDIUM_1KB, LARGE_2MB};
    } else {
        for (const auto& p : opt_payloads) {
            PayloadType pt{};
            if (!parsePayloadType(p, pt)) {
                std::cerr << "Unknown payload type: " << p << std::endl;
                return 2;
            }
            payloads_sel.push_back(pt);
        }
    }

    std::cout << "Starting Performance Tests" << std::endl;

    // Determine test install dir
    std::string test_dir;
    char* executable_path = epicsGetExecDir();
    if (executable_path) {
        try {
            test_dir = executable_path;
            free(executable_path);
        } catch (...) {
            free(executable_path);
            throw;
        }
    }

    // Change working dir to test dir
    if ( chdir(test_dir.c_str()) ) {
        std::cerr << "Failed to change to test directory: " << test_dir << std::endl;
        return 2;
    }

    // Extract the target architecture from the test directory name
    const std::string target_arch = extractTargetArch(test_dir);

    // Determine the pvacms executable location
    const std::string pvacms_executable_path = test_dir
        + ".."
        + OSI_PATH_SEPARATOR + ".."
        + OSI_PATH_SEPARATOR + "bin"
        + OSI_PATH_SEPARATOR + target_arch
        + OSI_PATH_SEPARATOR + "pvacms";
    std::cout << "pvacms executable: " << pvacms_executable_path << std::endl;

    // Create a child process to run PVACMS
    pvacms_subprocess = Child{
        "SSLKEYLOGFILE",                  {},
        "XDG_DATA_HOME",                    test_dir+"perf/data",
        "XDG_CONFIG_HOME",                  test_dir+"perf/config",
        "EPICS_PVA_BROADCAST_PORT",         "55076",
        "EPICS_PVACMS_SERVER_PORT",         "55075",
        "EPICS_PVACMS_TLS_PORT",            "55076",
        "EPICS_PVA_SERVER_PORT",            "55077",
        "EPICS_PVA_TLS_PORT",               "55078",
        "EPICS_CERT_AUTH_TLS_KEYCHAIN",     "cert_auth.p12",
        "EPICS_PVAS_TLS_KEYCHAIN",          "superserver1.p12",
    };
    if (!startPVACMS(pvacms_executable_path, pvacms_subprocess)) {
        std::cerr << "Failed to start pvacms: " << pvacms_executable_path << std::endl;
        return 1;
    }

    // Wait for pvacms to start up
    std::cout << "Waiting for pvacms to start before running tests" << std::endl;
    sleep(2);
    std::cout << "PVACMS Ready" << std::endl;

    // Run selected scenarios
    auto first = true;
    for (auto scenario_type : scenarios_sel) {
        if (first)
            std::cout
                  << std::right << std::setw(15) << "Connection Type" << ", "
                  << std::right << std::setw(13) << "Payload" << ", "
                  << std::right << std::setw(13) << "Tx Rate(Hz)" << ", "
                  << std::right << std::setw(13) << "Throughput" << ", "
                  << std::right << std::setw( 8) << "N" << ", "
                  << std::right << std::setw(10) << "Min(ms)" << ", "
                  << std::right << std::setw(10) << "Max(ms)" << ", "
                  << std::right << std::setw(10) << "Mean(ms)" << ", "
                  << std::right << std::setw(10) << "StdDev(ms)" << ", "
                  << std::right << std::setw(12) << "CPU(% core)" << ", "
                  << std::right << std::setw(12) << "Memory(MB)" << ", "
                  << std::right << std::setw(19) << "Network Load(bytes)"
                  << std::endl;
        first = false;

        for (auto payload_type : payloads_sel) {
            if (opt_rates.empty()) {
                Scenario::run(scenario_type, payload_type);
            } else {
                const std::string payload_label =
                    (payload_type == LARGE_2MB
                         ? "LARGE(2MB)"
                         : (payload_type == MEDIUM_1KB ? "MEDIUM(1KB)" : "SMALL(32B)"));
                for (auto rate : opt_rates) {
                    const std::string speed_label = formatRateLabel(rate);
                    Scenario scenario(scenario_type);
                    scenario.run(payload_type, rate, payload_label, speed_label);
                }
            }
        }

        std::cout << std::endl;
    }

    stopPVACMS(pvacms_subprocess);

    std::cout << "Performance Tests Complete" << std::endl;
#endif
    return 0;
}
