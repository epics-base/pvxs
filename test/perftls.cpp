/*
 * Minimal performance test harness.
 * Usage Instructions:
 * 1. Generate the TLS keychains:
 *    - project_root/test/<arch>/gen_test_certs
 * 3. Run the test:
 *    - project_root/test/<arch>/perftls --consumer # run the consumer side of the test
 *    - project_root/test/<arch>/perftls --producer # run the producer side of the test
 *
 * You can choose to run the test with different scenario types, payload types, and rates by adding parameters to the consumer side of the test.
 * For example:
 *   - # run the consumer side of the test with TCP scenario, SMALL payload, and 100 Hz rate
 *     project_root/test/<arch>/perftls --consumer --scenario-type TCP --payload-type SMALL --rate 100
 *
 *   - # run the consumer side of the test with the TLS_CMS and TLS_CMS_STAPLED scenarios, SMALL, MEDIUM, and LARGE payloads, and 1000, 10000, and 100000 Hz rates
 *     project_root/test/<arch>/perftls --consumer --scenario-type TLS_CMS TLS_CMS_STAPLED --payload-type SMALL MEDIUM LARGE --rate 1000 10000 100000
 *
 *   - # run the consumer side of the test with all permutations of payload and rate for the TLS_CMS_STAPLED scenario
 *     project_root/test/<arch>/perftls --consumer --scenario-type TLS_CMS_STAPLED
 *
 * Behind the scenes:
 * - The producer will configure the PVACMS and start it
 * - The producer will subscribe to the PERF:CONTROL pv to await instructions for what tests to produce tests for
 * - The consumer will start the PERF:CONTROL pv and post a request for a PREPARE message for a specific type of test
 * - The producer will post an initial acknowledgement message (initial value) that has a counter value of -1 on the appropriate test PV
 * - The consumer will not do anything until the acknowledgement message is received and discarded
 * - Once the acknowledgement message has been received the consumer will post a START message for the specific type of the test on PERF:CONTROL
 * - Once the START message is received the producer will start posting periodic messages to the appropriate test PV at the specified rate for 60 seconds
 * - The consumer will consumer all of the messages posted by the producer and measure the elapsed transit time
 * - If at any time the producer receives a new PREPARE message it will interrupt the prior sending sequence
 * - If the consumer receives a counter out of sequence it will immediately stop its capture of the messages and send a STOP on the PERF:CONTROL channel
 * - If a STOP is received at any time the producer will immediately stop the sequence of sending messages and will post an acknowledgement of the STOP
 * - Once the acknowledgement of the STOP is received a consumer can proceed to the next scenario or exit if it is the last scenario scheduled
 */

#include "perftls.h"

#include <algorithm>
#include <csignal>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <iomanip>
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

// Enable expert API
#define PVXS_ENABLE_EXPERT_API
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

DEFINE_LOGGER(perflog, "pvxs.perf");
DEFINE_LOGGER(producerlog, "pvxs.perf.scenario.producer");
DEFINE_LOGGER(consumerlog, "pvxs.perf.scenario.consumer");

using namespace pvxs::members;

// Global child process struct to store the process ID and environment variables.
Child pvacms_subprocess;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Forward declarations

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
std::uint64_t getRssBytes();
double procCPUSeconds();
double wallSeconds();
double cpuPercentSince(double w0, double c0);
#endif
static double wireSizeBytes(const Value& value_to_size);

/**
 * Create a performance test control value which is an NTEnum of the scenario_code to run,
 * with two extra fields indicating the payload and the rate
 *
 * @param scenario_code the scenario to run
 * @param payload_code the payload size to push through
 * @param rate and the rate to run it at
 * @return A performance test control value ready to post
 */
Value createPerfControlValue(const unsigned scenario_code, const unsigned payload_code = 0, const long rate = 0) {
    auto m_def(nt::NTEnum{}.build());
    m_def += {Int32("payload_code")};
    m_def += {Int32("rate")};
    Value value = m_def.create();
    value["value.index"] = scenario_code;
    if ( payload_code != 0) value["payload_code"] = payload_code;
    if (rate != 0) value["rate"] = rate;
    return value;
}

/**
 * Create the SMALL size test payload.  This is an NTScalar<Int32> and a counter
 * @return a SMALL size test payload value
 */
Value createSmallValue() {
    auto s_def(nt::NTScalar{TypeCode::Int32}.build());
    s_def += {Int32("counter")};
    auto value = s_def.create();
    value["counter"] = -1; // Set an initial value.  This will be ignored
    return value;
}


/**
 * Create the MEDIUM size test payload.  This is an NTNDArray with 32x32 ubyte and counter
 * @return a MEDIUM size test payload value
 */
Value createMediumValue() {
    auto m_def(nt::NTNDArray{}.build());
    m_def += {Int32("counter")};
    m_def += {
        StructA("dimensions",
                {
                    Int32("value"),
                }),
    };
    Value value = m_def.create();
    constexpr int d0 = 32, d1 = 32;
    shared_array<uint8_t> buf(d0 * d1);
    for (size_t i = 0u; i < buf.size(); ++i)
        buf[i] = static_cast<uint8_t>(i);
    const shared_array<const uint8_t> medium_data(buf.freeze());
    shared_array<Value> small_dimensions;
    small_dimensions.resize(2);
    small_dimensions[0] = value["dimension"].allocMember().update("size", d0);
    small_dimensions[1] = small_dimensions[0].cloneEmpty().update("size", d1);

    value["value->ubyteValue"] = medium_data;
    value["dimension"] = small_dimensions.freeze();
    value["counter"] = -1; // Set an initial value.  This will be ignored
  return value;
}


/**
 * Create the MEDIUM size test payload.  This is an NTNDArray 2000x2000 4bpp (size approximated by structure)
 * @return a MEDIUM size test payload value
 */
Value createLargeValue() {
    auto l_def(nt::NTNDArray{}.build());
    l_def += {Int32("counter")};
    l_def += {
        StructA("dimensions",
                {
                    Int32("value"),
                }),
    };
    Value value = l_def.create();

    constexpr int height = 2000;
    constexpr int width = 2000;
    constexpr size_t n_pixels = static_cast<size_t>(height) * static_cast<size_t>(width);
    constexpr size_t n_bytes = (n_pixels + 1u) / 2u;  // two pixels per byte

    // allocate packed buffer (each byte holds two 4-bit pixels)
    shared_array<uint8_t> buf(n_bytes);

    // ---- dimensions (pixel sizes) ----
    shared_array<Value> dims;
    dims.resize(2);
    dims[0] = value["dimension"]
        .allocMember()
        .update("size", height)
        .update("offset", 0)
        .update("fullSize", height)
        .update("binning", 1)
        .update("reverse", false);
    dims[1] = dims[0].cloneEmpty().update("size", width).update("fullSize", width);
    value["dimension"] = dims.freeze();

    // ---- data ----
    value["value->ubyteValue"] = shared_array<const uint8_t>(buf.freeze());

    // ---- sizes / codec ----
    value["uncompressedSize"] = static_cast<int64_t>(n_bytes);
    value["compressedSize"] = static_cast<int64_t>(n_bytes);  // raw
    value["codec.name"] = "raw";

    // ---- attributes: at least ColorMode and BitsPerPixel ----
    auto mkAttr = [&](const char* name, const uint32_t n) {
        auto attribute = value["attribute"].allocMember();
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
    value["attribute"] = attrs.freeze();
    value["counter"] = -1; // Set an initial value.  This will be ignored
    return value;
}

std::string getPathToFileInTestDir(const std::string &file_name = {}) {
    std::string path_to_file{};
    char* executable_path = epicsGetExecDir();
    if (executable_path) {
        path_to_file = executable_path;
        free(executable_path);
    }
    return path_to_file + file_name;
}

/**
 * Add a value to the result
 * @param value The value to add
 */
int32_t Result::add(const double value) {
    if (value <= 0.0)
        return -1;
    accumulator.add(value);
    return accumulator.N;
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
    const uint32_t rate, const std::string &rate_label, const double cpu_percent, const double rss_mb, uint64_t bytes_captured)  {
    // Scale results
    accumulator.scale(1000); // to milliseconds

    // Wipe the progress bar
    std::cout << std::right << std::setw(155) <<" \r";

    // 1) Connection Type
    std::cout  << std::right << std::setw(15)
               << (scenario_type == TLS_CMS_STAPLED ? "TLS_CMS_STAPLED"
                  : scenario_type == TLS_CMS        ? "TLS_CMS"
                  : scenario_type == TLS            ? "TLS"
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
    std::cout << std::right << std::setw(8) << accumulator.N << ", "; // Total number of readings (sample size)
    if (accumulator.vmin < std::numeric_limits<double>::max())    std::cout << std::right << std::setw(10) << accumulator.vmin << ", "; else std::cout << " , ";
    if (accumulator.vmax > std::numeric_limits<double>::lowest()) std::cout << std::right << std::setw(10) << accumulator.vmax << ", "; else std::cout << " ,  ";
    // 6) Mean, StdDev
    std::cout << std::right << std::setw(10) << accumulator.mean << ", ";        // The Mean Transmission Time
    std::cout << std::right << std::setw(10) << accumulator.stddev() <<  ", ";   // Standard Deviation from the Mean

    // 7) SEM, Jitter
    std::cout << std::right << std::setw(11) << accumulator.sem() << ", ";       // Standard Error on the Mean (Precision)
    std::cout << std::right << std::setw(11) << accumulator.jitter() <<  ", ";   // Standard Deviation of successive deltas

    // 8) Drops?
    std::cout << std::right << std::setw(10) << (accumulator.N < rate * 60.0 ? "yes" : "no")  << ", ";

    // 9) CPU% of 1 Core
    std::cout << std::right << std::setw(12) << cpu_percent << ", " ;

    // 10) Memory used
    std::cout << std::right << std::setw(12) << rss_mb << ", " ;

    // 11) Network load
    std::cout << std::right << std::setw(19) << bytes_captured;
}

void SubscriptionMonitor::run() {
    // Start a monitor subscription for the given payload type and set an appropriate queue size to avoid coalescing.
    self.startMonitor(payload, rate);

    auto end = std::time(nullptr);
    end += 67; // add 10% extra time to read everything

    // Wait until everything has finished
    while (end > std::time(nullptr)) {
        if (self.interrupted.wait(1.0/rate)) break;
    }
}

void Producer::run() const {
    const auto total = static_cast<uint32_t>(rate * window);
    const auto time_per_update = 1.0 / static_cast<double>(rate);
    double prior_percentage = std::numeric_limits<double>::max();

    self.postValue(payload, -1); // Reset
    for (auto counter = 0; counter < total; ++counter) {
        // Post 1 update
        self.postValue(payload, counter);

        // Calculate elapsed time and time till the next tick
        epicsTimeStamp now{};
        epicsTimeGetCurrent(&now);
        const double elapsed_since_start = epicsTimeDiffInSeconds(&now, &start);
        const double next_emission_secs_from_start = static_cast<double>(counter + 1)  * time_per_update ;
        auto time_till_next_emission = next_emission_secs_from_start - elapsed_since_start;
        if (time_till_next_emission < 0.0) time_till_next_emission = 1.0 / 100000000.0; // Should not get there, but if so set a very small amount of time

        // Update the progress bar once per percentage change
        const auto progress_percentage = elapsed_since_start >= window ? 100.00 : static_cast<uint32_t>(100 * (elapsed_since_start / window));
        if (progress_percentage != prior_percentage) {
            prior_percentage = progress_percentage;
            printProgressBar(progress_percentage, counter + 1);
        }

        // Sleep until the next emission time
        if (self.interrupted.wait(time_till_next_emission) ) {
            std::cout << "\nInterrupted\n";
            break;
        }
    }
    self.ready.signal();
}

void Consumer::run() {
    const auto window_count = static_cast<int32_t>(rate * window);
    const auto total_receive_ticks = static_cast<int32_t>(receive_window * rate);
    const auto time_per_update = 1.0 / static_cast<double>(rate);
    int32_t running_count{-1}; // Keeps track of actual counted packets consumed
    auto tick = 0;
    double prior_percentage = std::numeric_limits<double>::max();
    self.ready.wait();  // wait for first update
    while (tick < total_receive_ticks && running_count < window_count) {
        // Get any available updates
        running_count = self.processPendingUpdates(result, start);
        tick = std::max(++tick, running_count);

        epicsTimeStamp now{};
        epicsTimeGetCurrent(&now);
        const double elapsed_since_start = epicsTimeDiffInSeconds(&now, &start);

        // Update the progress bar once per percentage change
        const auto progress_percentage = elapsed_since_start >= window ? 100.00 : static_cast<uint32_t>(100 * (elapsed_since_start / window));
        if (progress_percentage != prior_percentage) {
            prior_percentage = progress_percentage;
            printProgressBar(progress_percentage, running_count);
        }

        // Poll network capture
        sniffer->poll();

        // Sleep until the tick
        const auto next_tick_secs_from_start = time_per_update * tick ;
        const auto time_till_next_tick = next_tick_secs_from_start - elapsed_since_start;
        if (self.interrupted.wait(time_till_next_tick)) break;
    }
}

/**
 * Print a progress bar to the console
 * @param progress_percentage The percentage done
 * @param N the current count of packets received
 */
void Timed::printProgressBar(double progress_percentage, const int32_t N) const {
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
    << std::right << std::setw(8) << N << ": ";
    auto prefix = oss.str();

    if (progress_percentage > 100.0)
        progress_percentage = 100.0;
    std::string bar;
    bar.reserve(210);
    bar += prefix;
    bar += "▏";  // left cap
    const double bar_len = 205.0 - static_cast<double>(prefix.size()) - 2.0;
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
    const auto n = toUpperStr(name);
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
    char buf[32];
    if (rate >= 1000000) std::snprintf(buf, sizeof(buf), "%3ldMHz", rate / 1000000);
    else if (rate >= 1000) std::snprintf(buf, sizeof(buf), "%3ldKHz", rate / 1000);
    else std::snprintf(buf, sizeof(buf), "%3ld Hz", rate);
    return std::string(buf);
}

/**
 * Constructor for the Scenario for a producer
 * @param scenario_type The type of scenario to build.
 * - TCP: Plain TCP connection.
 * - TLS: TLS connection.
 * - TLS_CMS: TLS connection with CMS status checking.
 * - TLS_CMS_STAPLED: TLS connection with CMS status checking and stapling.
 */
Scenario::Scenario(const ScenarioType scenario_type) : scenario_type(scenario_type), is_consumer(false) {
    buildProducerContext();
    initSmallScenarios();
    initMediumScenarios();
    initLargeScenarios();
    producer.start();
}

/**
 * Constructor for the Scenario for a consumer
 * @param scenario_type The type of scenario to build.
 * - TCP: Plain TCP connection.
 * - TLS: TLS connection.
 * - TLS_CMS: TLS connection with CMS status checking.
 * - TLS_CMS_STAPLED: TLS connection with CMS status checking and stapling.
 * @param db_file_name optional db file name to output detailed data to
 * @param run_id the unique program run ID
 */
Scenario::Scenario(const ScenarioType scenario_type, const std::string &db_file_name, const std::string &run_id) : scenario_type(scenario_type), run_id(run_id), is_consumer(true) {
    small_value = createSmallValue();
    medium_value = createMediumValue();
    large_value = createLargeValue();

    // Initialize optional SQLite DB once per Scenario instance
    if (!db_file_name.empty()) {
        try {
            initDB(db_file_name);
        } catch (const std::exception& e) {
            log_err_printf(consumerlog, "Could not open sqlite db (%s): %s\n", db_file_name.c_str(), e.what());
        }
    }
    buildConsumerContext();
}

/**
 * Initialize the SMALL payload type test and add its PV to the server
 */
void Scenario::initSmallScenarios() {
    small_pv = server::SharedPV::buildReadonly();
    producer.addPV("PERF:SMALL", small_pv);
    small_value = createSmallValue();
    small_pv.open(small_value);
}

/**
 * Initialize the MEDIUM payload type test and add its PV to the server
 */
void Scenario::initMediumScenarios() {
    medium_pv = server::SharedPV::buildReadonly();
    producer.addPV("PERF:MEDIUM", medium_pv);
    medium_value = createMediumValue();
    medium_pv.open(medium_value);
}

/**
 * Initialize the LARGE payload type test and add its PV to the server
 */
void Scenario::initLargeScenarios() {
    large_pv = server::SharedPV::buildReadonly();
    producer.addPV("PERF:LARGE", large_pv);
    large_value = createLargeValue();
    large_pv.open(large_value);
}

WireSizes computeWireSizes() {
    using namespace pvxs;
    using namespace pvxs::nt;

    WireSizes ws{};
    const auto s_val{createSmallValue()};
    ws.small = wireSizeBytes(s_val);
    const auto m_val{createMediumValue()};
    ws.medium = wireSizeBytes(m_val);
    const auto l_val{createLargeValue()};
    ws.large = wireSizeBytes(l_val);
    return ws;
}

std::string decodeRunID(const std::string& run_id) {
    if (run_id.size()!=8) return std::string("?");

    char* end=nullptr;
    const unsigned long run_time = std::strtoul(run_id.c_str(), &end, 16);

    if (!end || *end!='\0') return std::string("?");
    const auto run_time_posix = static_cast<time_t>(run_time);
    char run_id_string[64];
    std::tm g{};
    gmtime_r(&run_time_posix, &g);
    std::strftime(run_id_string, sizeof(run_id_string), "%Y-%m-%d %H:%M:%S UTC", &g);
    return std::string(run_id_string);
}

int sqliteBusyTimeout(sqlite3* db) {
    return sqlite3_busy_timeout(db, 60000); // 60s
}

uint64_t countSamples(sqlite3* db, const std::string& run_id) {
    sqlite3_stmt* statement=nullptr;
    uint64_t samples=0;
    if (sqlite3_prepare_v2(db, PERF_COUNT_SAMPLES_SQL, -1, &statement, nullptr)==SQLITE_OK) {
        sqlite3_bind_text(statement, sqlite3_bind_parameter_index(statement, ":run_id"), run_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement)==SQLITE_ROW)
            samples = static_cast<uint64_t>(sqlite3_column_int64(statement, 0));
    }
    if (statement) sqlite3_finalize(statement);
    return samples;
}

bool latestRunID(sqlite3* db, std::string& run_id) {
    sqlite3_stmt* statement=nullptr;
    bool ok=false;
    if (sqlite3_prepare_v2(db, PERF_GET_LATEST_RUN_ID_SQL, -1, &statement, nullptr)==SQLITE_OK) {
        if (sqlite3_step(statement)==SQLITE_ROW) {
            const unsigned char* run_id_string = sqlite3_column_text(statement, 0);
            if (run_id_string) run_id = reinterpret_cast<const char*>(run_id_string); ok=true;
        }
    }
    if (statement) sqlite3_finalize(statement);
    return ok;
}

void listRuns(sqlite3* db) {
    sqlite3_stmt* statement=nullptr;
    if (sqlite3_prepare_v2(db, PERF_LIST_SAMPLES_SQL, -1, &statement, nullptr)!=SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl; return;
    }
    while (sqlite3_step(statement)==SQLITE_ROW) {
        const auto run_id = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
        const auto samples = static_cast<unsigned long long>(sqlite3_column_int64(statement, 1));
        std::cout << run_id << " - Generated at: " << decodeRunID(run_id) << " - " << samples << " samples" << std::endl;
    }
    sqlite3_finalize(statement);
}

std::vector<std::string> splitIDs(const std::string& s) {
    std::vector<std::string> run_ids; std::string cur;
    for (const char c : s) {
        if (c==',' || c==' ' || c=='\t') { if (!cur.empty()) { run_ids.push_back(cur); cur.clear(); } }
        else cur.push_back(c);
    }
    if (!cur.empty()) run_ids.push_back(cur);
    return run_ids;
}

void infoRuns(sqlite3* db, const std::vector<std::string>& run_ids) {
    for (const auto& run_id: run_ids) {
        const auto samples = countSamples(db, run_id);
        std::cout << run_id << " - Generated at: " << decodeRunID(run_id) << " -  " << samples << " samples" << std::endl;
    }
}

void deleteRuns(sqlite3* db, const std::vector<std::string>& run_ids) {
    sqlite3_stmt* statement=nullptr;
    if (sqlite3_prepare_v2(db, PERF_DELETE_SQL, -1, &statement, nullptr)!=SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl; return;
    }
    for (const auto& run_id : run_ids) {
        sqlite3_reset(statement); sqlite3_clear_bindings(statement);
        sqlite3_bind_text(statement, 1, run_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement)!=SQLITE_DONE) {
            std::cerr << "SQLite delete error for RUN_ID=" << run_id << ": " << sqlite3_errmsg(db) << std::endl;
        } else {
            std::cout << "Deleted RUN_ID: " << run_id << std::endl;
        }
    }
    sqlite3_finalize(statement);
}

std::string payloadLabel(const PayloadType payload_id) {
    switch (payload_id) {
        case SMALL_32B:  return "SMALL(32B)";
        case MEDIUM_1KB: return "MEDIUM(1KB)";
        case LARGE_2MB:  return "LARGE(2MB)";
        default: return "?";
    }
}

// scenario index to column name
std::string scenarioLabel(const ScenarioType scenario_id) {
    switch (scenario_id) {
        case TCP:               return "TCP";
        case TLS:               return "TLS";
        case TLS_CMS:           return "TLS_CMS";
        case TLS_CMS_STAPLED:   return "TLS_CMS_STAPLED";
        default: return {};
    }
}

/**
 * Configure the server for the performance test scenario
 * The TLS keychain file is set to the server1.p12 file that has been generated for the other tls tests.
 */
void Scenario::buildProducerContext() {
    // Build Server
    auto serv_conf = server::Config::fromEnv();
    serv_conf.tls_keychain_file = getPathToFileInTestDir("server1.p12");

    serv_conf.tls_disabled = scenario_type == TCP;
    serv_conf.tls_disable_status_check = scenario_type < TLS_CMS;
    serv_conf.tls_disable_stapling = scenario_type < TLS_CMS_STAPLED;
    producer = serv_conf.build();
}

/**
 * Build the client context for the performance test scenario
 * The TLS keychain file is set to the client1.p12 file that has been generated for the other tls tests.
 */
void Scenario::buildConsumerContext() {
    // Build Client
    auto cli_conf = client::Config::fromEnv();
    cli_conf.tls_keychain_file = getPathToFileInTestDir("client1.p12");

    cli_conf.tls_disabled = scenario_type == TCP;
    cli_conf.tls_disable_status_check = scenario_type < TLS_CMS;
    cli_conf.tls_disable_stapling = scenario_type < TLS_CMS_STAPLED;
    consumer = cli_conf.build();
}

/**
 * Run the performance test Scenario for the given payload type.  This method runs tests for all the different rates
 * for the given payload type. The rates are 1 Hz, 10 Hz, 100 Hz, 1 KHz, 10 KHz, and 1 MHz. For the Large payload
 * type, the rates are 1 Hz, 10 Hz, 100 Hz, and 1 KHz. Each rate test runs for 60 seconds.
 * @param scenario_type the type of scenario.  TCP, TLS, TLS with CMS, TLS with CMS, and stapling
 * @param payload_type The type of payload to test.
 * @param db_file_name the db filename to output detailed results to
 * @param run_id the optional run id to label this run
 */
void Scenario::run(server::SharedPV &control_pv, const ScenarioType &scenario_type, const PayloadType payload_type, const std::string &db_file_name, const std::string &run_id) {
    const auto payload_label =
        (payload_type == LARGE_2MB  ? "LARGE(2MB)"
       : payload_type == MEDIUM_1KB ? "MEDIUM(1KB)"
       :                              "SMALL(32B)");
    uint32_t rate = 1;
    rate =    1; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type,        rate, payload_label, formatRateLabel(rate));
    rate =   10; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type,        rate, payload_label, formatRateLabel(rate));
    rate =  100; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type,        rate, payload_label, formatRateLabel(rate));
    rate = 1000; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type,        rate, payload_label, formatRateLabel(rate));
    if (payload_type != LARGE_2MB) {
        rate =   10000; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type, rate, payload_label, formatRateLabel(rate));
        rate =  100000; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type, rate, payload_label, formatRateLabel(rate));
        rate = 1000000; Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type, rate, payload_label, formatRateLabel(rate));
    }
}

/**
 * Run the performance test Scenario for the given payload type and rate.
 * This method runs a single test for the given payload type and rate.  Each test runs for 60 seconds.
 * The method does both sides of the communication - the server and the client. A single `event` is used for both.
 * - A timer is set on the `event`, based on the specified rate, and when it expires, a value is Posted to the
 * server's SharedPV. A special test is made to ensure that we don't Post anything after the test window has expired
 * when we're waiting for tardy packets.
 * - At the same time, whenever the client monitor receives an update, it signals the same `event` thus interrupting
 * the timer. In this case the queue of received updates is processed, and a new timer is set with the remaining
 * time to the next Post.
 * - The loop continues until the test window expires.
 *
 * @param payload_type The type of payload to test - SMALL, MEDIUM, or LARGE.
 * @param rate The rate to test - 1 Hz, 10 Hz, 100 Hz, 1 KHz, 10 KHz, or 1 MHz.
 * @param payload_label The label for the payload type - SMALL, MEDIUM, or LARGE.
 * @param rate_label The label for the rate - 1 Hz, 10 Hz, 100 Hz, 1 KHz, 10 KHz, or 1 MHz.
 */
void Scenario::run(server::SharedPV &control_pv, const PayloadType payload_type,
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

    // This is used to collect the network traffic appearing on the test ports.
    const auto sniffer = std::make_shared<PortSniffer>(5075, 5076);
    sniffer->startCapture();

    // Start a monitor subscription for the given payload type and set an appropriate queue size to avoid coalescing.
    SubscriptionMonitor subscription_monitor{*this, payload_type, rate};
    epicsThread subscription_thread(subscription_monitor, "PERF-Monitor", epicsThreadGetStackSize(epicsThreadStackMedium), epicsThreadPriorityHigh);
    subscription_thread.start();

    // Mark the start time for this sequence, and quiesce before the test
    epicsTimeStamp start{};
    epicsTimeGetCurrent(&start);

    // Create and start threads
    current_rate = rate;
    current_payload = payload_type;
    Consumer update_consumer{*this, result, rate,  start, sniffer, payload_label, rate_label};

    // Signal the producer to send data
    auto control_value = control_pv.fetch();
    if (control_value["value.index"].as<int32_t>() != scenario_type) control_value["value.index"] = scenario_type;
    if (control_value["payload_code"].as<int32_t>() != payload_type) control_value["payload_code"] = payload_type;
    if (control_value["rate"].as<int32_t>() != rate) control_value["rate"] = rate;
    control_pv.post(control_value);

    update_consumer.run();   // Run the consumer

    // Wait for the update-subscription monitor to complete
    subscription_thread.exitWait();

    // Final drain/capture
    sniffer->poll();
    bytes_captured = sniffer->endCapture();

    const double rss_mb = static_cast<double>(getRssBytes()) / (1024 * 1024);
    const auto cpu_percent = cpuPercentSince(w0, c0);

    result.print(scenario_type, payload_type, payload_label, rate, rate_label, cpu_percent, rss_mb, bytes_captured);
    std::cout << std::endl;
}

void Scenario::closeDB() {
    if (stmt_insert) { sqlite3_finalize(stmt_insert); stmt_insert = nullptr; }
    if (stmt_update_tcp) { sqlite3_finalize(stmt_update_tcp); stmt_update_tcp = nullptr; }
    if (stmt_update_tls) { sqlite3_finalize(stmt_update_tls); stmt_update_tls = nullptr; }
    if (stmt_update_tls_cms) { sqlite3_finalize(stmt_update_tls_cms); stmt_update_tls_cms = nullptr; }
    if (stmt_update_tls_cms_stapled) { sqlite3_finalize(stmt_update_tls_cms_stapled); stmt_update_tls_cms_stapled = nullptr; }
    if (db) { sqlite3_close(db); db = nullptr; }
}

void Scenario::initDB(const std::string &db_path) {
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK)
        throw std::runtime_error(SB() << "Can't open results db: " << sqlite3_errmsg(db));
    const int rc = sqlite3_exec(db, PERF_CREATE_SQL, nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) throw std::runtime_error(SB() << "Can't create schema: " << sqlite3_errmsg(db));

    if (sqlite3_prepare_v2(db, PERF_INSERT_SQL, -1, &stmt_insert, nullptr) != SQLITE_OK)
        throw std::runtime_error(SB() << "prepare insert failed: " << sqlite3_errmsg(db));
    if (sqlite3_prepare_v2(db, PERF_UPDATE_TCP_SQL, -1, &stmt_update_tcp, nullptr) != SQLITE_OK)
        throw std::runtime_error(SB() << "prepare update TCP failed: " << sqlite3_errmsg(db));
    if (sqlite3_prepare_v2(db, PERF_UPDATE_TLS_SQL, -1, &stmt_update_tls, nullptr) != SQLITE_OK)
        throw std::runtime_error(SB() << "prepare update TLS failed: " << sqlite3_errmsg(db));
    if (sqlite3_prepare_v2(db, PERF_UPDATE_TLS_CMS_SQL, -1, &stmt_update_tls_cms, nullptr) != SQLITE_OK)
        throw std::runtime_error(SB() << "prepare update TLS_CMS failed: " << sqlite3_errmsg(db));
    if (sqlite3_prepare_v2(db, PERF_UPDATE_TLS_CMS_STAPLED_SQL, -1, &stmt_update_tls_cms_stapled, nullptr) != SQLITE_OK)
        throw std::runtime_error(SB() << "prepare update TLS_CMS_STAPLED failed: " << sqlite3_errmsg(db));
}

void Scenario::insertOrUpdateSample(const int payload_id, const uint32_t rate, const int32_t packet_id, const double transit_time) const {
    if (!db) return;

    // Bind INSERT
    sqlite3_reset(stmt_insert);
    sqlite3_clear_bindings(stmt_insert);
    sqlite3_bind_text(stmt_insert, sqlite3_bind_parameter_index(stmt_insert, ":run_id"), run_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt_insert, sqlite3_bind_parameter_index(stmt_insert, ":packet_id"), packet_id);
    sqlite3_bind_int (stmt_insert, sqlite3_bind_parameter_index(stmt_insert, ":payload_id"), payload_id);
    sqlite3_bind_int (stmt_insert, sqlite3_bind_parameter_index(stmt_insert, ":rate"), static_cast<int>(rate));

    // Columns 5..8 depend on scenario
    auto bind_col = [&](const int col, const bool selected) {
        if (selected) sqlite3_bind_double(stmt_insert, col, transit_time);
        else sqlite3_bind_null(stmt_insert, col);
    };
    bind_col(sqlite3_bind_parameter_index(stmt_insert, ":s_tcp"), scenario_type == TCP);
    bind_col(sqlite3_bind_parameter_index(stmt_insert, ":s_tls"), scenario_type == TLS);
    bind_col(sqlite3_bind_parameter_index(stmt_insert, ":s_tls_cms"), scenario_type == TLS_CMS);
    bind_col(sqlite3_bind_parameter_index(stmt_insert, ":s_tls_cms_stapled"), scenario_type == TLS_CMS_STAPLED);

    int rc = sqlite3_step(stmt_insert);
    if (rc == SQLITE_DONE) return;

    // If a row exists, update the appropriate column only
    sqlite3_stmt* stmt_update = nullptr;
    switch (scenario_type) {
        case TCP: stmt_update = stmt_update_tcp; break;
        case TLS: stmt_update = stmt_update_tls; break;
        case TLS_CMS: stmt_update = stmt_update_tls_cms; break;
        case TLS_CMS_STAPLED: stmt_update = stmt_update_tls_cms_stapled; break;
    }
    sqlite3_reset(stmt_update);
    sqlite3_clear_bindings(stmt_update);
    sqlite3_bind_double(stmt_update, sqlite3_bind_parameter_index(stmt_update, ":value"), transit_time);
    sqlite3_bind_text  (stmt_update, sqlite3_bind_parameter_index(stmt_update, ":run_id"), run_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int   (stmt_update, sqlite3_bind_parameter_index(stmt_update, ":payload_id"), payload_id);
    sqlite3_bind_int   (stmt_update, sqlite3_bind_parameter_index(stmt_update, ":rate"), static_cast<int>(rate));
    sqlite3_bind_int   (stmt_update, sqlite3_bind_parameter_index(stmt_update, ":packet_id"), packet_id);
    rc = sqlite3_step(stmt_update);
    if (rc != SQLITE_DONE) {
        log_warn_printf(consumerlog, "sqlite update failed: %s\n", sqlite3_errmsg(db));
    }
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
    sub = consumer.monitor(pv_name).record("queueSize", queue_size).record("pipeline", true).
        record("ackAny", std::string("50%")).maskConnected(true) // suppress Connected events from throwing
        .maskDisconnected(true).event([this](client::Subscription &) {
            // Drain all currently queued updates from the subscription and enqueue locally.
            // Important: only signaling when the client queue transitions from empty->non-empty.
            // If we leave entries in the subscription queue, further events may not be delivered.
            try {
                Guard G(lock);
                while (const auto value = sub->pop()) {
                    const auto N = value["counter"].as<int32_t>();
                    if (N >= 0) {
                        epicsTimeStamp receive_time{};
                        epicsTimeGetCurrent(&receive_time);
                        update_queue.push(Update{value, receive_time});
                        ready.signal();
                    }
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
    Guard G(lock);
    epicsTimeStamp now{};
    epicsTimeGetCurrent(&now);
    int32_t count{result.accumulator.N};

    auto items = update_queue.size();
    while (items--) {
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

            /*
            if (received_count != count) {
                // Stop this test early on the first detected-drop
                interrupted.signal();
                break;
            }
            */

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
            if (bucket_index < 60) {
                count = result.add(transit_time);
                if (db) insertOrUpdateSample(current_payload, current_rate, received_count, transit_time);
            }
        } catch (const client::Connected&) {
            // ignore
        } catch (const client::Disconnect&) {
            // ignore
        }
    }
    return count;
}

/**
 * Get target architecture
 *
 * @return
 */
std::string getTargetArch() {
    const std::string path = getPathToFileInTestDir();
    if (path.empty())
        return {};
    const auto terminated_by_path_separator = path.back() == '/';
    const auto base_path = path.substr(0, std::string::npos - (terminated_by_path_separator ? 1 : 0));
    const std::string target_arch = basename(const_cast<char*>(base_path.c_str()));
    return target_arch.substr(2, std::string::npos);
}

/**
 * Get get bin dir
 *
 * @return
 */
std::string getBinDir(const std::string &executable = {}) {
    const std::string test_path = getPathToFileInTestDir();
    const std::string target_arch = getTargetArch();
    if (test_path.empty() || target_arch.empty())
        return executable;
    return test_path
        + ".."
        + OSI_PATH_SEPARATOR + ".."
        + OSI_PATH_SEPARATOR + "bin"
        + OSI_PATH_SEPARATOR + target_arch
        + OSI_PATH_SEPARATOR + executable;
}

/**
 * Start the PVACMS process
 * @param pvacms_executable_path The path to the PVACMS executable
 * @param pvacms_subprocess_ref Reference to the child process object to construct
 * @return True if the process was started successfully, false otherwise
 */
bool startPVACMS(const std::string& pvacms_executable_path, Child& pvacms_subprocess_ref) {
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
        for (const auto& env_part : pvacms_subprocess_ref.env) {
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
        execlp(argv0, "pvacms", "--preload-cert", getPathToFileInTestDir("server1.p12").c_str(), getPathToFileInTestDir("client1.p12").c_str(), nullptr);

        // If exec fails
        log_err_printf(perflog, "Failed to start child process: %s %s\n", pvacms_executable_path.c_str(), "pvacms");
        _exit(127);
    }

    // Parent process
    pvacms_subprocess_ref.pid = pid;
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

/**
 * Simple Ctrl-C (SIGINT) trap: print the exit message, stop PVACMS, then exit
 */
void onExit(int) {
    std::cerr << std::endl << "Exiting..." << std::endl;
    stopPVACMS(pvacms_subprocess);
    _exit(130);
}

void outputColumnHeadings() {
    std::cout
        << std::right << std::setw(15) << "Connection Type" << ", "
        << std::right << std::setw(13) << "Payload" << ", "
        << std::right << std::setw(13) << "Tx Rate(Hz)" << ", "
        << std::right << std::setw(13) << "Throughput" << ", "
        << std::right << std::setw( 8) << "N" << ", "            // Total number of readings (sample size)
        << std::right << std::setw(10) << "Min(ms)" << ", "      // Min Transmission Time
        << std::right << std::setw(10) << "Max(ms)" << ", "      // Max Transmission Time
        << std::right << std::setw(10) << "Mean(ms)" << ", "     // The Mean Transmission Time
        << std::right << std::setw(10) << "StdDev(ms)" << ", "   // Standard Deviation from the Mean
        << std::right << std::setw(11) << "SEM(ms)" << ", "      // Standard Error on the Mean (Precision)
        << std::right << std::setw(11) << "Jitter(ms)" << ", "   // Standard Deviation of successive deltas
        << std::right << std::setw(10) << "Drops(y/n)" << ", "
        << std::right << std::setw(12) << "CPU(% core)" << ", "
        << std::right << std::setw(12) << "Memory(MB)" << ", "
        << std::right << std::setw(19) << "Network Load(bytes)"
        << std::endl;
}

bool configureAndStartPVACMS() {
    // Determine the pvacms executable location
    const std::string pvacms_executable_path = getBinDir("pvacms");

    // Create a child process to run PVACMS
    pvacms_subprocess = Child{
        "EPICS_PVACMS_SERVER_PORT",         "55075",
        "EPICS_PVACMS_TLS_PORT",            "55076",
        "EPICS_CERT_AUTH_TLS_KEYCHAIN",     getPathToFileInTestDir("cert_auth.p12"),
        "EPICS_PVAS_TLS_KEYCHAIN",          getPathToFileInTestDir("superserver1.p12"),
    };

    if (!startPVACMS(pvacms_executable_path, pvacms_subprocess)) {
        std::cerr << "Failed to start pvacms: " << pvacms_executable_path << std::endl;
        return false;
    }

    // Wait for pvacms to start up
    std::cout << "Waiting for pvacms to start before running tests" << std::endl;
    sleep(2);
    std::cout << "PVACMS Ready" << std::endl;
    return true;
}


void runProducer() {
    if (!configureAndStartPVACMS()) {
        std::cerr << "Producer failed to start" << std::endl;
        exit(51);
    }

    MPMCFIFO<std::shared_ptr<client::Subscription>> perf_control_update_queue(2);

    // Subscribe to PERF:CONTROL to get instructions on which test to run
    Scenario scenario{TCP}; // default TCP
    bool first_time = true;
    auto perf_control_client = client::Context::fromEnv();
    auto sub = perf_control_client
        .monitor("PERF:CONTROL")
        .maskConnected(true)
        .maskDisconnected(true)
        .event([&](const client::Subscription& perf_control_monitor) {
            std::cout << "Received PERF:CONTROL update" << std::endl;
            if (!first_time ) {
                std::cout << "Interrupting prior scenario" << std::endl;
                scenario.interrupted.signal();
                scenario.ready.wait(); // wait till prior is done before starting a new one
                std::cout << "Prior scenario has finished\n";
            } else first_time = false;
            perf_control_update_queue.push(perf_control_monitor.shared_from_this());
        })
        .exec();
    perf_control_client.hurryUp();

    std::cout << "Connection Type,       Payload,   Tx Rate(Hz),    Throughput,        N" << std::endl;
    // Loop indefinitely for performance test operations, stop by interrupt
    while(const auto perf_control_update = perf_control_update_queue.pop()) {
        while (auto perf_control_update_value = perf_control_update->pop()) {
            epicsTimeStamp start;
            epicsTimeGetCurrent(&start);

            const auto scenario_code = perf_control_update_value["value.index"].as<uint32_t>();
            if (scenario_code < 0) continue;
            const auto scenario_type = static_cast<ScenarioType>(scenario_code);
            const auto payload_type_value = perf_control_update_value["payload_code"];
            if (!payload_type_value) continue; // Skip initial values

            const auto payload_type = static_cast<PayloadType>(payload_type_value.as<uint32_t>());
            const auto rate = perf_control_update_value["rate"].as<int32_t>();

            scenario.scenario_type = scenario_type;
            auto producer = Producer(scenario, payload_type, rate, start);
            producer.payload_label = payloadLabel(payload_type);
            producer.rate_label = formatRateLabel(rate);
            producer.run();
            std::cout << std::endl;
        }
    }
}

void doReport(sqlite3* db, const std::string& run_id) {
    {
        const auto samples = countSamples(db, run_id);
        if ( !samples ) {
            std::cout << "No samples found for RUN_ID=" << run_id << std::endl;
            return;
        }

        std::cout << run_id << " -  Generated at: " << decodeRunID(run_id) << ":  " << samples << " samples" << std::endl;
        std::cout << std::setw(15) << "Connection Type" << ", "
                  << std::setw(13) << "Payload" << ", "
                  << std::setw(13) << "Tx Rate(Hz)" << ", "
                  << std::setw(13) << "Throughput" << ", "
                  << std::setw( 8) << "N" << ", "           // Total number of readings (sample size)
                  << std::setw(10) << "Min(ms)" << ", "     // Min Transmission Time
                  << std::setw(10) << "Max(ms)" << ", "     // Max Transmission Time
                  << std::setw(10) << "Mean(ms)" << ", "    // The Mean Transmission Time
                  << std::setw(10) << "StdDev(ms)" << ", "  // Standard Deviation from the Mean
                  << std::setw(11) << "SEM(ms)" << ", "     // Standard Error on the Mean (Precision)
                  << std::setw(11) << "Jitter(ms)" << ", "  // Standard Deviation of successive deltas
                  << "Drops" << std::endl;
    }

    // precompute payload wire sizes for throughput
    const auto wire_sizes = computeWireSizes();

    // For each scenario, return values if they are non-zero
    for (auto scenario_code = 0; scenario_code < 4; ++scenario_code) {
        const auto scenario_id = static_cast<ScenarioType>(scenario_code);
        const auto scenario_label = scenarioLabel(scenario_id);

        // Get the list of payload IDs and rates for this report
        sqlite3_stmt* payloads_statement=nullptr;
        if (sqlite3_prepare_v2(db, PERF_REPORT_PAYLOADS_SQL, -1, &payloads_statement, nullptr)!=SQLITE_OK) {
            std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
            return;
        }
        sqlite3_bind_text(payloads_statement, sqlite3_bind_parameter_index(payloads_statement, ":run_id"), run_id.c_str(), -1, SQLITE_TRANSIENT);

        while (sqlite3_step(payloads_statement)==SQLITE_ROW) {
            const auto payload_id = static_cast<PayloadType>(sqlite3_column_int(payloads_statement, 0));
            const int rate = sqlite3_column_int(payloads_statement, 1);

            // Count samples for this scenario, payload, and rate
            sqlite3_stmt* count_statement=nullptr;
            int64_t samples=0;
            if (sqlite3_prepare_v2(db, PERF_REPORT_SAMPLE_COUNT_SQL, -1, &count_statement, nullptr)==SQLITE_OK) {
                sqlite3_bind_text(count_statement, sqlite3_bind_parameter_index(count_statement, ":scenario_type"), scenario_label.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(count_statement, sqlite3_bind_parameter_index(count_statement, ":run_id"), run_id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int (count_statement, sqlite3_bind_parameter_index(count_statement, ":payload_id"), payload_id);
                sqlite3_bind_int (count_statement, sqlite3_bind_parameter_index(count_statement, ":rate"), rate);
                if (sqlite3_step (count_statement) == SQLITE_ROW)
                    samples = sqlite3_column_int64(count_statement, scenario_code);
            }
            if (count_statement) sqlite3_finalize(count_statement);
            if (samples==0) continue;

            // If rows exist, then stream the rows, ordered by PACKET_ID, to compute stats and detect drops
            sqlite3_stmt* samples_statement=nullptr;
            if (sqlite3_prepare_v2(db, PERF_REPORT_SAMPLE_DATA, -1, &samples_statement, nullptr)!=SQLITE_OK) {
                std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
                continue;
            }

            sqlite3_bind_text(samples_statement, sqlite3_bind_parameter_index(samples_statement, ":scenario_type"), scenario_label.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(samples_statement, sqlite3_bind_parameter_index(samples_statement, ":run_id"), run_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int (samples_statement, sqlite3_bind_parameter_index(samples_statement, ":payload_id"), payload_id);
            sqlite3_bind_int (samples_statement, sqlite3_bind_parameter_index(samples_statement, ":rate"), rate);

            Accumulator accumulator;
            const auto expected_samples = rate * 60;
            const bool drops=samples != expected_samples;
            while (sqlite3_step(samples_statement) == SQLITE_ROW) {
                const double value = sqlite3_column_double(samples_statement, scenario_code+1);
                if (value > 0.0) accumulator.add(value); // convert to ms
            }
            sqlite3_finalize(samples_statement);

            // Remove max if unique and vastly different (2 standard deviations)
            if (!drops) {
                if ( accumulator.max_count == 1 && accumulator.vmax > accumulator.mean + accumulator.stddev() * 2 ) {
                    const auto new_N = accumulator.N - 1;
                    const auto new_sum = accumulator.mean * static_cast<double>(accumulator.N) - accumulator.vmax;
                    const double new_mean = new_sum / new_N;

                    accumulator.M2 = accumulator.M2
                        - (accumulator.vmax - accumulator.mean) * (accumulator.vmax - new_mean);
                    accumulator.mean = new_mean;
                    accumulator.N = new_N;
                }
                // Remove min if unique and vastly different
                if ( accumulator.min_count == 1 && accumulator.vmin < accumulator.mean - accumulator.stddev() * 2 ) {
                    const auto new_N = accumulator.N - 1;
                    const auto new_sum = accumulator.mean * static_cast<double>(accumulator.N) - accumulator.vmin;
                    const double new_mean = new_sum / new_N;

                    accumulator.M2 = accumulator.M2
                        - (accumulator.vmin - accumulator.mean) * (accumulator.vmin - new_mean);
                    accumulator.mean = new_mean;
                    accumulator.N = new_N;
                }
            }

            // Scale results
            accumulator.scale(1000); // to milliseconds

            // 4) Throughput
            std::string throughput_units = " bps";
            auto throughput = (payload_id == LARGE_2MB ? wire_sizes.large : payload_id == MEDIUM_1KB ? wire_sizes.medium : wire_sizes.small) * 8.0 * static_cast<double>(rate);
            if      ( throughput >= 1000000000 ) { throughput /= 1000000000; throughput_units = "Gbps"; }
            else if ( throughput >= 1000000    ) { throughput /= 1000000;    throughput_units = "Mbps"; }
            else if ( throughput >= 1000       ) { throughput /= 1000;       throughput_units = "Kbps"; }

            std::cout << std::setw(15) << scenarioLabel(scenario_id) << ", "
                      << std::setw(13) << payloadLabel(payload_id) << ", "
                      << std::setw(13) << formatRateLabel(rate) << ", "
                      << std::right << std::setw(9)  << throughput << throughput_units << ", "
                      << std::defaultfloat << std::setw(8) << accumulator.N << ", " // Total number of readings (sample size)
                      << std::setprecision(6)
                      << std::setw(10) << accumulator.vmin << ", "                  // Min Transmission Time
                      << std::setw(10) << accumulator.vmax << ", "                  // Max Transmission Time
                      << std::setw(10) << accumulator.mean<< ", "                   // The Mean Transmission Time
                      << std::setw(10) << accumulator.stddev() << ", "              // Standard Deviation from the Mean
                      << std::setw(11) << accumulator.sem() << ", "                 // Standard Error on the Mean (Precision)
                      << std::setw(11) << accumulator.jitter() << ", "              // Standard Deviation of successive deltas
                      << (drops? "yes" : "no")
                      << std::endl;
        }
        sqlite3_finalize(payloads_statement);
    }
}

// Compute the PVA wire size (bytes) of a Value (type + data), for throughput calculations.
// Performance Test only: uses internal wire encoder.
static double wireSizeBytes(const Value& value_to_size) {
    using namespace pvxs::impl;
    std::vector<uint8_t> buf;
    buf.reserve(4096000);
    VectorOutBuf M(true, buf);
    to_wire_full(M, value_to_size);
    return static_cast<double>(M.consumed());
}

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

int parseCommandlineOptions(const int argc,
                            char **argv,
                            std::vector<std::string> opt_scenarios,
                            std::vector<std::string> opt_payloads,
                            std::vector<long> opt_rates,
                            std::string db_file_name,
                            bool opt_report_list,
                            std::string opt_report_id,
                            std::string opt_report_del_ids,
                            std::string opt_report_info_ids,
                            bool &opt_consumer) {
    bool opt_producer = false;
    CLI::App app{"PVXS TLS performance tests"};
    app.add_flag("--consumer", opt_consumer, "Run in consumer mode: publish PERF:CONTROL and subscribe to data PV");
    app.add_flag("--producer", opt_producer,
                 "Run in producer mode: subscribe to PERF:CONTROL and publish requested performance data");
    app.add_option("-s,--scenario-type", opt_scenarios,
                   "Scenario type(s): TCP, TLS, TLS_CMS, TLS_CMS_STAPLED. May be repeated.");
    app.add_option("-f,--db", db_file_name, "SQLite database file for per-packet results to write or to read reports");
    app.add_option("-p,--payload-type", opt_payloads, "Payload type(s): SMALL, MEDIUM, LARGE. May be repeated.");
    app.add_option("-r,--rate", opt_rates, "Update rate(s) in Hz. May be repeated.");
    app.add_option("--report", opt_report_id, "Generate a report for RUN_ID. Use 'last' for last report")->
        expected(1, 1);
    app.add_flag("--report-list", opt_report_list, "List all RUN_IDs and their generated time with sample counts");
    app.add_option("--report-del", opt_report_del_ids, "Delete entries for comma-separated RUN_ID list")->
        expected(1, 50);
    app.add_option("--report-info", opt_report_info_ids, "Show info for comma-separated RUN_ID list")->expected(1, 50);

    CLI11_PARSE(app, argc, argv);

    if (opt_consumer && opt_producer) {
        std::cerr << "--producer and --consumer cannot both be specified" << std::endl;
        return 10;
    }
    if (opt_consumer && opt_producer) {
        std::cerr << "at least --producer or --consumer must be specified" << std::endl;
        return 11;
    }
    opt_consumer = !opt_producer;
    return 0;
}

void processReportOptions(const std::string &db_file_name, const bool opt_report_list, std::string opt_report_id, const std::string &opt_report_del_ids, const std::string &opt_report_info_ids) {
    // If any report options are set, process them and exit
    if (opt_report_list || !opt_report_id.empty() || !opt_report_del_ids.empty() || !opt_report_info_ids.empty()) {
        if (db_file_name.empty()) {
            std::cerr << "--output <dbfile> is required for report operations" << std::endl;
            exit(21);
        }
        sqlite3* rdb=nullptr;
        if (sqlite3_open(db_file_name.c_str(), &rdb)!=SQLITE_OK) {
            std::cerr << "Failed to open DB: " << db_file_name << ": " << sqlite3_errmsg(rdb) << std::endl;
            if (rdb) sqlite3_close(rdb);
            exit(22);
        }
        sqliteBusyTimeout(rdb);
        if (opt_report_list) {
            listRuns(rdb);
        }
        if (!opt_report_info_ids.empty()) {
            infoRuns(rdb, splitIDs(opt_report_info_ids));
        }
        if (!opt_report_del_ids.empty()) {
            deleteRuns(rdb, splitIDs(opt_report_del_ids));
        }
        if (!opt_report_id.empty()) {
            if (opt_report_id == "last") {
                if (!latestRunID(rdb, opt_report_id)) {
                    std::cerr << "No runs found in DB" << std::endl;
                    sqlite3_close(rdb);
                    exit(23);
                }
            }
            doReport(rdb, opt_report_id);
        }
        sqlite3_close(rdb);
        exit(0);
    }
}
std::string generateRunID() {
    const auto now = static_cast<unsigned int>(std::time(nullptr));
    char run_id_buffer[9];
    std::snprintf(run_id_buffer, sizeof(run_id_buffer), "%08x", now);
    return {run_id_buffer};
}

std::vector<ScenarioType> determineScenarios(const std::vector<std::string> &opt_scenarios) {
    std::vector<ScenarioType> scenarios_sel;
    if (opt_scenarios.empty()) {
        scenarios_sel = {TCP, TLS, TLS_CMS, TLS_CMS_STAPLED};
    } else {
        for (const auto& scenario_type_name : opt_scenarios) {
            ScenarioType scenario_type;
            if (!parseScenarioType(scenario_type_name, scenario_type)) {
                std::cerr << "Unknown scenario type: " << scenario_type_name << std::endl;
                exit(31);
            }
            scenarios_sel.push_back(scenario_type);
        }
    }
    return scenarios_sel;
}

std::vector<PayloadType> determinePayloads(const std::vector<std::string> &opt_payloads) {
    std::vector<PayloadType> payloads_sel;
    if (opt_payloads.empty()) {
        payloads_sel = {SMALL_32B, MEDIUM_1KB, LARGE_2MB};
    } else {
        for (const auto& payload_type_name : opt_payloads) {
            PayloadType payload_type;
            if (!parsePayloadType(payload_type_name, payload_type)) {
                std::cerr << "Unknown payload type: " << payload_type_name << std::endl;
                exit(41);
            }
            payloads_sel.push_back(payload_type);
        }
    }
    return payloads_sel;
}

void runConsumers(const std::vector<ScenarioType> &scenarios, const std::vector<PayloadType> &payloads, const std::vector<long> &rates, const std::string &run_id, const std::string &db_file_name) {
    // Host PERF:CONTROL

    auto config = server::Config::fromEnv();
    // config.tcp_port +=51000;
    config.tls_disabled = true;
    server::Server control_server = config.build();
    server::SharedPV control_pv = server::SharedPV::buildReadonly();
    control_server.addPV("PERF:CONTROL", control_pv);

    const Value control_value = createPerfControlValue(-1);
    control_pv.open(control_value);
    control_server.start();

    auto first = true;
    for (auto scenario_type : scenarios) {
        if (first) {
            if (!run_id.empty())
                std::cout
                    << "Recording Samples to Database: " << db_file_name << std::endl
                    << "Run ID                       : " << run_id << std::endl;
            outputColumnHeadings();
            first = false;
        }

        for (const auto payload_type : payloads) {
            if (rates.empty()) {
                Scenario::run(control_pv, scenario_type, payload_type, db_file_name, run_id);
            } else {
                const std::string payload_label =
                (payload_type == LARGE_2MB
                     ? "LARGE(2MB)"
                     : (payload_type == MEDIUM_1KB ? "MEDIUM(1KB)" : "SMALL(32B)"));
                for (const auto rate : rates) {
                    Scenario {scenario_type, db_file_name, run_id}.run(control_pv, payload_type, rate, payload_label, formatRateLabel(rate));
                }
            }
        }
    }
    control_pv.close();
    control_server.start();
    std::cout << "Performance Tests Complete" << std::endl;
}

}  // namespace perf
}  // namespace pvxs

int main(int argc, char* argv[]) {
#if defined(EPICS_VERSION_INT) && EPICS_VERSION_INT >= VERSION_INT(7, 0, 3, 1)
    using namespace pvxs::perf;
    pvxs::logger_level_set(perflog.name, pvxs::Level::Info);
    pvxs::logger_config_env();

    // Install simple Ctrl-C trap
    signal(SIGHUP, onExit);
    signal(SIGINT, onExit);
    signal(SIGQUIT, onExit);
    signal(SIGKILL, onExit);

    // CLI argument parsing
    std::vector<std::string> opt_scenarios, opt_payloads;
    std::vector<long> opt_rates;
    std::string db_file_name;
    bool opt_report_list = false;
    std::string opt_report_id, opt_report_del_ids, opt_report_info_ids;
    bool opt_consumer = false;

    // Parse commandline options and exit
    int parse_result = parseCommandlineOptions(argc, argv, opt_scenarios, opt_payloads, opt_rates, db_file_name, opt_report_list,
                                         opt_report_id, opt_report_del_ids, opt_report_info_ids, opt_consumer);
    if (parse_result) return parse_result;

    // If the options are for reporting only, then run the report and exit
    processReportOptions(db_file_name, opt_report_list, opt_report_id, opt_report_del_ids, opt_report_info_ids);

    // calculate the run_id if the db filename is specified
    std::string run_id;
    if (!db_file_name.empty()) run_id = generateRunID();

    // Build selected lists (defaults to all if no selection)
    auto scenarios_sel = determineScenarios(opt_scenarios);

    // Build selected lists (defaults to all if no selection)
    auto payloads_sel = determinePayloads(opt_payloads);

    std::cout << "Starting Performance Tests" << std::endl;

    if (opt_consumer) runConsumers(scenarios_sel, payloads_sel, opt_rates, run_id, db_file_name); else runProducer();

#endif
    exit(0);
}
