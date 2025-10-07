/**
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_PERFTLS_H
#define PVXS_PERFTLS_H

#include <algorithm>
#include <csignal>
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
#include <sys/time.h>
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

// CLI11 for command-line parsing
#include <CLI/CLI.hpp>

#include <sqlite3.h>

#if defined(__APPLE__)
#include <pcap.h>
#endif

// 68e54a41|59145|0|10000|3.2e-05|||
// 68e54a41|59146|0|10000|2.7e-05|||
// 68e54a41|59147|0|10000|3.5e-05|||
// 68e54a41|59148|0|10000|3.1e-05|||
#define PERF_CREATE_SQL \
    "CREATE TABLE IF NOT EXISTS results ("\
    "  RUN_ID TEXT NOT NULL," \
    "  PACKET_ID INTEGER NOT NULL," \
    "  PAYLOAD_ID INTEGER NOT NULL," \
    "  RATE INTEGER NOT NULL," \
    "  TCP REAL," \
    "  TLS REAL," \
    "  TLS_CMS REAL," \
    "  TLS_CMS_STAPLED REAL," \
    "  PRIMARY KEY ( "\
    "    RUN_ID, "\
    "    PAYLOAD_ID, "\
    "    RATE, "\
    "    PACKET_ID"\
    "  )" \
    ");"

#define PERF_INSERT_SQL \
    "INSERT INTO results ("\
    "  RUN_ID, "\
    "  PACKET_ID, "\
    "  PAYLOAD_ID, "\
    "  RATE, "\
    "  TCP, "\
    "  TLS, "\
    "  TLS_CMS, "\
    "  TLS_CMS_STAPLED"\
    ")" \
    "VALUES (" \
    "  :run_id," \
    "  :packet_id," \
    "  :payload_id," \
    "  :rate," \
    "  :s_tcp," \
    "  :s_tls," \
    "  :s_tls_cms," \
    "  :s_tls_cms_stapled " \
    ");"

#define PERF_UPDATE_TCP_SQL \
    "UPDATE results "\
    "SET "\
    "  TCP=:value "\
    "WHERE RUN_ID=:run_id "\
    "  AND PAYLOAD_ID=:payload_id "\
    "  AND RATE=:rate "\
    "  AND PACKET_ID=:packet_id;"

#define PERF_UPDATE_TLS_SQL \
    "UPDATE results "\
    "SET "\
    "  TLS=:value "\
    "WHERE RUN_ID=:run_id "\
    "  AND PAYLOAD_ID=:payload_id "\
    "  AND RATE=:rate "\
    "  AND PACKET_ID=:packet_id;"

#define PERF_UPDATE_TLS_CMS_SQL \
    "UPDATE results "\
    "SET "\
    "  TLS_CMS=:value "\
    "WHERE RUN_ID=:run_id "\
    "  AND PAYLOAD_ID=:payload_id "\
    "  AND RATE=:rate "\
    "  AND PACKET_ID=:packet_id;"

#define PERF_UPDATE_TLS_CMS_STAPLED_SQL \
    "UPDATE results "\
    "SET "\
    "  TLS_CMS_STAPLED=:value "\
    "WHERE RUN_ID=:run_id "\
    "  AND PAYLOAD_ID=:payload_id "\
    "  AND RATE=:rate "\
    "  AND PACKET_ID=:packet_id;"

#define PERF_DELETE_SQL \
    "DELETE FROM results "\
    "WHERE RUN_ID=?;"

#define PERF_COUNT_SAMPLES_SQL \
    "SELECT COUNT(*) " \
    "FROM results " \
    "WHERE " \
    "  RUN_ID=:run_id;"

#define PERF_LIST_SAMPLES_SQL \
    "SELECT " \
    "  RUN_ID, " \
    "  COUNT(*) AS N " \
    "FROM results " \
    "GROUP BY RUN_ID " \
    "ORDER BY RUN_ID DESC;"

#define PERF_GET_LATEST_RUN_ID_SQL \
    "SELECT " \
    "  RUN_ID " \
    "FROM results " \
    "GROUP BY RUN_ID " \
    "ORDER BY RUN_ID DESC LIMIT 1;"

#define PERF_REPORT_PAYLOADS_SQL \
    "SELECT " \
    "  PAYLOAD_ID, " \
    "  RATE " \
    "FROM results " \
    "WHERE RUN_ID=:run_id " \
    "GROUP BY " \
    "  PAYLOAD_ID, " \
    "  RATE " \
    "ORDER BY " \
    "  PAYLOAD_ID, " \
    "  RATE;"

#define PERF_REPORT_SAMPLE_COUNT_SQL \
    "SELECT " \
    "  COUNT(TCP), " \
    "  COUNT(TLS), " \
    "  COUNT(TLS_CMS), " \
    "  COUNT(TLS_CMS_STAPLED) " \
    "FROM results " \
    "WHERE RUN_ID=:run_id " \
    "  AND PAYLOAD_ID=:payload_id " \
    "  AND RATE=:rate " \
    "  AND :scenario_type IS NOT NULL;"

#define PERF_REPORT_SAMPLE_DATA \
    "SELECT " \
    "  PACKET_ID, " \
    "  TCP, TLS, TLS_CMS, TLS_CMS_STAPLED " \
    "FROM results " \
    "WHERE RUN_ID=:run_id " \
    "  AND PAYLOAD_ID=:payload_id " \
    "  AND RATE=:rate " \
    "  AND :scenario_type IS NOT NULL " \
    "ORDER BY PAYLOAD_ID, RATE, PACKET_ID ;"

namespace pvxs {
namespace perf {

/**
 * Child process struct to store the process ID and environment variables.
 */
struct Child {
    pid_t pid;
    std::vector<std::string> env{};

    Child() : pid(-1) {}

    explicit Child(const std::initializer_list<std::string>& key_value_pairs) : pid(-1), env(key_value_pairs) {}
};


struct PortSniffer;

/**
 * Scenario type: This is used to specify whether the test will use TCP or TLS connections,
 * and whether the status-checking and/or stapling will be enabled or disabled.
 */
enum ScenarioType { TCP, TLS, TLS_CMS, TLS_CMS_STAPLED };

/**
 * Payload type: This is used to specify the size of the PVAccess Payload that will be sent over the network.
 * Small is a single 32 but integer wrapped in an NT scalar.
 * Medium is a 32x32 ubyte array (1024 bytes) wrapped in an NT NDArray.
 * Large is a 4mpx image = 2000x2000 pixels, 4 bits per pixel (2,000,000 bytes) wrapped in an NT NDArray.
 */
enum PayloadType {
    SMALL_32B,
    MEDIUM_1KB,
    LARGE_2MB,
};

struct WireSizes { double small; double medium; double large; };

struct Accumulator {
    int32_t N=0;     // Size of sample
    double mean=0.0; // Mean of sample
    double M2=0.0;
    double vmin=std::numeric_limits<double>::max();
    double vmax=std::numeric_limits<double>::lowest();
    uint32_t max_count{0}, min_count{0};

    /**
     * Welford's online algorithm for computing mean, variance, and standard deviation in a single pass
     *
     * @see https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
     *
     * @param value value to add
     */
    void add(const double value) {
        if (value == vmin) ++min_count;
        else if (value < vmin) { vmin = value; min_count = 1; }
        if (value == vmax) ++max_count;
        else if (value > vmax) { vmax = value; max_count = 1; }
        ++N;

        const double delta = value - mean;
        mean += delta/static_cast<double>(N);
        const double delta2 = value - mean;
        M2 += delta*delta2;
    }

    /**
     * Calculate the variance
     * @return the variance
     */
    double variance() const {
        return N > 1 ? M2 / (static_cast<double>(N) - 1) : 0.0;
    }

    /**
     * Calculate the standard deviation
     * @return the standard deviation
     */
    double stddev() const {
        return std::sqrt(variance());
    }
};

/**
 * Result: This is used to store the results of the performance tests.
 * It stores the average transmission times (values) taken from the time the updates are
 * sent to the time they are read by the client.  The values are grouped by the corresponding update send-time.
 * The values are grouped by second that they are sent.
 * Alongside the values we store the number of updates (expected_count) and the number of updates that
 * were dropped (dropped) grouped by second that they are sent.
 * We also store the minimum and maximum transmission times (min and max).
 * We print the results in a table format with the following columns:
 * - The average transmission time for the updates per second of the test.
 * - The number of updates that were dropped per second of the test.
 * - The minimum transmission time for the updates per second of the test.
 * - The maximum transmission time for the updates per second of the test.
 */
struct Result {
    Accumulator accumulator;
    double small_size;
    double medium_size;
    double large_size;

    Result(const double small_size_, const double medium_size_, const double large_size_) : small_size(small_size_), medium_size(medium_size_), large_size(large_size_) {}

    int32_t add(double value) ;
    void print(ScenarioType scenario_type, PayloadType payload_type, const std::string &payload_label, uint32_t rate, const std::string &rate_label, double cpu_percent, double rss_mb, uint64_t bytes_captured) const ;

    double variance() const {
        return accumulator.variance();
    }

    double stddev() const {
        return accumulator.stddev();
    }
};

struct Update {
    Value value;
    const epicsTimeStamp receive_time;
    Update(const Value& value, const epicsTimeStamp &receive_time) : value {value}, receive_time{receive_time} {}
};

/**
 * Scenario: This is the configuration for a performance test scenario.
 * A scenario is one of TCP, TLS, TLS_CMS, or TLS_CMS_STAPLED.
 * - TCP uses a plain TCP connection.
 * - TLS uses a TLS connection.
 * - TLS_CMS uses a TLS connection with CMS status checking.
 * - TLS_CMS_STAPLED uses a TLS connection with CMS status checking and stapling.
 * When a scenario is created, it builds the server and client.
 * It builds three sizes of payload to be used if the associated payload type is selected in the run methods.
 * The payload types are SMALL, MEDIUM, or LARGE.
 * - SMALL is a single 32 but integer wrapped in an NT scalar.
 * - MEDIUM is a 32x32 ubyte array (1024 bytes) wrapped in an NT NDArray.
 * - LARGE is a 2000x2000 ubyte array (4,000,000 bytes): 4 bits/pixel equivalent to a 4 mega-pixel image.
 * It also builds the shared PVs for each of the payload types: PERF:SMALL, PERF:MEDIUM, or PERF:LARGE.
 */
struct Scenario {
    const ScenarioType scenario_type;
    // Optional SQLite database for detailed per-packet output
    sqlite3* db{nullptr};
    sqlite3_stmt* stmt_insert{nullptr};
    sqlite3_stmt* stmt_update_tcp{nullptr};
    sqlite3_stmt* stmt_update_tls{nullptr};
    sqlite3_stmt* stmt_update_tls_cms{nullptr};
    sqlite3_stmt* stmt_update_tls_cms_stapled{nullptr};
    std::string run_id; // 8-hex id for this program run
    MPMCFIFO<Update> update_queue;
    std::atomic<bool> stop_early{false};

    // Server and client to use for each side of the performance test scenario
    server::Server server;
    client::Context client;

    // Shared PV and small payload the SMALL payload type test
    server::SharedPV small_pv;
    Value small_value;

    // Shared PV and medium payload for the MEDIUM payload type test
    server::SharedPV medium_pv;
    Value medium_value;

    // Shared PV and large payload for the LARGE payload type test
    server::SharedPV large_pv;
    Value large_value;

    // Subscription the client will make for this performance test scenario
    std::shared_ptr<client::Subscription> sub;

    // Ports for the server and client
    int tcp_port{0};
    int udp_port{0};

    /**
     * Constructor for the Scenario
     * @param scenario_type The type of scenario to build.
     * - TCP: Plain TCP connection.
     * - TLS: TLS connection.
     * - TLS_CMS: TLS connection with CMS status checking.
     * - TLS_CMS_STAPLED: TLS connection with CMS status checking and stapling.
     * @param db_file_name the db file name.  If ommited then no detailed output
     * @param run_id the run id to use for this scenario
     */
    explicit Scenario(ScenarioType scenario_type, const std::string &db_file_name = {}, const std::string &run_id = {});

    ~Scenario() { server.stop(); closeDB(); }

    void initSmallScenarios();
    void initMediumScenarios();
    void initLargeScenarios();
    void configureServer();
    void startServer() ;
    void buildClientContext();
    static void run(const ScenarioType &scenario_type, PayloadType payload_type, const std::string &db_file_name = {}, const std::string &run_id = {});
    void run(PayloadType payload_type, uint32_t rate, const std::string& payload_label, const std::string& rate_label);
    void startMonitor(PayloadType payload_type, uint32_t rate);
    void postValue(PayloadType payload_type, int32_t counter = -1);
    int32_t processPendingUpdates(Result &result, const epicsTimeStamp &start);

    // SQLite helpers
    void initDB(const std::string &db_path);
    void closeDB();
    void insertOrUpdateSample(int payload_id, uint32_t rate, int32_t packet_id, double transit_time) const;

    // Context for DB writes during a run
    uint32_t current_rate{0};
    PayloadType current_payload{SMALL_32B};
};

struct SubscriptionMonitor final : epicsThreadRunable {
    Scenario &self;
    const PayloadType payload;
    const uint32_t rate;
    SubscriptionMonitor(Scenario &scenario, const PayloadType payload, uint32_t rate)
        : self{scenario}, payload{payload}, rate{rate} {}
    void run();
};

struct UpdateProducer final {
    Scenario &self;
    PayloadType payload;
    const uint32_t rate;
    const double window = 60.0;
    const epicsTimeStamp start;

    UpdateProducer(Scenario &scenario, const PayloadType payload_type, const uint32_t rate, const epicsTimeStamp& start)
        : self{scenario}, payload{payload_type}, rate{rate}, start{start} {}

   void run();
};

struct UpdateConsumer final : epicsThreadRunable {
    Scenario &self;
    Result &result;
    const uint32_t rate;
    epicsTimeStamp start;
    std::shared_ptr<PortSniffer> sniffer;
    const std::string payload_label;
    const std::string rate_label;
    uint32_t prior_percentage = std::numeric_limits<uint32_t>::max();
    const double window = 60.0;
    const double receive_window = window * 1.0 / 0.9;

    UpdateConsumer(Scenario &scenario, Result & result, const uint32_t rate, const epicsTimeStamp &start, const std::shared_ptr<PortSniffer> &sniffer, const std::string &payload_label, const std::string &rate_label)
        : self{scenario}, result{result}, rate{rate}, start{start}, sniffer{sniffer}, payload_label{payload_label}, rate_label{rate_label} {}

    void run() override;
    void printProgressBar(double progress_percentage) ;

};

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
// Packet capture helper to measure bytes for specific ports during an interval
struct PortSniffer {
    std::vector<pcap_t*> handles{};
    std::string bpf{};
    std::uint64_t total{0};
    int tcp_port{0};
    int udp_port{0};

    explicit PortSniffer(int tcp_port_, int udp_port_) : tcp_port(tcp_port_), udp_port(udp_port_) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "(tcp or udp) and (port %d or port %d)", tcp_port, udp_port);
        bpf.assign(buf);
    }

    static void onPacket(u_char* user, const struct pcap_pkthdr* h, const u_char* /*bytes*/) {
        auto* total = reinterpret_cast<std::uint64_t*>(user);
        *total += static_cast<std::uint64_t>(h->len);
    }

    bool openAll(std::string& err) {
        char error_buf[PCAP_ERRBUF_SIZE] = {0};
        pcap_if_t* all_devices = nullptr;
        if (pcap_findalldevs(&all_devices, error_buf) != 0) {
            err = error_buf;
            return false;
        }
        for (pcap_if_t* d = all_devices; d; d = d->next) {
            // Build handles via pcap_create to enable immediate mode
            pcap_t* h = pcap_create(d->name, error_buf);
            if (!h)
                continue;
            pcap_set_snaplen(h, 65535);
            pcap_set_promisc(h, 1);
            pcap_set_timeout(h, 50);
#if defined(PCAP_ERROR_BREAK)
            (void)0;  // placeholder to keep preprocessor happy in some environments
#endif
#ifdef PCAP_TSTAMP_PRECISION_NANO
            // Prefer microsecond default; leave as-is
#endif
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
            pcap_set_immediate_mode(h, 1);
#endif
            if (pcap_activate(h) != 0) {
                pcap_close(h);
                continue;
            }
            // Non-blocking to allow polling without stalls
            pcap_setnonblock(h, 1, error_buf);

            bpf_program prog{};
            if (pcap_compile(h, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
                pcap_close(h);
                continue;
            }
            if (pcap_setfilter(h, &prog) != 0) {
                pcap_freecode(&prog);
                pcap_close(h);
                continue;
            }
            pcap_freecode(&prog);
            handles.push_back(h);
        }
        pcap_freealldevs(all_devices);
        if (handles.empty()) {
            err = "pcap: no capture handles opened";
            return false;
        }
        return true;
    }

    void closeAll() {
        for (auto* h : handles)
            pcap_close(h);
        handles.clear();
    }

    void startCapture() {
        total = 0;
        std::string err;
        if (handles.empty() && !openAll(err)) {
            std::cerr << "PortSniffer init failed: " << err << std::endl;
            return;
        }
        // no initial dispatch; polling will drain continuously during the test window
    }

    // Poll all handles and drain all currently buffered packets
    void poll() {
        for (auto* h : handles) {
            // -1 => process all currently buffered packets
            pcap_dispatch(h, -1, &PortSniffer::onPacket, reinterpret_cast<u_char*>(&total));
        }
    }

    std::uint64_t endCapture() {
        // final drain
        for (auto* h : handles) {
            pcap_dispatch(h, -1, &PortSniffer::onPacket, reinterpret_cast<u_char*>(&total));
        }
        return total;
    }

    ~PortSniffer() {
        closeAll();
    }
};

#endif

}
}

#endif //PVXS_PERFTLS_H
