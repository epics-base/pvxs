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
#include <ifaddrs.h>

#include <mach/mach.h>
#include <net/if.h>
#include <sys/time.h>
#endif

#include <libgen.h>
#include <unistd.h>

#include <sys/types.h>

#include <epicsTime.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <memory>

// Enable expert API (Timer, evbase)
#define PVXS_ENABLE_EXPERT_API

#include <pvxs/source.h>

#include "evhelper.h"
#include "openssl.h"

// CLI11 for command-line parsing
#include <CLI/CLI.hpp>

#include <sqlite3.h>

#if defined(__APPLE__)
#include <pcap.h>
#endif

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

#define PERF_OP_PREPARE 0
#define PERF_OP_START  1
#define PERF_OP_STOP   2

// Distinct negative codes for control and error paths
#define PERF_NULL_SCENARIO      (-100)
#define PERF_OUT_OF_SEQUENCE    (-1001)

#define PERF_ACK                (-2001)
#define PERF_STOP_ACK           (-2002)
#define PERF_BAD_OP             (-2999)

namespace pvxs {
namespace perf {

DEFINE_LOGGER(perflog, "pvxs.perf");
DEFINE_LOGGER(producerlog, "pvxs.perf.producer");
DEFINE_LOGGER(producerdatalog, "pvxs.perf.producer.data");
DEFINE_LOGGER(consumerlog, "pvxs.perf.consumer");
DEFINE_LOGGER(consumerdatalog, "pvxs.perf.consumer.data");

enum PayloadType {
    SMALL_32B,
    MEDIUM_1KB,
    LARGE_2MB,
};

struct ProducerSource : server::Source {
    struct PVState {
        Value prototype;
        std::unique_ptr<server::MonitorControlOp> monitor_control_op;
        epicsEvent space;
        std::atomic<bool> started{false};
        std::atomic<int32_t> last_req{PERF_ACK};
        std::atomic<int32_t> last_sent{PERF_ACK};
        explicit PVState(const Value &prototype) : prototype(prototype) {}
    };

    ProducerSource();

    server::SharedPV small_pv{server::SharedPV::buildReadonly()};
    server::SharedPV medium_pv{server::SharedPV::buildReadonly()};
    server::SharedPV large_pv{server::SharedPV::buildReadonly()};
    const std::shared_ptr<PVState> small_pv_state;
    const std::shared_ptr<PVState> medium_pv_state;
    const std::shared_ptr<PVState> large_pv_state;

    const std::map<PayloadType,std::shared_ptr<PVState>> payload_type_state_map = {
        {SMALL_32B, small_pv_state},
        {MEDIUM_1KB, medium_pv_state},
        {LARGE_2MB, large_pv_state}
    };

    const std::map<std::string,std::shared_ptr<PVState>> pv_name_state_map = {
        {"PERF:SMALL", small_pv_state},
        {"PERF:MEDIUM", medium_pv_state},
        {"PERF:LARGE", large_pv_state}
    };

    std::shared_ptr<PVState> getPVStateByPayload(const PayloadType payload_type) const {
        try {
            return payload_type_state_map.at(payload_type);
        } catch (const std::out_of_range&) { return {}; }
    }

    std::shared_ptr<PVState> getPVStateByPVName(const std::string& pv_name) const {
        try {
            return pv_name_state_map.at(pv_name);
        } catch (const std::out_of_range&) { return {}; }
    }

    void onSearch(Search& op) override {
        for (auto& pv : op) {
            if (getPVStateByPVName(pv.name())) pv.claim();
        }
    }

    void onCreate(std::unique_ptr<server::ChannelControl>&& channel_control_op) override {
        const auto pv_state = getPVStateByPVName(channel_control_op->name());
        if (!pv_state) return;

        channel_control_op->onSubscribe([pv_state](std::unique_ptr<server::MonitorSetupOp>&& monitor_setup_op){
            try {
                // Ensure cleanup if a client aborts or a channel closes
                monitor_setup_op->onClose([pv_state](const std::string&){
                    pv_state->monitor_control_op.reset();
                    pv_state->started.store(false, std::memory_order_release);
                    pv_state->last_req.store(PERF_ACK, std::memory_order_release);
                    pv_state->last_sent.store(PERF_ACK, std::memory_order_release);
                    pv_state->space.signal();
                });

                pv_state->monitor_control_op = monitor_setup_op->connect(pv_state->prototype);
                if (!pv_state->monitor_control_op) {
                    monitor_setup_op->error("connect failed");
                    return;
                }
                server::MonitorStat stats;
                pv_state->monitor_control_op->stats(stats);
                pv_state->monitor_control_op->setWatermarks(0u, stats.limitQueue);

                pv_state->monitor_control_op->onStart([pv_state](const bool is_start){
                    pv_state->started.store(is_start, std::memory_order_release);
                    if (is_start) pv_state->space.signal();
                });

                pv_state->monitor_control_op->onHighMark([pv_state] { pv_state->space.signal(); });
            } catch (std::exception& e) {
                monitor_setup_op->error(e.what());
            }
        });
    }

    bool sendOne(const std::shared_ptr<PVState>& pv_state, const int32_t counter) {
        // Build the value to send
        auto makeValue = [&](const int32_t counter_to_send){
            log_debug_printf(producerlog, "Making Payload for: %s\n", counter_to_send >= 0 ? (SB() << counter_to_send).str().c_str() : counter_to_send == PERF_ACK ? "PERF_ACK" : "PERF_STOP_ACK");
            Value value = pv_state->prototype.clone();
            value["counter"] = counter_to_send;
            auto timestamp = value["timeStamp"];
            epicsTimeStamp sent_time{};
            epicsTimeGetCurrent(&sent_time);
            timestamp["secondsPastEpoch"] = sent_time.secPastEpoch;
            timestamp["nanoseconds"] = sent_time.nsec;
            // value.mark(true);
            return value;
        };

        while (true) {
            if (!pv_state->monitor_control_op) return false; // no subscriber

            if (counter < 0) {
                // For control messages (PERF_ACK, PERF_STOP_ACK), bypass flow-control and force post.
                // This ensures the consumer can receive the ACK promptly.
                const auto value = makeValue(counter);
                log_debug_printf(producerlog, "Posting Control Payload: %s\n",  counter == PERF_ACK ? "PERF_ACK" : "PERF_STOP_ACK");
                (void)pv_state->monitor_control_op->forcePost(value);
                return true;
            }

            // Always attempt to enqueue; allow server-side queueing even if the client hasn't
            // signaled start/resume yet. Backpressure is honored via tryPost() and onHighMark().
            auto value = makeValue(counter);
            log_debug_printf(producerlog, "Posting Payload for: %d\n", counter);
            if (pv_state->monitor_control_op->tryPost(value)) {
                return true;
            }
            // No space, wait until high-water callback signals there is room.
            pv_state->space.wait();
        }
    }

    void enqueue(const PayloadType payload_type, const int32_t counter) {
        const auto pv_state = getPVStateByPayload(payload_type);
        if (!pv_state) return;

        if (counter < 0) {
            // control/ACK messages: always send immediately (bypass start and flow control)
            (void)sendOne(pv_state, counter);
            return;
        }

        // Update the last requested counter, only increasing
        while (true) {
            auto prev = pv_state->last_req.load(std::memory_order_acquire);
            if (pv_state->last_req.compare_exchange_weak(prev, counter, std::memory_order_acq_rel)) break;
        }

        // Send as many as allowed up to the last requested
        while (true) {
            const auto sent = pv_state->last_sent.load(std::memory_order_acquire);
            const auto want = pv_state->last_req.load(std::memory_order_acquire);
            if (sent >= want) break;
            // If 'sent' is negative (e.g., initial PERF_ACK or STOP_ACK), the next valid data counter is 0
            int32_t next = sent + 1;
            if (next < 0) next = 0;
            if (!sendOne(pv_state, next))  // No subscriber (or closed, or waited too long) — nothing else to do
                break;
            pv_state->last_sent.store(next, std::memory_order_release);
        }
    }
};

struct PortSniffer;
/**
 * Child process struct to store the process ID and environment variables.
 */
struct Child {
    pid_t pid;
    std::vector<std::string> env{};

    Child() : pid(-1) {}

    explicit Child(const std::initializer_list<std::string>& key_value_pairs) : pid(-1), env(key_value_pairs) {}
};

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

struct WireSizes { double small; double medium; double large; };

struct Accumulator {
    // Primary sample statistics
    int32_t N=0;     // Size of sample
    double mean=0.0; // Mean of sample
    double M2=0.0;   // Sum of the squares, of differences from the mean
    double vmin=std::numeric_limits<double>::max();
    double vmax=std::numeric_limits<double>::lowest();
    uint32_t max_count{0}, min_count{0};

    // Jitter statistics computed online from successive differences (value[n] - value[n-1])
    int32_t Nj=0;        // Number of successive differences accumulated
    double meanj=0.0;    // Mean of the sum, of successive differences
    double M2j=0.0;      // Sum of the squares, of the successive differences
    double prev=0.0;     // Previous value to compute a difference
    bool has_prev=false; // Flag to indicate if previous value is valid

    /**
     * Welford's online algorithm for computing mean, variance, and standard deviation in a single pass
     * Also maintains jitter statistics as the standard deviation of successive deltas, without
     * storing the full data set.
     *
     * @see https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
     *
     * @param value value to add
     */
    void add(const double value) {
        // Track min/max and counts
        if (value == vmin) ++min_count;
        else if (value < vmin) { vmin = value; min_count = 1; }
        if (value == vmax) ++max_count;
        else if (value > vmax) { vmax = value; max_count = 1; }

        // Primary stats
        ++N;
        const double delta = value - mean;
        mean += delta/static_cast<double>(N);
        const double delta2 = value - mean;
        M2 += delta*delta2;

        // Jitter stats (successive differences)
        if (has_prev) {
            const double d = value - prev;
            ++Nj;
            const double dj = d - meanj;
            meanj += dj/static_cast<double>(Nj);
            const double dj2 = d - meanj;
            M2j += dj*dj2;
        } else {
            has_prev = true;
        }
        prev = value;
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

    /**
     * Precision of the mean (standard error). Useful to gauge confidence in the mean without
     * storing all samples.
     * @return standard error of the mean
     */
    double sem() const {
        return N > 0 ? stddev() / std::sqrt(static_cast<double>(N)) : 0.0;
    }

    /**
     * Jitter variance from successive differences
     */
    double jitter_variance() const {
        return Nj > 1 ? M2j / (static_cast<double>(Nj) - 1) : 0.0;
    }

    /**
     * Jitter (standard deviation of successive deltas)
     */
    double jitter() const {
        return std::sqrt(jitter_variance());
    }

    /**
     * Scale accumulated statistics by a constant factor.
     * Intended to convert units (e.g., seconds -> milliseconds) after accumulation.
     * Safe to call after accumulation; if called mid-stream, `prev` is also scaled
     * so subsequent jitter calculations remain consistent with the new units.
     *
     * @param factor
     * - Mean                ==> Multiply by factor
     * - M2                  ==> Multiply by factor squared
     * - Jitter mean (meanj) ==> multiply by factor
     * - Jitter M2 (M2j)     ==> multiply by factor squared
     * - Min/Max/Prev values ==> multiply by factor
     */
    void scale(const double factor) {
        vmin *= factor;
        vmax *= factor;
        mean *= factor;
        meanj *= factor;
        M2 *= factor*factor;
        M2j *= factor*factor;
        if (has_prev) prev *= factor;
    }
};

/**
 * Result: Manager
 *
 * This is used to store the results of the performance tests.
 *
 * It stores the average transmission times (values) taken from the time the updates are
 * sent to the time they are read by the client.
 *
 * The values are grouped by the second in which they are sent.
 *
 * Alongside the values we store the number of updates (expected_count) and the number of updates that
 * were dropped (dropped) grouped by the second in which they are sent.
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
    void print(ScenarioType scenario_type, PayloadType payload_type, const std::string &payload_label, uint32_t rate, const std::string &rate_label, double cpu_percent, double rss_mb, uint64_t bytes_captured)  ;
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
    epicsMutex lock;
    ScenarioType scenario_type;
    // Optional SQLite database for detailed per-packet output
    sqlite3* db{nullptr};
    sqlite3_stmt* stmt_insert{nullptr};
    sqlite3_stmt* stmt_update_tcp{nullptr};
    sqlite3_stmt* stmt_update_tls{nullptr};
    sqlite3_stmt* stmt_update_tls_cms{nullptr};
    sqlite3_stmt* stmt_update_tls_cms_stapled{nullptr};
    std::string run_id{}; // 8-hex id for this program run
    MPMCFIFO<Update> update_queue;
    epicsEvent interrupted;    // Used to cancel sleeps and terminate worker loops:
                               // - Producer: STOP/interrupts early (control handler sets this)
                               // - Consumer: set on out-of-sequence to break sleep/poll loops
                               // - Subscription monitor: checked periodically to exit promptly
    epicsEvent ok;             // Dual-purpose depending on role:
                               // - Consumer: signaled when a positive-count data update is enqueued (first data arrival gate)
                               // - Producer: signaled at end of Producer::run() to tell control loop prior scenario finished
    epicsEvent ack;            // signaled when the initial PERF_ACK is seen on data PV
    epicsEvent stop_ack;       // signaled when PERF_STOP_ACK is seen on data PV
    epicsEvent sub_event;      // signaled by subscription callback to wake drain worker
    std::atomic<bool> run_active{false}; // true when Producer::run() is active
    bool is_consumer{true};

    // Server (producer) and client (consumer) to be used for each side of the performance test scenario
    server::Server producer;
    client::Context consumer;

    // Custom Source used by the producer to implement backpressure and a virtual queue
    std::shared_ptr<ProducerSource> producer_source;

    /**
     * Constructor for the Scenario
     * @param scenario_type The type of scenario to build.
     * - TCP: Plain TCP connection.
     * - TLS: TLS connection.
     * - TLS_CMS: TLS connection with CMS status checking.
     * - TLS_CMS_STAPLED: TLS connection with CMS status checking and stapling.
     */
    Scenario (ScenarioType scenario_type);

    /**
     * Constructor for the Scenario
     * @param scenario_type The type of scenario to build.
     * - TCP: Plain TCP connection.
     * - TLS: TLS connection.
     * - TLS_CMS: TLS connection with CMS status checking.
     * - TLS_CMS_STAPLED: TLS connection with CMS status checking and stapling.
     * @param db_file_name The db file name.  If omitted, then no detailed output
     * @param run_id The run id to use for this scenario
     */
    Scenario (ScenarioType scenario_type, const std::string &db_file_name , const std::string &run_id);

    ~Scenario() {
        if (is_consumer) closeDB(); else producer.stop();
    }

    void postValue(PayloadType payload_type, int32_t counter = PERF_ACK);
    void startMonitor(PayloadType payload_type, uint32_t rate);
    void drainSubscription();
    int32_t processPendingUpdates(Result &result, const epicsTimeStamp &start);
    static void run(server::SharedPV &control_pv, const ScenarioType &scenario_type, PayloadType payload_type, const std::string &db_file_name = {}, const std::string &run_id = {});
    void run(server::SharedPV &control_pv, PayloadType payload_type, uint32_t rate, const std::string& payload_label, const std::string& rate_label);

  private:
    // Subscription the client will make for this performance test scenario
    std::shared_ptr<client::Subscription> sub;

    void initSmallScenarios();
    void initMediumScenarios();
    void initLargeScenarios();
    void buildProducerContext();

    void buildConsumerContext();

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
    void run() override;
};

struct Timed {
    Scenario &self;
    std::string payload_label;
    std::string rate_label;
    explicit Timed(Scenario &scenario, const std::string &payload_label = {}, const std::string &rate_label = {}) : self{scenario}, payload_label(payload_label), rate_label(rate_label) {}
    void printProgressBar(double progress_percentage, int32_t N) const;
};

struct Producer final : Timed {
    PayloadType payload;
    uint32_t rate;
    double window = 60.0;
    epicsTimeStamp start_time{};

    Producer(Scenario &scenario, const PayloadType payload_type, const uint32_t rate)
        : Timed{scenario}, payload{payload_type}, rate{rate} {}

   void run();

    void configure(const PayloadType payload_type, const uint32_t new_rate) {
        payload = payload_type;
        rate = new_rate;
    };
};

struct Consumer final : Timed {
    Result &result;
    const uint32_t rate;
    epicsTimeStamp start;
    std::shared_ptr<PortSniffer> sniffer;
    server::SharedPV &control_pv;
    const double window = 60.0;
    const double receive_window = 120.0;

    Consumer(Scenario &scenario, Result & result, const uint32_t rate, const std::shared_ptr<PortSniffer> &sniffer, server::SharedPV &control_pv, const std::string &payload_label, const std::string &rate_label)
        : Timed{scenario, payload_label, rate_label}, result{result}, rate{rate}, sniffer{sniffer}, control_pv{control_pv} {}

    void run();
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
