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

#if defined(__APPLE__)
#include <pcap.h>
#endif

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
    SMALL_4B,
    MEDIUM_1KB,
    LARGE_2MB,
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
    epicsMutex lock;

    int32_t n = 0;
    double mean = 0.0;
    double M2 = 0.0; // the sum, of the squares, of the differences from the current mean
    double min = std::numeric_limits<double>::max();
    double max = std::numeric_limits<double>::lowest();

    int32_t add(double value) ;
    void print(ScenarioType scenario_type, PayloadType payload_type, const std::string &payload_label, uint32_t rate, const std::string &rate_label, double cpu_percent, double rss_mb, uint64_t bytes_captured) const ;

    double variance() const {
        return n > 1 ? M2 / (static_cast<double>(n) - 1) : 0.0;
    }

    double stddev() const {
        return std::sqrt(variance());
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
    MPMCFIFO<Update> update_queue;

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
     */
    explicit Scenario(ScenarioType scenario_type);

    ~Scenario() { server.stop(); }

    void initSmallScenarios();
    void initMediumScenarios();
    void initLargeScenarios();
    void configureServer();
    void startServer() ;
    void buildClientContext();
    static void run(const ScenarioType &scenario_type, PayloadType payload_type);
    void run(PayloadType payload_type, uint32_t rate, const std::string& payload_label, const std::string& rate_label);
    void startMonitor(PayloadType payload_type, uint32_t rate);
    void postValue(PayloadType payload_type, int32_t counter = -1);
    int32_t processPendingUpdates(Result &result, const epicsTimeStamp &start);
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
    const std::string progress_prefix;
    uint32_t prior_percentage = std::numeric_limits<uint32_t>::max();
    const double window = 60.0;
    const double receive_window = window * 1.0 / 0.9;

    UpdateConsumer(Scenario &s, Result & result, const uint32_t rate, const epicsTimeStamp &start, const std::shared_ptr<PortSniffer> &sniffer, const std::string& progress_prefix)
        : self{s}, result{result}, rate{rate}, start{start}, sniffer{sniffer}, progress_prefix{progress_prefix} {}

    void run() override;
    void printProgressBar(uint32_t progress_percentage, const std::string& prefix) ;

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
