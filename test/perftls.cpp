/*
 * Minimal performance test harness.
 * Starts pvacms from project_root/bin, prints progress messages, then stops it.
 * C++11, helpers in anonymous namespace inside pvxs namespace as requested.
 */

#include <algorithm>
#include <csignal>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <functional>

#ifdef __linux__
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <time.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <mach/mach.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <iostream>
#endif

#include <libgen.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <epicsVersion.h>
#include <osiFileName.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>

#include <epicsTime.h>

// Enable expert API (Timer, evbase)
#define PVXS_ENABLE_EXPERT_API
#include "evhelper.h"

#include "openssl.h"

// CLI11 for command-line parsing
#include <CLI/CLI.hpp>

#if defined(__APPLE__)
#include <pcap.h>
#endif

DEFINE_LOGGER(perf, "pvxs.perf");

namespace pvxs {
namespace {
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
    if (!f) return 0;
    long pages_res = 0;
    long pages_total = 0;
    if (std::fscanf(f, "%ld %ld", &pages_total, &pages_res) != 2) {
        std::fclose(f);
        return 0;
    }
    std::fclose(f);
    const long page_size = sysconf(_SC_PAGESIZE); // bytes per page
    return static_cast<std::uint64_t>(pages_res) * static_cast<std::uint64_t>(page_size);
}

// Return process CPU time (user+sys) in seconds
/**
 *
 * @return
 */
double procCPUSeconds() {
    timespec ts{};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) return 0.0;
    return ts.tv_sec + ts.tv_nsec/1e9;
}

#elif defined(__APPLE__) || defined(__FreeBSD__)

// Return resident set size in bytes
std::uint64_t getRssBytes() {
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) {
        return 0;
    }
    return info.resident_size;
}

// Return process CPU time (user+sys) in seconds
double procCPUSeconds() {
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    double user = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec/1e6;
    double sys  = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec/1e6;
    return user + sys;
}

#endif

// Return wall clock (monotonic) in seconds
double wallSeconds() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec)/1e9;
}

// Sample CPU usage since prior reading (percentage of one core)
double cpuPercentSince(const double w0, const double c0) {
    const double w1 = wallSeconds();
    const double c1 = procCPUSeconds();
    const double dw = w1 - w0;
    const double dc = c1 - c0;
    return dw > 0.0 ? dc/dw*100.0 : 0.0;
}

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
// Packet capture helper to measure bytes for specific ports during an interval
struct PortSniffer {
    std::vector<pcap_t*> handles;
    std::string bpf;
    std::uint64_t total{0};
    int tcp_port{0};
    int udp_port{0};

    explicit PortSniffer(int tcp_port_, int udp_port_)
        : tcp_port(tcp_port_), udp_port(udp_port_)
    {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "(tcp or udp) and (port %d or port %d)", tcp_port, udp_port);
        bpf.assign(buf);
    }

    static void onPacket(u_char* user, const struct pcap_pkthdr* h, const u_char* /*bytes*/) {
        auto* total = reinterpret_cast<std::uint64_t*>(user);
        *total += static_cast<std::uint64_t>(h->len);
    }

    bool openAll(std::string& err) {
        char ebuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_if_t* alldevs = nullptr;
        if (pcap_findalldevs(&alldevs, ebuf) != 0) {
            err = ebuf;
            return false;
        }
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            // Build handles via pcap_create to enable immediate mode
            pcap_t* h = pcap_create(d->name, ebuf);
            if (!h) continue;
            // Snaplen, promisc, timeout
            pcap_set_snaplen(h, 65535);
            pcap_set_promisc(h, 1);
            pcap_set_timeout(h, 50);
#if defined(PCAP_ERROR_BREAK)
            (void)0; // placeholder to keep preprocessor happy in some environments
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
            pcap_setnonblock(h, 1, ebuf);

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
        pcap_freealldevs(alldevs);
        if (handles.empty()) {
            err = "pcap: no capture handles opened";
            return false;
        }
        return true;
    }

    void closeAll() {
        for (auto* h : handles) pcap_close(h);
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

    ~PortSniffer() { closeAll(); }
};
#endif

/**
 * Print a progress bar to the console
 * @param elapsed The elapsed time in seconds
 * @param prefix The prefix to print before the progress bar
 */
void printProgressBar(uint32_t elapsed, const std::string &prefix)
{
    constexpr uint32_t total = 60;
    if (elapsed > total) elapsed = total;
    std::string bar;
    bar.reserve(prefix.size() + total * 3 + 16);
    bar += prefix;
    bar += "▏"; // left cap
    for (uint32_t i = 0u; i < elapsed; ++i) bar += "█";
    for (uint32_t i = elapsed; i < total; ++i) bar += "░";
    bar += "▕"; // right cap
    std::cout << bar << "\r" << std::flush;
}

/**
 * Scenario type: This is used to specify whether the test will use tcp or tls connections,
 * and whether the status checking and stapling is enabled or disabled.
 */
enum ScenarioType {
    TCP,
    TLS,
    TLS_CMS,
    TLS_CMS_STAPLED
};

/**
 * Payload type: This is used to specify the size of the payload that will be sent over the network.
 * Small is a single 32 but integer wrapped in an NT scalar.
 * Medium is a 32x32 ubyte array (1024 bytes) wrapped in an NT NDArray.
 * Large is a 100x100x10 ubyte array (100,000 bytes) wrapped in an NT NDArray.
 */
enum PayloadType {
    SMALL,
    MEDIUM,
    LARGE,
};

// Helpers for CLI parsing and labels
inline std::string toUpperStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::toupper(c); });
    return s;
}

bool parseScenarioType(const std::string& name, ScenarioType& out) {
    auto n = toUpperStr(name);
    if ( n == "TCP" ) { out = TCP; return true; }
    if ( n == "TLS" ) { out = TLS; return true; }
    if ( n == "TLS_CMS" || n == "TLS-CMS" || n == "TLSCMS" ) { out = TLS_CMS; return true; }
    if ( n == "TLS_CMS_STAPLED" || n == "TLS-CMS-STAPLED" || n == "TLSSTAPLED" || n == "TLSCMSSTAPLED") { out = TLS_CMS_STAPLED; return true; }
    return false;
}

    bool parsePayloadType(const std::string &name, PayloadType &out) {
        auto n = toUpperStr(name);
    if ( n == "SMALL"  ) { out = SMALL; return true; }
    if ( n == "MEDIUM" ) { out = SMALL; return true; }
    if ( n == "LARGE"  ) { out = LARGE; return true; }
        return false;
    }

std::string formatRateLabel(long rate) {
    if ( rate >= 1000000 && rate % 1000000 == 0 ) {
        long v = rate/1000000;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%3ldMHz", v);
        return std::string(buf);
    }
    if ( rate >= 1000 && rate % 1000 == 0 ) {
        long v = rate / 1000;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%3ldKHz", v);
        return std::string(buf);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%3ld Hz", rate);
    return std::string(buf);
}

struct Result {
    epicsMutex lock;
    std::array<uint64_t, 60> counts;
    std::array<double, 60> values;
    uint32_t expected_count{0};
    std::array<uint32_t, 60> dropped;
    double min=std::numeric_limits<double>::max();
    double max=-1.0;

    void add(const uint index, const double value, const uint32_t this_count, const uint32_t rate) {
        if (value <= 0.0) return;

        Guard G(lock);
        const auto count = counts[index]++;
        // Calculate moving average
        values[index] = (values[index] * count + value)/(count+1);
        // Calculate dropped packets
        for (; expected_count < this_count; ++expected_count) {
            const auto dropped_index = expected_count / rate;
            dropped[dropped_index]++;
        }
        expected_count++;
        if (value < min) min = value;
        if (value > max) max = value;
    }

    void print() const {
        for (const auto value: values) {
            if (value) std::cout << value ; else std::cout << "   ";
            std::cout << ", ";
        }
        for (const auto value: dropped) {
            if (value) std::cout << value ; else std::cout << "   ";
            std::cout << ", ";
        }
        if (min < std::numeric_limits<double>::max()) std::cout << min ; else std::cout << "  ";
        if (max > 0) std::cout << ", " << max; else std::cout << ",    " ;
    }
};

struct Scenario {
    epicsEvent event;
    server::Server serv;
    client::Context cli;
    server::SharedPV small_pv;
    server::SharedPV medium_pv;
    server::SharedPV large_pv;
    Value small_value;
    Value medium_value;
    Value large_value;
    std::shared_ptr<client::Subscription> sub;
    uint32_t counter{0};
    int tcp_port{0};
    int udp_port{0};

    Scenario(ScenarioType scenario_type) {
        // Build Server
        auto serv_conf = pvxs::server::Config::fromEnv();
        serv_conf.tls_keychain_file = "server1.p12";
        // Use ephemeral port to avoid conflicts with pvacms child process
        serv_conf.udp_port = 0;
        serv_conf.tls_disabled = scenario_type == TCP;
        serv_conf.tls_disable_status_check = scenario_type < TLS_CMS;
        serv_conf.tls_disable_stapling = scenario_type < TLS_CMS_STAPLED;
        serv = serv_conf.build();


        // Build PVs
        small_pv = server::SharedPV::buildReadonly();
        serv.addPV("PERF:SMALL", small_pv);
        medium_pv = server::SharedPV::buildReadonly();
        serv.addPV("PERF:MEDIUM", medium_pv);
        large_pv = server::SharedPV::buildReadonly();
        serv.addPV("PERF:LARGE", large_pv);

        // Build data
        // 4 byte data payload (plus NT scaffolding)
        auto s_def (nt::NTScalar{TypeCode::Int32}.build());
        s_def += { Int32("counter") };
        small_value = s_def.create();

        auto def(nt::NTNDArray{}.build());
        def += { Int32("counter") };
        def += { StructA("dimensions", { Int32("value"), }), };

        // 1k payloads (plus NT scaffolding)
        medium_value = def.create();
        // 1K: Build 32x32 = 1024 bytes ubyte array
        {
            constexpr int d0 = 32, d1 = 32;
            shared_array<uint8_t> buf(d0*d1);
            for (size_t i = 0u; i < buf.size(); ++i) buf[i] = static_cast<uint8_t>(i);
            shared_array<const uint8_t> medium_data(buf.freeze());
            shared_array<Value> small_dimensions;
            small_dimensions.resize(2);
            small_dimensions[0] = medium_value["dimension"].allocMember().update("size", d0);
            small_dimensions[1] = small_dimensions[0].cloneEmpty().update("size", d1);

            medium_value["value->ubyteValue"] = medium_data;
            medium_value["dimension"] = small_dimensions.freeze();
        }

        // 2MB = 4 Mega-Pixels: 2000 x 2000 mono (4 Mpx), 4 bits/pixel => 2,000,000 bytes
        large_value = def.create();
        constexpr int height = 2000;
        constexpr int width  = 2000;
        constexpr size_t n_pixels = static_cast<size_t>(height) * static_cast<size_t>(width);
        constexpr size_t n_bytes  = (n_pixels + 1u) / 2u; // two pixels per byte

        // allocate packed buffer (each byte holds two 4-bit pixels)
        shared_array<uint8_t> buf(n_bytes);

        // ---- dimensions (pixel sizes) ----
        shared_array<Value> dims;
        dims.resize(2);
        dims[0] = large_value["dimension"].allocMember()
                     .update("size", height)
                     .update("offset", 0)
                     .update("fullSize", height)
                     .update("binning", 1)
                     .update("reverse", false);
        dims[1] = dims[0].cloneEmpty()
                     .update("size", width)
                     .update("fullSize", width);
        large_value["dimension"] = dims.freeze();

        // ---- data ----
        large_value["value->ubyteValue"] = shared_array<const uint8_t>(buf.freeze());

        // ---- sizes / codec ----
        large_value["uncompressedSize"] = static_cast<int64_t>(n_bytes);
        large_value["compressedSize"]   = static_cast<int64_t>(n_bytes); // raw
        large_value["codec.name"]       = "raw";

        // ---- attributes: at least ColorMode and BitsPerPixel ----
        auto mkAttr = [&](const char* name, const uint32_t n) {
            auto attribute = large_value["attribute"].allocMember();
            attribute["name"]        = name;
            attribute["value"]       = n;
            attribute["descriptor"]  = "auto";
            attribute["sourceType"]  = 0;
            attribute["source"]      = "";
            return attribute;
        };
        pvxs::shared_array<Value> attrs;
        attrs.resize(2);
        attrs[0] = mkAttr("ColorMode", 0); // 0 = Mono (convention)
        attrs[1] = mkAttr("BitsPerPixel", 4);
        large_value["attribute"] = attrs.freeze();

        // finalize dims

        small_pv.open(small_value);
        medium_pv.open(medium_value);
        large_pv.open(large_value);

        serv.start();
        // After server starts, query effective bound ports and build client
        {
            const auto& eff = serv.config();
            udp_port = eff.udp_port;
            tcp_port = eff.tcp_port;
        }

        // Build Client (force network over loopback, using the server's actual ports)
        {
            auto cli_conf = client::Config::fromEnv();
#ifdef PVXS_ENABLE_OPENSSL
            // Mirror TLS flags from scenario
            cli_conf.tls_disabled = (scenario_type == TCP);
            cli_conf.tls_disable_status_check = scenario_type < TLS_CMS;
            cli_conf.tls_disable_stapling = scenario_type < TLS_CMS_STAPLED;
#endif
            cli_conf.tls_keychain_file = "client1.p12";
            // Direct all discovery and name resolution to localhost using our server's ports
            cli_conf.udp_port = udp_port;
            cli_conf.tcp_port = tcp_port;
            cli_conf.addressList.clear();
            cli_conf.addressList.push_back(std::string("127.0.0.1:") + std::to_string(udp_port));
            cli_conf.nameServers.clear();
            cli_conf.nameServers.push_back(std::string("127.0.0.1:") + std::to_string(tcp_port));
            cli_conf.interfaces.clear();
            cli_conf.interfaces.push_back("127.0.0.1");
            cli_conf.autoAddrList = false;
            cli = cli_conf.build();
        }
    }

    ~Scenario() {
        serv.stop();
    }

    void run(const PayloadType payload_type) {
        const auto payload_label = (payload_type == LARGE ? "Large(4MB)" : payload_type == MEDIUM ? "Medium(1KB)" : "SMALL(4B)");
        run(payload_type, 1, payload_label, "  1 Hz");
        run(payload_type, 10, payload_label, " 10 Hz");
        run(payload_type, 100, payload_label, "100 Hz");
        run(payload_type, 1000, payload_label, "  1KHz");
        if ( payload_type != LARGE ) {
            run(payload_type, 10000, payload_label, " 10KHz");
            run(payload_type, 100000, payload_label, "100KHz");
            run(payload_type, 1000000, payload_label, "  1MHz");
        }
    }

    void startMonitor(const PayloadType payload_type) {
        // Set up monitor subscription and consume updates using epicsEvent pattern
        const char* pv_name = (payload_type == LARGE) ? "PERF:LARGE" : (payload_type == MEDIUM) ? "PERF:MEDIUM" : "PERF:SMALL";

        sub = cli.monitor(pv_name)
            .maskConnected(true)   // suppress Connected events from throwing
            .maskDisconnected(true)
            .event([this](client::Subscription&){
                // signal our Scenario epicsEvent when an update arrives
                event.signal();
            })
            .exec();
    }

    std::function<void()> postValue(const PayloadType payload_type) {
        return [this, payload_type]() {
            try {
                // Build update value and post to the appropriate PV
                if (payload_type == LARGE) {
                    auto v = large_value.clone();
                    v["counter"] = counter++;
                    auto ts = v["timeStamp"];
                    if (ts) {
                        epicsTimeStamp now{};
                        epicsTimeGetCurrent(&now);
                        ts["secondsPastEpoch"] = now.secPastEpoch;
                        ts["nanoseconds"] = now.nsec;
                    }
                    v.mark(true);
                    large_pv.post(v);
                } else if (payload_type == MEDIUM) {
                    auto v = medium_value.clone();
                    v["counter"] = counter++;
                    auto ts = v["timeStamp"];
                    if (ts) {
                        epicsTimeStamp now{};
                        epicsTimeGetCurrent(&now);
                        ts["secondsPastEpoch"] = now.secPastEpoch;
                        ts["nanoseconds"] = now.nsec;
                    }
                    v.mark(true);
                    medium_pv.post(v);
                } else {
                    auto v = small_value.clone();
                    v["counter"] = counter++;
                    auto ts = v["timeStamp"];
                    if (ts) {
                        epicsTimeStamp now{};
                        epicsTimeGetCurrent(&now);
                        ts["secondsPastEpoch"] = now.secPastEpoch;
                        ts["nanoseconds"] = now.nsec;
                    }
                    v.mark(true);
                    small_pv.post(v);
                }
            } catch (std::exception &e) {
                log_warn_printf(perf, "post_once error: %s\n", e.what());
            }
        };
    }

    // Drain all pending updates
    void processPendingUpdates(Result &result, const epicsTimeStamp &start, uint32_t &last_index, const std::string &progress_prefix, const uint32_t
                               rate) const {
        bool first_event_in_batch = true;
        epicsTimeStamp now{};
        while(true) {
            try {
                if (auto val = sub->pop()) {

                    // Get now only when we get the first update in this batch
                    if (first_event_in_batch)
                        epicsTimeGetCurrent(&now);

                    first_event_in_batch = false;

                    // Get the timestamp that shows when the data was sent
                    const auto timestamp = val["timeStamp"];
                    const auto received_count = val["counter"].as<uint32_t>();
                    epicsTimeStamp sent{
                        timestamp["secondsPastEpoch"].as<epicsUInt32>(),
                        timestamp["nanoseconds"].as<epicsUInt32>()
                    };

                    // Determine how much time has elapsed from the beginning of the test sequence
                    const double elapsed = epicsTimeDiffInSeconds(&sent, &start);
                    // Determine how much time the data was in transit
                    const double transit_time = epicsTimeDiffInSeconds(&now, &sent);

                    constexpr double window = 60.0;
                    if (elapsed >= window) break;
                    const auto bucket_index = static_cast<uint32_t>(elapsed);

                    if (bucket_index < result.values.size() && transit_time > 0)
                        result.add(bucket_index, transit_time, received_count, rate);

                    if (bucket_index != last_index) {
                        last_index = bucket_index;
                        printProgressBar(bucket_index, progress_prefix);
                    }
                } else break;
            } catch(const client::Connected&) {
                // ignore
            } catch(const client::Disconnect&) {
                // ignore
            }
        }
    }

    void run(const PayloadType payload_type, const long rate, const std::string &payload_label, const std::string &speed_label) {
        if ( payload_type == LARGE && rate > 1000 ) {
            log_warn_printf(perf, "Skipping LARGE payloads where rate is greater that 1K: %s\n", speed_label.c_str());
            return;
        }

        Result result{};

        // Collect Data
        const double w0 = wallSeconds();
        const double c0 = procCPUSeconds();
        std::uint64_t bytes_captured = 0;
        {
            PortSniffer sniffer(tcp_port, udp_port);
            sniffer.startCapture();

            startMonitor(payload_type);

            // Calculate the posting cadence
            const double period = 1.0/static_cast<double>(rate);

            const auto postOnce = postValue(payload_type);

            // Mark the start time for this sequence
            epicsTimeStamp start{};
            epicsTimeGetCurrent(&start);

            // 60-second window
            uint32_t last_index = std::numeric_limits<uint32_t>::max();
            const std::string progress_prefix = std::string(payload_label) + ", " + std::string(speed_label) + ", ";

            while(true) {
                // continuously drain captured packets during the test window
                sniffer.poll();

                processPendingUpdates(result, start, last_index, progress_prefix, rate);

                constexpr double window = 60.0;
                constexpr double receive_window = 120.0;
                // Check if the time window has expired
                epicsTimeStamp nows{};
                epicsTimeGetCurrent(&nows);
                double elapsed = epicsTimeDiffInSeconds(&nows, &start);
                const double remaining_time = window - elapsed;
                const double remaining_wait_time = receive_window - elapsed;
                if (remaining_time <= 0.0) break;

                // Determine time until next post
                double until_next = period - std::fmod(elapsed, period);
                if (until_next < 0.0) until_next = 0.0;
                const double time_to_wait = std::min(remaining_wait_time, until_next);

                // Wait for the next update or the next time to post a new value
                const bool signaled = event.wait(time_to_wait);

                // drain again after wait to catch bursts
                sniffer.poll();

                if(!signaled) {
                    postOnce();
                    // drain after posting too
                    sniffer.poll();
                }
            }

            // End of Tests
            // final drain before reading total
            sniffer.poll();
            bytes_captured = sniffer.endCapture();
        }

        const double rss_mb = static_cast<double>(getRssBytes()) / (1024 * 1024);
        const auto cpu_percent = cpuPercentSince(w0, c0);

        // Display Data
        std::cout << payload_label << ", "  << speed_label << ", ";
        result.print();
        std::cout << ", " << cpu_percent << ", " << rss_mb << ",  " << bytes_captured << std::endl;
    }
};

/**
 * Extract target architecture from the given test executable path name
 *
 * @param path
 * @return
 */
std::string extractTargetArch(const std::string& path)
{
    if ( path.empty() ) return std::string();
    auto terminated_by_path_separator = ( path.back() == '/' ) ;
    const auto base_path = path.substr(0,std::string::npos - (terminated_by_path_separator?1:0));
    std::string target_arch = basename(const_cast<char *>(base_path.c_str()));
    const auto ta= target_arch.substr(2,std::string::npos);
    log_debug_printf(perf, "Target architecture: %s\n", ta.c_str());
    return ta;
}

struct Child {
    pid_t pid;
    std::vector<std::string> env{};

    Child() : pid(-1) {}

    explicit Child(const std::initializer_list<std::string> &key_value_pairs)
        : pid(-1), env(key_value_pairs) {}

};

bool startPVACMS(const std::string& pvacms_executable_path, Child& pvacms_subprocess)
{
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
        for (const auto &env_part : pvacms_subprocess.env) {
            if (key.empty()) {
                key = env_part;
            } else {
                if ( env_part.empty()) {
                    if (unsetenv(key.c_str()) != 0) {
                        log_err_printf(perf, "Failed to unset environment variable: %s \n", key.c_str());
                    }
                } else {
                    if (setenv(key.c_str(), env_part.c_str(), 1) != 0) {
                        log_err_printf(perf, "Failed to set environment variable: %s = \"%s\"\n", key.c_str(), env_part.c_str());
                    }
                }
                key = {};
            }
        }

        const char* argv0 = pvacms_executable_path.c_str();
        log_info_printf(perf, "Starting child process: %s %s\n", pvacms_executable_path.c_str(), "pvacms");
        execlp(argv0, "pvacms", "--preload-cert", "server1.p12", "client1.p12",  nullptr);

        // If exec fails
        log_err_printf(perf, "Failed to start child process: %s %s\n", pvacms_executable_path.c_str(), "pvacms");
        _exit(127);
    }

    // Parent process
    pvacms_subprocess.pid = pid;
    return true;
}

void stopPVACMS(Child& child)
{
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
            usleep(100000); // 100ms
        }
        // Force kill if still running
        kill(child.pid, SIGKILL);
        waitpid(child.pid, 0, 0);
        child.pid = -1;
    }
}

Child pvacms_subprocess;

// Simple Ctrl-C (SIGINT) trap: print message then exit
static void onSigint(int)
{
    const char msg[] = "\nExiting...\n";
    write(STDERR_FILENO, msg, sizeof(msg)-1);
    stopPVACMS(pvacms_subprocess);
    _exit(130);
}

} // anonymous namespace
} // namespace pvxs

int main(int argc, char* argv[])
{
#if defined(EPICS_VERSION_INT) && EPICS_VERSION_INT >= VERSION_INT(7, 0, 3, 1)
    (void)argc; (void)argv;
    pvxs::logger_level_set(perf.name, pvxs::Level::Info);
    pvxs::logger_config_env();
    // Install simple Ctrl-C trap
    signal(SIGINT, pvxs::onSigint);

    // CLI argument parsing
    std::vector<std::string> opt_scenarios;
    std::vector<std::string> opt_payloads;
    std::vector<long> opt_rates;

    CLI::App app{"PVXS TLS performance tests"};
    app.add_option("-s,--scenario-type", opt_scenarios, "Scenario type(s): TCP, TLS, TLS_CMS, TLS_CMS_STAPLED. May be repeated.");
    app.add_option("-p,--payload-type", opt_payloads, "Payload type(s): SMALL, MEDIUM, LARGE. May be repeated.");
    app.add_option("-r,--rate", opt_rates, "Update rate(s) in Hz. May be repeated.");
    CLI11_PARSE(app, argc, argv);

    // Build selected lists (defaults to all if no selection)
    std::vector<pvxs::ScenarioType> scenarios_sel;
    if(opt_scenarios.empty()) {
        scenarios_sel = {pvxs::TCP, pvxs::TLS, pvxs::TLS_CMS, pvxs::TLS_CMS_STAPLED};
    } else {
        for(const auto& s : opt_scenarios) {
            pvxs::ScenarioType st{};
            if(!pvxs::parseScenarioType(s, st)) {
                std::cerr << "Unknown scenario type: " << s << std::endl;
                return 2;
            }
            scenarios_sel.push_back(st);
        }
    }

    std::vector<pvxs::PayloadType> payloads_sel;
    if(opt_payloads.empty()) {
        payloads_sel = {pvxs::SMALL, pvxs::MEDIUM, pvxs::LARGE};
    } else {
        for(const auto& p : opt_payloads) {
            pvxs::PayloadType pt{};
            if(!pvxs::parsePayloadType(p, pt)) {
                std::cerr << "Unknown payload type: " << p << std::endl;
                return 2;
            }
            payloads_sel.push_back(pt);
        }
    }

    std::cout << "Starting Performance Tests" << std::endl;

    // Determine test install dir
    std::string test_dir;
    char *executable_path = epicsGetExecDir();
    if(executable_path) {
        try {
            test_dir = executable_path;
            free(executable_path);
        } catch(...) {
            free(executable_path);
            throw;
        }
    }

    // Change working dir to test dir
    if ( chdir(test_dir.c_str()) ) {
        std::cerr << "Failed to change to test directory: " <<test_dir << std::endl;
        return 2;
    }

    // Extract the target architecture from the test directory name
    const std::string target_arch = pvxs::extractTargetArch(test_dir);

    // Determine the pvacms executable location
    const std::string pvacms_executable_path = test_dir
        + ".."
        + OSI_PATH_SEPARATOR + ".."
        + OSI_PATH_SEPARATOR + "bin"
        + OSI_PATH_SEPARATOR + target_arch
        + OSI_PATH_SEPARATOR + "pvacms";
    std::cout << "pvacms executable: " << pvacms_executable_path << std::endl;

    // Create a child process to run PVACMS
    pvxs::pvacms_subprocess = pvxs::Child{
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
    if (!pvxs::startPVACMS(pvacms_executable_path, pvxs::pvacms_subprocess)) {
        std::cerr << "Failed to start pvacms: " << pvacms_executable_path << std::endl;
        return 1;
    }

    // Wait for pvacms to start up
    std::cout << "Waiting for pvacms to start before running tests" << std::endl;
    sleep (2);
    std::cout << "PVACMS Ready" << std::endl;

    // Run selected scenarios
    for (auto scenario_type : scenarios_sel) {
        std::cout << "+=======================================+=======================================" << std::endl;
        std::cout << "Scenario: " << (
            scenario_type == pvxs::TLS_CMS_STAPLED ? "TLS with stapled status" :
            scenario_type == pvxs::TLS_CMS ? "TLS with status":
            scenario_type == pvxs::TLS ? "TLS no status": "TCP") << std::endl;

        std::cout << "Configuring Performance Tests" << std::endl;
        pvxs::Scenario scenario(scenario_type);

        std::cout << "Running Performance Tests" << std::endl;
        std::cout << "+=======================================+=======================================" << std::endl;

        std::cout << "Starting Test" << std::endl;
        std::cout << "+=======================================+=======================================" << std::endl;
        std::cout << "           ,  ,"
                  << " 1, 2, 3, 4, 5, 6, 7, 8, 9,10,"
                  << "11,12,13,14,15,16,17,18,19,20,"
                  << "21,22,23,24,25,26,27,28,29,30,"
                  << "31,32,33,34,35,36,37,38,39,40,"
                  << "41,42,43,44,45,46,47,48,49,50,"
                  << "51,52,53,54,55,56,57,58,59,60,"
                  << "D1,  D2, D3, D4, D5, D6, D7, D8, D9,D10,"
                  << "D11,D12,D13,D14,D15,D16,D17,D18,D19,D20,"
                  << "D21,D22,D23,D24,D25,D26,D27,D28,D29,D30,"
                  << "D31,D32,D33,D34,D35,D36,D37,D38,D39,D40,"
                  << "D41,D42,D43,D44,D45,D46,D47,D48,D49,D50,"
                  << "D51,D52,D53,D54,D55,D56,D57,D58,D59,D60,"
                  << "min,max,"
                  << "cpu(%),mem(MB),wire(bytes)"
                  << std::endl;

        for (auto payload_type : payloads_sel) {
            if(opt_rates.empty()) {
                scenario.run(payload_type);
            } else {
                const std::string payload_label = (payload_type == pvxs::LARGE ? "Large(4MB)" : (payload_type == pvxs::MEDIUM ? "Medium(1KB)" : "Small(4B)"));
                for (auto rate : opt_rates) {
                    const std::string speed_label = pvxs::formatRateLabel(rate);
                    scenario.run(payload_type, rate, payload_label, speed_label);
                }
            }
        }

        std::cout << "+=======================================+=======================================" << std::endl;
        std::cout << "Test Complete" << std::endl;
        std::cout << std::endl;
    }

    pvxs::stopPVACMS(pvxs::pvacms_subprocess);

    std::cout << "Performance Tests Complete" << std::endl;
#endif
    return 0;
}
