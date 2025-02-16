/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <cmath>
#include <iostream>
#include <limits>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <stdexcept>

#ifdef __unix__
#include <pwd.h>
#endif
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include <epicsStdlib.h>
#include <epicsString.h>
#include <osiSock.h>
#include <unistd.h>

#include <pvxs/log.h>

#include <sys/stat.h>
#include <cstdlib>

#include "clientimpl.h"
#include "evhelper.h"
#include "serverconn.h"
#include "utilpvt.h"

DEFINE_LOGGER(serversetup, "pvxs.svr.init");
DEFINE_LOGGER(clientsetup, "pvxs.cli.init");
DEFINE_LOGGER(config, "pvxs.config");

namespace pvxs {

namespace impl {
std::string getHomeDir() {
#ifdef _WIN32
    const char* home = getenv("USERPROFILE");
#else
    struct passwd *pw = getpwuid(getuid());

    if (pw == nullptr) {
        throw std::runtime_error("Failed to get home directory");
    }
    const char * home = pw->pw_dir;
#endif
    return home ? std::string(home) : std::string("");
}

std::string getXdgConfigHome(std::string default_home) {
    const std::string suffix = SB() << OSI_PATH_SEPARATOR << "pva" << OSI_PATH_SEPARATOR << ConfigCommon::version ;
    const char* config_home = getenv("XDG_CONFIG_HOME");
    return SB() << (config_home ? config_home : default_home) << suffix;
}

std::string getXdgDataHome(std::string default_home) {
    const std::string suffix = SB() << OSI_PATH_SEPARATOR << "pva" << OSI_PATH_SEPARATOR << ConfigCommon::version ;
    const char* data_home = getenv("XDG_DATA_HOME");
    return SB() << (data_home ? data_home : default_home) << suffix;
}

ConfigCommon::~ConfigCommon() {}
#define stringifyX(X) #X
#define stringify(X) stringifyX(X)

const std::string ConfigCommon::home = getHomeDir();
const std::string ConfigCommon::version = stringify(PVXS_MAJOR_VERSION) "."  stringify(PVXS_MINOR_VERSION);
#ifdef _WIN32
const std::string ConfigCommon::config_home = SB() << home << "\\PVA\\" << version;
const std::string ConfigCommon::data_home = SB() << "C:\\ProgramData\\PVA\\" << version;
#else
const std::string ConfigCommon::config_home = getXdgConfigHome(SB() << home << "/.config");
const std::string ConfigCommon::data_home = getXdgDataHome(SB() << home << "/.local/share");
#endif
#undef stringifyX
#undef stringify
}  // namespace impl

SockEndpoint::SockEndpoint(const char* ep, const impl::ConfigCommon* conf, uint16_t defdefport) {
    uint16_t defport = conf ? conf->tcp_port : defdefport;
    // look for URI-ish prefix
    std::string urlstore;
    if (auto sep = strstr(ep, "://")) {
        auto schemeLen = sep - ep;
        if (!conf) {
            throw std::runtime_error("URI unsupported in this context");
#ifdef PVXS_ENABLE_OPENSSL
        } else if (schemeLen == 4u && strncmp(ep, "pvas", 4) == 0) {
            scheme = TLS;
            defport = conf ? conf->tls_port : defdefport;
#endif
        } else if (schemeLen == 3u && strncmp(ep, "pva", 3) == 0) {
            scheme = Plain;
        } else {
            throw std::runtime_error(SB() << "Unsupported scheme '" << ep << "'");
        }
        ep = sep + 3u;                     // skip past prefix
        if (auto end = strchr(ep, '/')) {  // trailing '/'
            // copy only host_ip:port
            urlstore.assign(ep, end - ep);
            ep = urlstore.c_str();
        }
    }

    // <IP46>
    // <IP46>,<ttl#>
    // <IP46>@ifacename
    // <IP46>,<ttl#>@ifacename
    auto comma = strchr(ep, ',');
    auto at = strchr(ep, '@');

    if (comma && at && comma > at) {
        throw std::runtime_error(SB() << '"' << escape(ep) << "\" comma expected before @");
    }

    if (!comma && !at) {
        addr.setAddress(ep, defport);

    } else {  // comma || at
        auto firstsep = comma ? comma : at;
        addr.setAddress(std::string(ep, firstsep - ep), defport);

        if (comma && !at) {
            ttl = parseTo<int64_t>(comma + 1);

        } else if (comma) {
            ttl = parseTo<int64_t>(std::string(comma + 1, at - comma - 1));
        }

        if (at) iface = at + 1;
    }

    auto& ifmap = IfaceMap::instance();

    if (addr.family() == AF_INET6) {
        if (iface.empty() && addr->in6.sin6_scope_id) {
            // interface index provide with IPv6 address
            // we map back to symbolic name for storage
            iface = ifmap.name_of(addr->in6.sin6_scope_id);
        }
        addr->in6.sin6_scope_id = 0;

    } else if (addr.family() == AF_INET && addr.isMCast() && !iface.empty()) {
        SockAddr ifaddr(AF_INET);

        if (evutil_inet_pton(AF_INET, iface.c_str(), &ifaddr->in.sin_addr.s_addr) == 1) {
            // map interface address to symbolic name

            iface = ifmap.name_of(ifaddr);
        }
    }

    if (!iface.empty() && !ifmap.index_of(iface)) {
        log_warn_printf(config, "Invalid interface address or name: \"%s\"\n", iface.c_str());
    }
}

MCastMembership SockEndpoint::resolve() const {
    if (!addr.isMCast()) throw std::logic_error("not mcast");

    auto& ifmap = IfaceMap::instance();

    MCastMembership m;
    m.af = addr.family();
    if (m.af == AF_INET) {
        auto& req = m.req.in;
        req.imr_multiaddr.s_addr = addr->in.sin_addr.s_addr;

        if (!iface.empty()) {
            auto iface = ifmap.address_of(this->iface);
            if (iface.family() == AF_INET) {
                req.imr_interface.s_addr = iface->in.sin_addr.s_addr;
            }
        }

    } else if (m.af == AF_INET6) {
        auto& req = m.req.in6;
        req.ipv6mr_multiaddr = addr->in6.sin6_addr;

        if (!iface.empty()) {
            req.ipv6mr_interface = ifmap.index_of(this->iface);
            if (!req.ipv6mr_interface) {
                log_warn_printf(config, "Unable to resolve interface '%s'\n", iface.c_str());
            }
        }

    } else {
        throw std::logic_error("Unsupported address family");
    }
    return m;
}

std::ostream& operator<<(std::ostream& strm, const SockEndpoint& addr) {
    if (addr.scheme == SockEndpoint::TLS) strm << "pvas://";
    strm << addr.addr;
    if (addr.addr.isMCast()) {
        if (addr.ttl) strm << ',' << addr.ttl;
        if (!addr.iface.empty()) strm << '@' << addr.iface;
    }
    return strm;
}

bool operator==(const SockEndpoint& lhs, const SockEndpoint& rhs) { return lhs.addr == rhs.addr && lhs.ttl == rhs.ttl && lhs.iface == rhs.iface; }

namespace {

/* Historically pvAccessJava used $EPICS_PVA_CONN_TMO as the period
 * between sending CMD_ECHO.  To avoid meta-stability apply a scaling
 * factor.
 * https://github.com/epics-base/pvAccessCPP/issues/171
 */
constexpr double tmoScale = 4.0 / 3.0;  // 40 second idle timeout / 30 configured

// remove duplicates while preserving order of first appearance
template <typename A>
void removeDups(std::vector<A>& addrs) {
    std::sort(addrs.begin(), addrs.end());
    addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
}

// special handling for SockEndpoint where duplication is based on
// address,interface.  Duplicates are combined with the longest TTL.
template <>
void removeDups(std::vector<SockEndpoint>& addrs) {
    std::map<std::pair<SockAddr, std::string>, size_t> seen;
    for (size_t i = 0; i < addrs.size();) {
        auto& ep = addrs[i];
        auto key = std::make_pair(ep.addr, ep.iface);
        auto it = seen.find(key);
        if (it == seen.end()) {  // first sighting
            seen[key] = i++;

        } else {  // duplicate
            auto& orig = addrs[it->second];

            if (ep.ttl > orig.ttl) {  // w/ longer TTL
                orig.ttl = ep.ttl;
            }

            addrs.erase(addrs.begin() + i);
            // 'ep' and 'orig' are invalidated
        }
    }
}

void split_into(std::vector<std::string>& out, const std::string& inp) {
    size_t pos = 0u;

    while (pos < inp.size()) {
        auto start = inp.find_first_not_of(" \t\r\n", pos);
        auto end = inp.find_first_of(" \t\r\n", start);
        pos = end;

        if (start < end) {
            out.push_back(inp.substr(start, end == std::string::npos ? end : end - start));
        }
    }

    removeDups(out);
}

void split_addr_into(const char* name, std::vector<std::string>& out, const std::string& inp, const impl::ConfigCommon* conf, uint16_t defaultPort,
                     bool required = false) {
    std::vector<std::string> raw;
    split_into(raw, inp);

    // parse, resolve host names, then re-print.
    // Catch syntax errors early, and normalize prior to removing duplicates
    for (auto& temp : raw) {
        try {
            SockEndpoint ep(temp, conf, defaultPort);
            out.push_back(SB() << ep);

        } catch (std::exception& e) {
            if (required) throw std::runtime_error(SB() << "invalid endpoint \"" << temp << "\" " << e.what());
            log_err_printf(config, "%s ignoring invalid '%s' : %s\n", name, temp.c_str(), e.what());
        }
    }
}

std::string join_addr(const std::vector<std::string>& in) {
    std::ostringstream strm;
    bool first = true;
    for (auto& addr : in) {
        if (first)
            first = false;
        else
            strm << ' ';
        strm << addr;
    }
    return strm.str();
}

void parse_bool(bool& dest, const std::string& name, const std::string& val) {
    if (epicsStrCaseCmp(val.c_str(), "YES") == 0 || val == "1") {
        dest = true;
    } else if (epicsStrCaseCmp(val.c_str(), "NO") == 0 || val == "0") {
        dest = false;
    } else {
        log_err_printf(config, "%s invalid bool value (YES/NO) : '%s'\n", name.c_str(), val.c_str());
    }
}

void parse_timeout(double& dest, const std::string& name, const std::string& val) {
    double temp;
    try {
        temp = parseTo<double>(val);

        if (!std::isfinite(temp) || temp < 0.0 || temp > double(std::numeric_limits<time_t>::max())) throw std::out_of_range("Out of range");

        dest = temp * tmoScale;
    } catch (std::exception& e) {
        log_err_printf(serversetup, "%s invalid double value : '%s'\n", name.c_str(), val.c_str());
    }
}

std::vector<SockEndpoint> parseAddresses(const std::vector<std::string>& addrs) {
    std::vector<SockEndpoint> ret;
    for (const auto& addr : addrs) {
        try {
            ret.emplace_back(addr);
        } catch (std::runtime_error& e) {
            log_warn_printf(config, "Ignoring %s : %s\n", addr.c_str(), e.what());
            continue;
        }
    }
    return ret;
}

void printAddresses(std::vector<std::string>& out, const std::vector<SockEndpoint>& inp) {
    std::vector<std::string> temp;
    temp.reserve(inp.size());

    for (auto& addr : inp) {
        temp.emplace_back(SB() << addr);
    }
    out = std::move(temp);
}

// Fill out address list by appending broadcast addresses
// of any and all local interface addresses already included
void expandAddrList(const std::vector<SockEndpoint>& ifaces, std::vector<SockEndpoint>& addrs) {
    SockAttach attach;
    evsocket dummy(AF_INET, SOCK_DGRAM, 0);

    for (auto& saddr : ifaces) {
        auto matchAddr = &saddr.addr;

        if (evsocket::ipstack == evsocket::Linsock && saddr.addr.family() == AF_INET6 && saddr.addr.isAny()) {
            // special case handling to match "promote" in server::Config::expand()
            // treat [::] as 0.0.0.0
            matchAddr = nullptr;

        } else if (saddr.addr.family() != AF_INET) {
            continue;
        }

        for (auto& addr : dummy.broadcasts(matchAddr)) {
            addr.setPort(0u);
            addrs.emplace_back(addr);
        }
    }
}

void addGroups(std::vector<SockEndpoint>& ifaces, const std::vector<SockEndpoint>& addrs) {
    auto& ifmap = IfaceMap::instance();
    std::set<std::string> allifaces;

    for (const auto& addr : addrs) {
        if (!addr.addr.isMCast()) continue;

        if (!addr.iface.empty()) {
            // interface already specified
            ifaces.push_back(addr);

        } else {
            // no interface specified, treat as wildcard
            if (allifaces.empty()) allifaces = ifmap.all_external();

            for (auto& iface : allifaces) {
                auto ifaceaddr(addr);
                ifaceaddr.iface = iface;
                ifaces.push_back(ifaceaddr);
            }
        }
    }
}

void enforceTimeout(double& tmo) {
    /* Inactivity timeouts with PVA have a long (and growing) history.
     *
     * - Originally pvAccessCPP clients didn't send CMD_ECHO, and servers would never timeout.
     * - Since module version 7.0.0 (in Base 7.0.3) clients send echo every 15 seconds, and
     *   either peer will timeout after 30 seconds of inactivity.
     * - pvAccessJava clients send CMD_ECHO every 30 seconds, and timeout after 60 seconds.
     *
     * So this was a bug, with c++ server timeout racing with Java client echo.
     *
     * - As a compromise, continue to send echo at least every 15 seconds,
     *   and increase default timeout to 40.
     */
    if (!std::isfinite(tmo) || tmo <= 0.0 || tmo >= double(std::numeric_limits<time_t>::max()))
        tmo = 40.0;
    else if (tmo < 2.0)
        tmo = 2.0;
}

#ifdef PVXS_ENABLE_OPENSSL
void parseTLSOptions(ConfigCommon& conf, const std::string& options) {
    std::vector<std::string> opts;
    split_into(opts, options);

    for (auto opt : opts) {
        auto sep(opt.find_first_of('='));
        if ( sep == std::string::npos)
            sep = opt.size();
        auto key(opt.substr(0, sep));
        auto val(sep <= key.size() ? opt.substr(sep + 1) : std::string());

        if (key == "client_cert") {
            if (val == "require") {
                conf.tls_client_cert_required = ConfigCommon::Require;
            } else if (val == "optional") {
                conf.tls_client_cert_required = ConfigCommon::Optional;
            } else {
                log_warn_printf(config, "Ignore unknown TLS option `client_cert` value %s.  expected `require` or `optional`\n", opt.c_str());
            }
        } else if (key == "on_expiration") {
            if (val == "fallback-to-tcp") {
                conf.expiration_behaviour = ConfigCommon::FallbackToTCP;
            } else if (val == "shutdown") {
                conf.expiration_behaviour = ConfigCommon::Shutdown;
            } else if (val == "standby") {
                conf.expiration_behaviour = ConfigCommon::Standby;
            } else {
                log_warn_printf(config, "Ignore unknown TLS option `on_expiration` value %s.  expected `fallback-to-tcp`, `shutdown` or `standby`\n", opt.c_str());
            }
        } else if (key == "on_no_cms") {
            if (val == "fallback-to-tcp") {
                conf.tls_throw_if_cant_verify = false;
            } else if (val == "throw") {
                conf.tls_throw_if_cant_verify = true;
            } else {
                log_warn_printf(config, "Ignore unknown TLS option `on_no_cms` value %s.  expected `fallback-to-tcp` or `throw`\n", opt.c_str());
            }
        } else if (key == "no_revocation_check") {
            if ( val.empty())
                conf.tls_disable_status_check = true;
            else
                log_warn_printf(config, "Ignore unknown TLS option `no_revocation_check` value %s.  no value expected\n", opt.c_str());
        } else if (key == "no_stapling") {
            if ( val.empty())
                conf.tls_disable_stapling = true;
            else
                log_warn_printf(config, "Ignore unknown TLS option `no_stapling` value %s.  no value expected\n", opt.c_str());
        } else {
            log_warn_printf(config, "Ignore unknown TLS option key %s\n", opt.c_str());
        }
    }
}

std::string printTLSOptions(const ConfigCommon& conf) {
    std::vector<std::string> opts;
    switch (conf.tls_client_cert_required) {
        case ConfigCommon::Default:
            break;
        case ConfigCommon::Optional:
            opts.push_back("client_cert=optional");
            break;
        case ConfigCommon::Require:
            opts.push_back("client_cert=require");
            break;
    }
    switch (conf.expiration_behaviour) {
        case ConfigCommon::FallbackToTCP:
            opts.push_back("on_expiration=fallback-to-tcp");
            break;
        case ConfigCommon::Shutdown:
            opts.push_back("on_expiration=shutdown");
            break;
        case ConfigCommon::Standby:
            opts.push_back("on_expiration=standby");
            break;
    }
    if ( conf.tls_disable_status_check)
        opts.push_back("no_revocation_check");
    if ( conf.tls_disable_stapling)
        opts.push_back("no_stapling");
    if ( conf.tls_throw_if_cant_verify)
        opts.push_back("on_no_cms=throw");
    else
        opts.push_back("on_no_cms=fallback-to-tcp");
    return join_addr(opts);
}
#endif

}  // namespace

namespace server {

void Config::fromDefs(Config& self, const std::map<std::string, std::string>& defs, bool useenv) {
    PickOne pickone{defs, useenv};
    PickOne pick_another_one{defs, useenv};

    if (pickone({"EPICS_PVAS_SERVER_PORT", "EPICS_PVA_SERVER_PORT"})) {
        try {
            self.tcp_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVAS_BROADCAST_PORT", "EPICS_PVA_BROADCAST_PORT"})) {
        try {
            self.udp_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVAS_INTF_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.interfaces, pickone.val, nullptr, self.tcp_port, true);
    }

    if (pickone({"EPICS_PVAS_IGNORE_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.ignoreAddrs, pickone.val, nullptr, 0, true);
    }

    if (pickone({"EPICS_PVAS_BEACON_ADDR_LIST", "EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.beaconDestinations, pickone.val, nullptr, self.udp_port);
    }

    if (pickone({"EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "EPICS_PVA_AUTO_ADDR_LIST"})) {
        parse_bool(self.auto_beacon, pickone.name, pickone.val);
    }

    if (pickone({"EPICS_PVA_CONN_TMO"})) {
        parse_timeout(self.tcpTimeout, pickone.name, pickone.val);
    }

#ifdef PVXS_ENABLE_OPENSSL
    // EPICS_PVAS_TLS_KEYCHAIN
    if (pickone({"EPICS_PVAS_TLS_KEYCHAIN", "EPICS_PVA_TLS_KEYCHAIN"})) {
        self.ensureDirectoryExists(self.tls_keychain_file = pickone.val);
        // EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_PVAS_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pick_another_one.val;
        } else {
            pick_another_one({"EPICS_PVA_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pick_another_one.val;
        }
        self.ensureDirectoryExists(password_filename);
        try {
            self.tls_keychain_pwd = self.getFileContents(password_filename);
        } catch (std::exception& e) {
            log_err_printf(serversetup, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "server.p12";
        std::ifstream file(filename.c_str());
        if (file.good()) tls_keychain_file = filename;
    }

    // EPICS_PVAS_TLS_OPTIONS
    if (pickone({"EPICS_PVAS_TLS_OPTIONS", "EPICS_PVA_TLS_OPTIONS"})) {
        parseTLSOptions(self, pickone.val);
    }

    // EPICS_PVAS_TLS_PORT
    if (pickone({"EPICS_PVAS_TLS_PORT", "EPICS_PVA_TLS_PORT"})) {
        try {
            self.tls_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }

    // EPICS_PVAS_TLS_STOP_IF_NO_CERT
    if (pickone({"EPICS_PVAS_TLS_STOP_IF_NO_CERT"})) {
        self.tls_stop_if_no_cert = parseTo<bool>(pickone.val);
    }
#endif  // PVXS_ENABLE_OPENSSL
    is_initialized = true;
}
#ifndef PVXS_ENABLE_OPENSSL

Config& Config::applyEnv() {
#else
Config& Config::applyEnv(const bool tls_disabled, const ConfigTarget target) {
    this->tls_disabled = tls_disabled;
    this->config_target = target;
#endif
    fromDefs(*this, std::map<std::string, std::string>(), true);
    return *this;
}

/**
 * @brief Create a Config object with default values suitable for testing a Mock CMS
 *
 * @return Config for CMS
 */
Config Config::forCms() {
    Config ret;
    ret.config_target = pvxs::impl::ConfigCommon::CMS;
    ret.tls_disable_status_check = true;
    ret.tls_disable_stapling = true;

    ret.is_initialized = true;
    return ret;
}

/**
 * @brief Create a Config object with default values suitable for isolated testing
 *
 * @param family AF_INET or AF_INET6
 * @return Config
 */
Config Config::isolated(int family) {
    Config ret;

    ret.udp_port = 0u;
    ret.tcp_port = 0u;
    ret.auto_beacon = false;
    switch (family) {
        case AF_INET:
            ret.interfaces.emplace_back("127.0.0.1");
            ret.beaconDestinations.emplace_back("127.0.0.1");
            break;
        case AF_INET6:
            ret.interfaces.emplace_back("::1");
            ret.beaconDestinations.emplace_back("::1");
            break;
        default:
            throw std::logic_error(SB() << "Unsupported address family " << family);
    }
    // For testing purposes disable status checking and stapling when using isolated config
    ret.tls_disable_status_check = true;
    ret.tls_disable_stapling = true;

    ret.is_initialized = true;
    return ret;
}

Config& Config::applyDefs(const std::map<std::string, std::string>& defs) {
    fromDefs(*this, defs, false);
    return *this;
}

void Config::updateDefs(defs_t& defs) const {
    defs["EPICS_PVA_BROADCAST_PORT"] = defs["EPICS_PVAS_BROADCAST_PORT"] = SB() << udp_port;
    defs["EPICS_PVA_SERVER_PORT"] = defs["EPICS_PVAS_SERVER_PORT"] = SB() << tcp_port;
    defs["EPICS_PVA_AUTO_ADDR_LIST"] = defs["EPICS_PVAS_AUTO_BEACON_ADDR_LIST"] = auto_beacon ? "YES" : "NO";

    if (!beaconDestinations.empty()) defs["EPICS_PVA_ADDR_LIST"] = defs["EPICS_PVAS_BEACON_ADDR_LIST"] = join_addr(beaconDestinations);
    if (!interfaces.empty()) defs["EPICS_PVA_INTF_ADDR_LIST"] = defs["EPICS_PVAS_INTF_ADDR_LIST"] = join_addr(interfaces);
    if (!ignoreAddrs.empty()) defs["EPICS_PVAS_IGNORE_ADDR_LIST"] = join_addr(ignoreAddrs);
    defs["EPICS_PVA_CONN_TMO"] = SB() << tcpTimeout / tmoScale;

    defs["EPICS_XDG_DATA_HOME"] = data_home;
    defs["EPICS_XDG_CONFIG_HOME"] = config_home;

#ifdef PVXS_ENABLE_OPENSSL
    // EPICS_PVAS_TLS_KEYCHAIN
    if (!tls_keychain_file.empty()) defs["EPICS_PVAS_TLS_KEYCHAIN"] = tls_keychain_file;

    // EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE
    if (!tls_keychain_pwd.empty()) defs["EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"] = "<password read>";

    // EPICS_PVAS_TLS_OPTIONS
    defs["EPICS_PVAS_TLS_OPTIONS"] = printTLSOptions(*this);

    // EPICS_PVAS_TLS_PORT
    defs["EPICS_PVA_TLS_PORT"] = defs["EPICS_PVAS_TLS_PORT"] = SB() << tls_port;

    // EPICS_PVAS_TLS_STOP_IF_NO_CERT
    defs["EPICS_PVAS_TLS_STOP_IF_NO_CERT"] = tls_stop_if_no_cert ? "YES" : "NO";
#endif  // PVXS_ENABLE_OPENSSL
}

void Config::expand() {
    auto ifaces(parseAddresses(interfaces));
    auto bdest(parseAddresses(beaconDestinations));

    // empty interface address list implies the wildcard
    // (because no addresses isn't interesting...)
    if (ifaces.empty()) {
        ifaces.emplace_back(SockAddr::any(AF_INET));
    }

    auto& ifmap = IfaceMap::instance();

    for (size_t i = 0; i < ifaces.size(); i++) {
        auto& ep = ifaces[i];

        if (!ep.addr.isMCast()) {
            // no-op

        } else if (!ep.iface.empty()) {
            ifaces.emplace_back(ifmap.address_of(ep.iface));
        } else {
            ifaces.emplace_back(SockAddr::any(ep.addr.family()));
        }
        // ep invalidated by emplace()
    }

    if (auto_beacon) {
        // use interface list add ipv4 broadcast addresses to beaconDestinations.
        // 0.0.0.0 -> adds all bcasts
        // otherwise add bcast for each iface address
        expandAddrList(ifaces, bdest);
        addGroups(ifaces, bdest);
        auto_beacon = false;
    }

    removeDups(ifaces);
    printAddresses(interfaces, ifaces);
    removeDups(bdest);
    printAddresses(beaconDestinations, bdest);
    removeDups(ignoreAddrs);

    enforceTimeout(tcpTimeout);
}

#define MATCHING_DEF(D) (pair.first.size() >= sizeof(D##prefix) - 1u && strncmp(pair.first.c_str(), D##prefix, sizeof(D##prefix) - 1u) == 0)
std::ostream& operator<<(std::ostream& strm, const Config& conf) {
    Config::defs_t defs;
    conf.updateDefs(defs);

    for (const auto& pair : defs) {
        // only print the server variant
        static const char prefix[] = "EPICS_PVAS_";
        static const char ca_prefix[] = "EPICS_CA_";
        static const char pvacms_prefix[] = "EPICS_PVACMS_";
        static const char ocsp_prefix[] = "EPICS_OCSP_";
        static const char auth_prefix[] = "EPICS_AUTH_";

        if (MATCHING_DEF() || MATCHING_DEF(ca_) || MATCHING_DEF(pvacms_) || MATCHING_DEF(ocsp_) || MATCHING_DEF(auth_))
            strm << indent{} << pair.first << '=' << pair.second << '\n';
    }
    return strm;
}
#undef MATCHING_DEF
}  // namespace server

namespace client {

void Config::fromDefs(Config& self, const std::map<std::string, std::string>& defs, bool useenv) {
    PickOne pickone{defs, useenv};

    if (pickone({"EPICS_PVA_BROADCAST_PORT"})) {
        try {
            self.udp_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception& e) {
            log_warn_printf(clientsetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }
    if (self.udp_port == 0u) {
        log_warn_printf(clientsetup, "ignoring EPICS_PVA_BROADCAST_PORT=%d\n", 0);
        self.udp_port = 5076;
    }

    if (pickone({"EPICS_PVA_SERVER_PORT", "EPICS_PVAS_SERVER_PORT"})) {
        try {
            self.tcp_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception& e) {
            log_warn_printf(clientsetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }
    if (self.tcp_port == 0u && !self.nameServers.empty()) {
        log_warn_printf(clientsetup, "ignoring EPICS_PVA_SERVER_PORT=%d\n", 0);
        self.tcp_port = 5075;
    }

    if (pickone({"EPICS_PVA_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.addressList, pickone.val, nullptr, self.udp_port);
    }

    if (pickone({"EPICS_PVA_NAME_SERVERS"})) {
        split_addr_into(pickone.name.c_str(), self.nameServers, pickone.val, &self, 0);
    }

    if (pickone({"EPICS_PVA_AUTO_ADDR_LIST"})) {
        parse_bool(self.autoAddrList, pickone.name, pickone.val);
    }

    if (pickone({"EPICS_PVA_INTF_ADDR_LIST"})) {
        split_addr_into(pickone.name.c_str(), self.interfaces, pickone.val, nullptr, 0);
    }

    if (pickone({"EPICS_PVA_CONN_TMO"})) {
        parse_timeout(self.tcpTimeout, pickone.name, pickone.val);
    }

#ifdef PVXS_ENABLE_OPENSSL
    // EPICS_PVA_TLS_KEYCHAIN
    if (pickone({"EPICS_PVA_TLS_KEYCHAIN"})) {
        self.ensureDirectoryExists(self.tls_keychain_file = pickone.val);
    } else {
        std::string filename = SB() << config_home << OSI_PATH_SEPARATOR << "client.p12";
        std::ifstream file(filename.c_str());
        if (file.good()) tls_keychain_file = filename;
    }

    // EPICS_PVA_TLS_KEYCHAIN_PWD_FILE
    if (pickone({"EPICS_PVA_TLS_KEYCHAIN_PWD_FILE"})) {
        std::string password_filename(pickone.val);
        try {
            self.ensureDirectoryExists(password_filename);
            self.tls_keychain_pwd = self.getFileContents(password_filename);
        } catch (std::exception& e) {
            log_err_printf(serversetup, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    }

    // EPICS_PVA_TLS_OPTIONS
    if (pickone({"EPICS_PVA_TLS_OPTIONS"})) {
        parseTLSOptions(self, pickone.val);
    }

    // EPICS_PVA_TLS_PORT
    if (pickone({"EPICS_PVA_TLS_PORT"})) {
        try {
            self.tls_port = parseTo<uint64_t>(pickone.val);
        } catch (std::exception& e) {
            log_err_printf(serversetup, "%s invalid integer : %s", pickone.name.c_str(), e.what());
        }
    }

    // EPICS_PVA_TLS_SERVER_ONLY
    if (pickone({"EPICS_PVA_TLS_SERVER_ONLY"})) {
        self.tls_server_only = parseTo<bool>(pickone.val);
    }
#endif  // PVXS_ENABLE_OPENSSL
    is_initialized = true;
}

#ifndef PVXS_ENABLE_OPENSSL
Config& Config::applyEnv() {
#else
Config& Config::applyEnv(const bool tls_disabled, const ConfigTarget target) {
    this->tls_disabled = tls_disabled;
    this->config_target = target;
#endif
    fromDefs(*this, std::map<std::string, std::string>(), true);
    return *this;
}

#ifdef PVXS_ENABLE_OPENSSL
Config& Config::applyEnv(const bool tls_disabled) { return applyEnv(tls_disabled, CLIENT); }

#endif  // PVXS_ENABLE_OPENSSL

Config& Config::applyDefs(const std::map<std::string, std::string>& defs) {
    fromDefs(*this, defs, false);
    return *this;
}

void Config::updateDefs(defs_t& defs) const {
    defs["EPICS_PVA_BROADCAST_PORT"] = SB() << udp_port;
    defs["EPICS_PVA_SERVER_PORT"] = SB() << tcp_port;
    defs["EPICS_PVA_AUTO_ADDR_LIST"] = autoAddrList ? "YES" : "NO";
    if (!addressList.empty()) defs["EPICS_PVA_ADDR_LIST"] = join_addr(addressList);
    if (!interfaces.empty()) defs["EPICS_PVA_INTF_ADDR_LIST"] = join_addr(interfaces);
    defs["EPICS_PVA_CONN_TMO"] = SB() << tcpTimeout / tmoScale;
    if (!nameServers.empty()) defs["EPICS_PVA_NAME_SERVERS"] = join_addr(nameServers);

    defs["XDG_DATA_HOME"] = data_home;
    defs["XDG_CONFIG_HOME"] = config_home;

#ifdef PVXS_ENABLE_OPENSSL
    // EPICS_PVA_TLS_KEYCHAIN
    if (!tls_keychain_file.empty()) defs["EPICS_PVA_TLS_KEYCHAIN"] = tls_keychain_file;

    // EPICS_PVA_TLS_KEYCHAIN_PWD_FILE
    if (!tls_keychain_pwd.empty()) defs["EPICS_PVA_TLS_KEYCHAIN_PWD_FILE"] = "<password read>";

    // EPICS_PVA_TLS_OPTIONS
    defs["EPICS_PVA_TLS_OPTIONS"] = printTLSOptions(*this);

    // EPICS_PVA_TLS_PORT
    defs["EPICS_PVA_TLS_PORT"] = SB() << tls_port;

    defs["EPICS_PVA_TLS_SERVER_ONLY"] = tls_server_only ? "YES" : "NO";

#endif  // PVXS_ENABLE_OPENSSL
}

void Config::expand() {
    if (udp_port == 0) throw std::runtime_error("Client can't use UDP random port");

    if (tcp_port == 0) tcp_port = 5075;

    auto ifaces(parseAddresses(interfaces));
    auto addrs(parseAddresses(addressList));

    if (ifaces.empty()) ifaces.emplace_back(SockAddr::any(AF_INET));

    if (autoAddrList) {
        expandAddrList(ifaces, addrs);
        addGroups(ifaces, addrs);
        autoAddrList = false;
    }

    printAddresses(interfaces, ifaces);
    removeDups(addrs);
    printAddresses(addressList, addrs);

    enforceTimeout(tcpTimeout);
}

std::ostream& operator<<(std::ostream& strm, const Config& conf) {
    Config::defs_t defs;
    conf.updateDefs(defs);

    for (const auto& pair : defs) {
        strm << indent{} << pair.first << '=' << pair.second << '\n';
    }

    return strm;
}

}  // namespace client

}  // namespace pvxs
