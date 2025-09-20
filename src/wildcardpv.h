/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_WILDCARDPV_H
#define PVXS_WILDCARDPV_H

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <string>

#include <pvxs/srvcommon.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/version.h>

#include "utilpvt.h"

namespace pvxs {
class Value;
namespace server {
struct ChannelControl;
struct Source;
}

namespace server {

struct PVXS_API WildcardPV {
    //! Create a new SharedPV with a Put handler which post() s any client-provided Value.
    static WildcardPV buildMailbox();

    //! Create a new WildcardPV with a Put handler which rejects any client-provided Value.
    static WildcardPV buildReadonly();

    ~WildcardPV();

    //! Attach this SharedPV with a new client channel.
    //! Not necessary when using StaticSource.
    //! eg. could call from Source::onCreate()
    void attach(std::unique_ptr<ChannelControl> &&op, const std::list<std::string> parameters);

    //! Callback when the number of attach()d clients becomes non-zero for a particular pv_name
    void onFirstConnect(std::function<void(WildcardPV &, const std::string &, const std::list<std::string> &)> &&fn);
    //! Callback when the number of attach()d clients becomes zero for a particular pv_name
    void onLastDisconnect(std::function<void(WildcardPV &, const std::string &, const std::list<std::string> &)> &&fn);
    //! Callback when a client executes a new Put operation for a given pv_name
    void onPut(std::function<void(WildcardPV &, std::unique_ptr<ExecOp> &&, const std::string &, const std::list<std::string> &, Value &&)> &&fn);
    //! Callback when a client executes an RPC operation for a given pc_name
    //! @note RPC operations are allowed even when the SharedPV is not opened (isOpen()==false)
    void onRPC(std::function<void(WildcardPV &, std::unique_ptr<ExecOp> &&, const std::string &, const std::list<std::string> &, Value &&)> &&fn);

    /** Provide data type and initial value.  Allows clients to begin connecting.
     * @pre !isOpen()
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     * @param initial Defines data type, and initial value
     */
    void open(const std::string &pv_name, const Value &initial);
    /**
     * @brief Test whether open(pv_name) has been called w/o matching close(pv_name)
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     * @return true if open
     */
    bool isOpen(const std::string &pv_name) const;
    /**
     * @brief Reverse the effects of open(pv_name) and force disconnect any remaining clients.
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     */
    void close(const std::string &pv_name);

    void close();

    /**
     * @brief Update the internal data value, and dispatch subscription updates to any clients.
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     * @param val the value to post
     */
    void post(const std::string &pv_name, const Value &val);
    /**
     * @brief query the internal data value and update the provided Value.
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     * @param val reference to value to update by fetching
     */
    void fetch(const std::string &pv_name, Value &val) const;
    /**
     * @brief Return a (shallow) copy of the internal data value
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     * @return shallow copy of the internal data value
     */
    Value fetch(const std::string &pv_name) const;

    /**
     * @brief The Wildcard PV name, only set when wildcard match is called
     */
    std::string wildcard_pv;
    /**
     * @brief Get the parameters from the given wildcard PV name.
     * Will provide strings for each of the parts of the PV name matched by
     * patterns in the wildcard PV name.  e.g. strings of `???` or `*` will
     * resolve to strings in the returned vector.
     *
     * @param pv_name For wildcard PVs this indicates the actual PV requested
     * @return a list of strings that correspond to the parts of the PV name matched by pattern in the Wildcard PV.
     */
    std::list<std::string> getParameters(const std::string &pv_name) noexcept ;

    struct Impl;

  private:
    std::shared_ptr<Impl> impl;

    template <typename T>
    bool exists(const std::map<std::string, T> &m, const std::string &ref) const;
};

/** Allow clients to find (through a Server) WildcardPV instances by name.
 *
 * A single wildcard PV name may only be added once to a WildcardSource.
 * However, a single SharedPV may be added multiple times with different PV names.
 */
struct PVXS_API WildcardSource final : Source, std::enable_shared_from_this<WildcardSource>
{
    // Factory: return a shared_ptr so callers can pass it directly to addSource()
    static std::shared_ptr<WildcardSource> build();

    ~WildcardSource() override = default;

    // Management API
    void close();
    WildcardSource& add(const std::string& name, const WildcardPV& pv);
    WildcardSource& remove(const std::string& name);

    typedef std::map<std::string, std::shared_ptr<WildcardPV>> pv_list_t;
    typedef std::map<std::string, WildcardPV> list_t;
    list_t list() const;

    // server::Source overrides
    void onSearch(Search& op) override;
    void onCreate(std::unique_ptr<ChannelControl>&& op) override;
    List onList() override;
    void show(std::ostream& strm) override;

  private:
    mutable RWLock lock;
    pv_list_t pvs;

    bool wildcardMatch(const std::string& searched_name, WildcardPV& pv);

    const std::regex kRegexSpecialChars{R"([-[\]{}()+.,\^$|#\s])"};
    const std::regex kWildcardStarPattern{"\\*"};
    const char kWildcardQueryCharacter = '?';
};


}  // namespace serverx
}  // namespace pvxs

#endif  // PVXS_WILDCARDPV_H
