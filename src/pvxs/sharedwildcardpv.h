/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SHAREDWILDCARDPV_H
#define PVXS_SHAREDWILDCARDPV_H

#include <functional>
#include <list>
#include <memory>
#include <map>
#include <string>

#include <pvxs/sharedpv.h>
#include <pvxs/version.h>
#include "srvcommon.h"

namespace pvxs {
class Value;

namespace server {

struct ChannelControl;
struct Source;

/** A SharedWildcardPV is multiple data values which may be accessed by multiple clients through a Server.
 *
 * On creation a SharedWildcardPV has no associated data structure, or data type.
 * This is set by calling open(pvname) to provide a data type, and initial data values.
 * Subsequent calls to post(pvname) will update this data structure (and send notifications
 * to subscribing clients).
 *
 * A later call to close(pvname) will force disconnect all clients, and discard the data value and type.
 * A further call to open(pvname) sets a new data value, which may be of a different data type.
 *
 * The onPut(pvname) and onRPC(pvname) methods attach functors which will be called each time a Put or RPC
 * operation is executed by a client.
 *
 * Servers provide implementations for onFirstConnect() and onFirstDisconnect() as well as onRPC() which
 * provide `pvname` and `parameters` as arguments to be used for processing and to call
 * the open(pvname), close(pvname), onRPC(pvname), post(pvname) lower level functions.
 *
 * Serves can optionally provide the onPut() handler again with pvname and parameters arguments
 * and can call low level post(pvname)
 *
 * monitoring and get are handled automatically by the framework
 */
struct PVXS_API SharedWildcardPV : public SharedPV {
    //! Create a new SharedPV with a Put handler which post() s any client provided Value.
    static SharedWildcardPV buildMailbox();

    //! Create a new SharedWildcardPV with a Put handler which rejects any client provided Value.
    static SharedWildcardPV buildReadonly();

    ~SharedWildcardPV();

    //! Attach this SharedPV with a new client channel.
    //! Not necessary when using StaticSource.
    //! eg. could call from Source::onCreate()
    void attach(std::unique_ptr<ChannelControl>&& op, const std::list<std::string> parameters);

    //! Callback when the number of attach()d clients becomes non-zero for a particular pv_name
    void onFirstConnect(std::function<void(SharedWildcardPV&, const std::string &, const std::list<std::string> &)>&& fn);
    //! Callback when the number of attach()d clients becomes zero for a particular pv_name
    void onLastDisconnect(std::function<void(SharedWildcardPV&, const std::string &, const std::list<std::string> &)>&& fn);
    //! Callback when a client executes a new Put operation for a given pv_name
    void onPut(std::function<void(SharedWildcardPV&, std::unique_ptr<ExecOp>&&, const std::string &, const std::list<std::string> &, Value&&)>&& fn);
    //! Callback when a client executes an RPC operation for a given pc_name
    //! @note RPC operations are allowed even when the SharedPV is not opened (isOpen()==false)
    void onRPC(std::function<void(SharedWildcardPV&, std::unique_ptr<ExecOp>&&, const std::string &, const std::list<std::string> &, Value&&)>&& fn);

    /** Provide data type and initial value.  Allows clients to begin connecting.
     * @pre !isOpen()
     * @param initial Defines data type, and initial value
     */
    void open(const std::string &pv_name, const Value& initial);
    //! Test whether open(pv_name) has been called w/o matching close(pv_name)
    bool isOpen(const std::string &pv_name) const;
    //! Reverse the effects of open(pv_name) and force disconnect any remaining clients.
    void close(const std::string &pv_name);

    //! Update the internal data value, and dispatch subscription updates to any clients.
    void post(const std::string &pv_name, const Value& val);
    //! query the internal data value and update the provided Value.
    void fetch(const std::string &pv_name, Value& val) const;
    //! Return a (shallow) copy of the internal data value
    Value fetch(const std::string &pv_name) const;

    struct Impl;
    //! The Wildcard PV name, only set when wildcard match is called
    std::string wildcard_pv;
    inline const std::list<std::string> getParameters(const std::string& pv_name) noexcept {
        std::list<std::string> parameters;
        size_t pv_name_pos = 0;
        size_t wildcard_pv_pos = 0;

        while (wildcard_pv_pos < wildcard_pv.length() && pv_name_pos < pv_name.length()) {
            if (wildcard_pv[wildcard_pv_pos] == '?') {
                // Extract the sequence of '?' matched characters
                size_t start = pv_name_pos;
                while (wildcard_pv_pos < wildcard_pv.length() && wildcard_pv[wildcard_pv_pos] == '?') {
                    wildcard_pv_pos++;
                    pv_name_pos++;
                }
                parameters.push_back(pv_name.substr(start, pv_name_pos - start));
            } else if (wildcard_pv[wildcard_pv_pos] == '*') {
                // Extract the sequence of '*' matched characters
                size_t start = pv_name_pos;
                wildcard_pv_pos++;
                if (wildcard_pv_pos < wildcard_pv.length()) {
                    // There are more characters in format after '*', find the next part
                    char next_char = wildcard_pv[wildcard_pv_pos];
                    pv_name_pos = pv_name.find(next_char, pv_name_pos);
                    if (pv_name_pos != std::string::npos) {
                        parameters.push_back(pv_name.substr(start, pv_name_pos - start));
                    } else {
                        // This condition should not happen in a valid input where the non '*' and '?' match correctly
                        parameters.push_back(pv_name.substr(start));
                        return parameters;
                    }
                } else {
                    // '*' is the last character in format, extract till the end of pv_name
                    parameters.push_back(pv_name.substr(start));
                    return parameters;
                }
            } else {
                // Skip the non '?' and '*' characters in the format
                wildcard_pv_pos++;
                pv_name_pos++;
            }
        }
        return parameters;
    }
  private:
    std::shared_ptr<Impl> impl;

    template <typename T>
    bool exists(const std::map<std::string, T>&m , const std::string &ref) const;
};

} // namespace server
} // namespace pvxs

#endif // PVXS_SHAREDWILDCARDPV_H
