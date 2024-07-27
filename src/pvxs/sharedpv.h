/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SHAREDPV_H
#define PVXS_SHAREDPV_H

#include <functional>
#include <list>
#include <memory>
#include <map>
#include <string>

#include <pvxs/version.h>
#include "srvcommon.h"

namespace pvxs {
class Value;

namespace server {

struct ChannelControl;
struct Source;

/** A SharedPV is a single data value which may be accessed by multiple clients through a Server.
 *
 * On creation a SharedPV has no associated data structure, or data type.
 * This is set by calling open() to provide a data type, and initial data values.
 * Subsequent calls to post() will update this data structure (and send notifications
 * to subscribing clients).
 *
 * A later call to close() will force disconnect all clients, and discard the data value and type.
 * A further call to open() sets a new data value, which may be of a different data type.
 *
 * The onPut() and onRPC() methods attach functors which will be called each time a Put or RPC
 * operation is executed by a client.
 */
struct PVXS_API SharedPV {
    //! Create a new SharedPV with a Put handler which post() s any client provided Value.
    static SharedPV buildMailbox();

    //! Create a new SharedPV with a Put handler which rejects any client provided Value.
    static SharedPV buildReadonly();

    ~SharedPV();

    inline explicit operator bool() const { return !!impl; }

    //! Attach this SharedPV with a new client channel.
    //! Not necessary when using StaticSource.
    //! eg. could call from Source::onCreate()
    void attach(std::unique_ptr<ChannelControl>&& op);

    //! Callback when the number of attach()d clients becomes non-zero.
    void onFirstConnect(std::function<void(SharedPV&)>&& fn);
    //! Callback when the number of attach()d clients becomes non-zero for wildcard PVs.
    void onFirstWildcardConnect(std::function<void(SharedPV &, std::shared_ptr<std::list<std::string>>)> &&fn);
    //! Callback when the number of attach()d clients becomes zero.
    void onLastDisconnect(std::function<void(SharedPV&)>&& fn);
    //! Callback when a client executes a new Put operation.
    void onPut(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);
    //! Callback when a client executes an RPC operation.
    //! @note RPC operations are allowed even when the SharedPV is not opened (isOpen()==false)
    void onRPC(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);
    //! Callback when a client executes an RPC operation for wildcard PVs.
    void onWildcardRPC(std::function<void(SharedPV&, std::shared_ptr<std::list<std::string>>, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);

    /** Provide data type and initial value.  Allows clients to begin connecting.
     * @pre !isOpen()
     * @param initial Defines data type, and initial value
     */
    void open(const Value& initial);
    //! Test whether open() has been called w/o matching close()
    bool isOpen() const;
    //! Reverse the effects of open() and force disconnect any remaining clients.
    void close();

    //! Update the internal data value, and dispatch subscription updates to any clients.
    void post(const Value& val);
    //! query the internal data value and update the provided Value.
    void fetch(Value& val) const;
    //! Return a (shallow) copy of the internal data value
    Value fetch() const;

    struct Impl;
    std::map<std::string, std::shared_ptr<std::list<std::string>>> wildcard_parameters_map;
    inline void set_wildcard_parameters(const std::string& pv_name,
                                        const std::string& format) noexcept {
        auto& wildcard_parameters = wildcard_parameters_map[pv_name];
        if (!wildcard_parameters) {
            wildcard_parameters = std::make_shared<std::list<std::string>>();
        } else if (!wildcard_parameters->empty()) {
            return;
        }

        size_t name_pos = 0;
        size_t format_pos = 0;

        while (format_pos < format.length() && name_pos < pv_name.length()) {
            if (format[format_pos] == '?') {
                // Extract the sequence of '?' matched characters
                size_t start = name_pos;
                while (format_pos < format.length() && format[format_pos] == '?') {
                    format_pos++;
                    name_pos++;
                }
                wildcard_parameters->push_back(pv_name.substr(start, name_pos - start));
            } else if (format[format_pos] == '*') {
                // Extract the sequence of '*' matched characters
                size_t start = name_pos;
                format_pos++;
                if (format_pos < format.length()) {
                    // There are more characters in format after '*', find the next part
                    char next_char = format[format_pos];
                    name_pos = pv_name.find(next_char, name_pos);
                    if (name_pos != std::string::npos) {
                        wildcard_parameters->push_back(pv_name.substr(start, name_pos - start));
                    } else {
                        // This condition should not happen in a valid input where the non '*' and '?' match correctly
                        wildcard_parameters->push_back(pv_name.substr(start));
                        return;
                    }
                } else {
                    // '*' is the last character in format, extract till the end of pv_name
                    wildcard_parameters->push_back(pv_name.substr(start));
                    return;
                }
            } else {
                // Skip the non '?' and '*' characters in the format
                format_pos++;
                name_pos++;
            }
        }
    }

  private:
    std::shared_ptr<Impl> impl;
};

/** Allow clients to find (through a Server) SharedPV instances by name.
 *
 * A single PV name may only be added once to a StaticSource.
 * However, a single SharedPV may be added multiple times with different PV names.
 */
struct PVXS_API StaticSource
{
    static StaticSource build();

    ~StaticSource();

    inline explicit operator bool() const { return !!impl; }

    //! Fetch the Source interface, which may be used with Server::addSource()
    std::shared_ptr<Source> source() const;

    //! call SharedPV::close() on all PVs
    void close();

    //! Add a new name through which a SharedPV may be addressed.
    StaticSource& add(const std::string& name, const SharedPV& pv);
    //! Remove a single name
    StaticSource& remove(const std::string& name);

    typedef std::map<std::string, SharedPV> list_t;
    list_t list() const;

    struct Impl;
private:
    std::shared_ptr<Impl> impl;
};

} // namespace server
} // namespace pvxs

#endif // PVXS_SHAREDPV_H
