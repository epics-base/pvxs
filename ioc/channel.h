
/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_CHANNEL_H
#define PVXS_CHANNEL_H

#include <string>
#include <memory>

#include <dbChannel.h>

namespace pvxs {
namespace ioc {

/**
 * This class encapsulates a shared pointer to a dbChannel but provides constructors
 * from string and dbChannel to make its use simpler.  It can be used wherever a dbChannel is used.
 * As a bonus when constructed with parameters it provides an already open dbChannel.
 */
class Channel : public std::shared_ptr<dbChannel> {
public:
    Channel() = default;
    Channel(const Channel&) = default;
    Channel(Channel&&) = default;
    // This constructor calls dbChannelOpen()
    explicit Channel(const char* name);
    inline
    explicit Channel(const std::string& name)
        :Channel(name.c_str())
    {}

    Channel& operator=(const Channel&) = default;
    Channel& operator=(Channel&&) = default;

    operator dbChannel*() const {
        return get();
    }
};

} // pvxs
} // ioc

#endif //PVXS_CHANNEL_H
