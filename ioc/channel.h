
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
class Channel {
private:
    std::shared_ptr<dbChannel> pDbChannel;
    void prepare();

public:
    // This constructor calls dbChannelOpen()
    explicit Channel(const std::string& name);

/**
 * Destructor is default because pDbChannel cleans up after itself.
 */
    ~Channel() = default;

    /**
 * Cast as a shared pointer to a dbChannel.  This returns the pDbChannel member
 *
 * @return the pDbChannel member
 */
    operator dbChannel*() const {
        return pDbChannel.get();
    }
/**
 * Const pointer indirection operator
 * @return pointer to the dbChannel associated with this group channel
 */
    const dbChannel* operator->() const {
        return pDbChannel.get();
    }

    explicit operator bool() const {
        return pDbChannel.operator bool();
    }

/**
 * Move constructor
 *
 * @param other other Channel
 */
    Channel(Channel&& other) noexcept
            :pDbChannel(std::move(other.pDbChannel)) {
    }

/**
 * Move assignment operator
 *
 * @param other the other channel
 * @return the moved channel
 */
    Channel& operator=(Channel&& other) noexcept {
        pDbChannel = std::move(other.pDbChannel);
        other.pDbChannel = nullptr;
        return *this;
    }

    // Disallowed methods.  Copy and move constructors
    Channel(const Channel&) = delete;
    const std::shared_ptr<dbChannel>& shared_ptr() const {
        return pDbChannel;
    };
};

} // pvxs
} // ioc

#endif //PVXS_CHANNEL_H
