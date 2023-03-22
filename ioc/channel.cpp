/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>

#include "channel.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {
/**
 * Construct a group channel from a given db channel name
 *
 * @param name the db channel name
 */
Channel::Channel(const std::string& name)
        :pDbChannel(std::shared_ptr<dbChannel>(dbChannelCreate(name.c_str()),
        [](dbChannel* ch) {
            if (ch) {
                dbChannelDelete(ch);
            }
        })) {
    if (pDbChannel) {
        prepare();
    }
}

/**
 * Internal function to prepare the dbChannel for operation by opening it
 */
void Channel::prepare() {
    if (!pDbChannel) {
        throw std::invalid_argument(SB() << "NULL channel while opening group channel");
    }
    if (dbChannelOpen(pDbChannel.get())) {
        throw std::invalid_argument(SB() << "Failed to open group channel " << dbChannelName(pDbChannel));
    }
}


} // pvxs
} // ioc
