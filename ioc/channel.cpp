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
Channel::Channel(const char* name)
        :std::shared_ptr<dbChannel>(std::shared_ptr<dbChannel>(dbChannelCreate(name),
        [](dbChannel* ch) {
            if (ch) {
                dbChannelDelete(ch);
            }
        }))
{
    if(!*this)
        throw std::runtime_error(SB()<<"Invalid PV: "<<name);
    if (dbChannelOpen(get()))
        throw std::invalid_argument(SB() << "Failed dbChannelOpen(\"" << dbChannelName(get()) <<"\")");
}

} // pvxs
} // ioc
