/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_SINGLESOURCE_H
#define PVXS_SINGLESOURCE_H

#include <dbNotify.h>
#include <dbEvent.h>

#include "dbeventcontextdeleter.h"
#include "iocsource.h"
#include "singlesrcsubscriptionctx.h"

namespace pvxs {
namespace ioc {

/**
 * Single Source class to handle initialisation, processing, and shutdown of single source database record support
 *  - Handlers for get, put and subscriptions
 *  - type converters to and from pvxs and db
 */
class SingleSource : public server::Source {
public:
    SingleSource();
    void onCreate(std::unique_ptr<server::ChannelControl>&& channelControl) final;
    List onList() final {
        return allRecords;
    }

    void onSearch(Search& searchOperation) final;
    void show(std::ostream& outputStream) final;

private:
    // List of all database records that this single source serves
    List allRecords;
    // The event context for all subscriptions
    DBEventContext eventContext;
};

} // ioc
} // pvxs


#endif //PVXS_SINGLESOURCE_H
