/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_SINGLESRCSUBSCRIPTIONCTX_H
#define PVXS_SINGLESRCSUBSCRIPTIONCTX_H

#include <pvxs/source.h>

#include "channel.h"
#include "fieldconfig.h"
#include "subscriptionctx.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {

struct SingleInfo : public MappingInfo {
    Channel chan;
    INST_COUNTER(SingleInfo);

    explicit SingleInfo(Channel&& chan) :chan(std::move(chan)) {
        updateNsecMask(dbChannelRecord(this->chan));
    }
};

/**
 * A subscription context
 */
class SingleSourceSubscriptionCtx : public SubscriptionCtx {

public:
    explicit SingleSourceSubscriptionCtx(const std::shared_ptr<SingleInfo>& sInfo);

    // extra dbChannel* to have a distinct state for any server side filters.  (eg. decimate)
    const Channel pPropertiesChannel;

    // This is used to store the current value.  Each subscription event simply merges
    // new fields into this value
    Value currentValue{};
    std::shared_ptr<SingleInfo> info;
    epicsMutex eventLock{};
    std::unique_ptr<server::MonitorControlOp> subscriptionControl{};
    bool eventsEnabled = false;
    INST_COUNTER(SingleSourceSubscriptionCtx);

    ~SingleSourceSubscriptionCtx() {
        assert(!eventsEnabled);
        // must db_cancel_event() before ~MonitorControlOp
        cancel();
    }
};

} // ioc
} // pvxs

#endif //PVXS_SINGLESRCSUBSCRIPTIONCTX_H
