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

#include <dbChannel.h>

#include "subscriptionctx.h"

namespace pvxs {
namespace ioc {

/**
 * A subscription context
 */
class SingleSourceSubscriptionCtx : public SubscriptionCtx {

public:
    explicit SingleSourceSubscriptionCtx(const std::shared_ptr<dbChannel>& dbChannelSharedPtr);
// For locking access to subscription context
    std::shared_ptr<dbChannel> pValueChannel;
    std::shared_ptr<dbChannel> pPropertiesChannel;

    // This is used to store the current value.  Each subscription event simply merges
    // new fields into this value
    Value currentValue{};
    epicsMutex eventLock{};
    std::unique_ptr<server::MonitorControlOp> subscriptionControl{};
};

} // ioc
} // pvxs

#endif //PVXS_SINGLESRCSUBSCRIPTIONCTX_H
