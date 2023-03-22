/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUPSRCSUBSCRIPTIONCTX_H
#define PVXS_GROUPSRCSUBSCRIPTIONCTX_H

#include <map>
#include <vector>

#include <pvxs/source.h>

#include "dbeventcontextdeleter.h"
#include "fieldsubscriptionctx.h"
#include "group.h"
#include "subscriptionctx.h"

namespace pvxs {
namespace ioc {

class GroupSourceSubscriptionCtx {
public:
    Group& group;
    epicsMutex eventLock{};
    bool eventsPrimed = false, firstEvent = true;
    std::unique_ptr<server::MonitorControlOp> subscriptionControl{};

    // This is as a special case for storing the initial value prior to both initial subscription events returning
    // This is so that we can merge this with the subsequent values that come in before all initial events are in
    Value currentValue;

    std::vector<FieldSubscriptionCtx> fieldSubscriptionContexts{};
    explicit GroupSourceSubscriptionCtx(Group& subscribedGroup)
            :group(subscribedGroup), currentValue(subscribedGroup.valueTemplate.cloneEmpty()) {
    }

};

} // pvxs
} // ioc

#endif //PVXS_GROUPSRCSUBSCRIPTIONCTX_H
