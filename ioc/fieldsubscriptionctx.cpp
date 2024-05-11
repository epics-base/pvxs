/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include "fieldsubscriptionctx.h"

namespace pvxs {
namespace ioc {

/**
 * Called when a client wishes to subscribe to a group.  The onSubscribe method calls this method for each
 * field within the group.  This method will create a new event subscription and attach it to this field
 * subscription context.
 *
 * @param pEventCtx the global event context which references the db event propagation framework
 * @param subscriptionCallback reference to a callback function to be called when the field is updated.
 * @param selectOptions the selection options to determine events to be monitored. DBE_VALUE | DBE_ALARM | DBE_PROPERTY
 * @param forValues true if this should monitor value changes, false for property changes.
 */
void FieldSubscriptionCtx::subscribeField(dbEventCtx pEventCtx, EVENTFUNC (* subscriptionCallback),
        unsigned int selectOptions, bool forValues) {
    auto& pDbChannel = (forValues ? field->value : field->properties);
    auto& pEventSubscription = forValues ? pValueEventSubscription : pPropertiesEventSubscription;
    pEventSubscription.subscribe(pEventCtx, pDbChannel,
                                 subscriptionCallback,
                                 this, selectOptions);
}

} // pvcs
} // ioc
