/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_SUBSCRIPTIONCTX_H
#define PVXS_SUBSCRIPTIONCTX_H

#include <memory>

/**
 * Add a subscription event by calling db_add_event using the given subscriptionCtx
 * and selecting the correct elements based on the given type of event being added.
 * You need to specify the correct options that correspond to the event type.
 * Adds a deleter to clean up the subscription by calling db_cancel_event.
 *
 * @param _type the type of event being added.  `Value` or `Properties`
 * @param _eventContext the name of the dbEventCtx to use to add events
 * @param _subscriptionContext - The subscriptionCtx to use
 * @param _options the options. DBE_VALUE, DBE_ALARM, or DBE_PROPERTY or some combination
 */
#define addSubscriptionEvent(_type, _eventContext, _subscriptionContext, _options) \
    _subscriptionContext->p ## _type ## EventSubscription                          \
    .reset(db_add_event((_eventContext) .get(),                                    \
        (_subscriptionContext) ->p ## _type ## Channel.get(),                      \
        subscription ## _type ## Callback,                                         \
        (void*) (_subscriptionContext).get(),                                      \
        _options                                                                   \
    ),                                                                             \
    [](dbEventSubscription pEventSubscription) {                                   \
        if (pEventSubscription) {                                                  \
            db_cancel_event(pEventSubscription);                                   \
        }                                                                          \
    })

namespace pvxs {
namespace ioc {

/**
 * A subscription context
 */
class SubscriptionCtx {
public:
// For locking access to subscription context
    std::shared_ptr<void> pValueEventSubscription{};
    std::shared_ptr<void> pPropertiesEventSubscription{};
    bool hadValueEvent = false;
    bool hadPropertyEvent = false;
};

} // ioc
} // pvxs

#endif //PVXS_SUBSCRIPTIONCTX_H
