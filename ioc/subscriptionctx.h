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
#include <stdexcept>
#include <type_traits>

#include <dbEvent.h>

#include "channel.h"
#include "dbeventcontextdeleter.h"

namespace pvxs {
namespace ioc {

class Subscription {
    std::shared_ptr<std::remove_pointer<dbEventSubscription>::type> sub; // holds void* returned by db_add_event()
public:
    unsigned mask=0;
    /* Add a subscription event by calling db_add_event using the given subscriptionCtx
     * and selecting the correct elements based on the given type of event being added.
     * You need to specify the correct options that correspond to the event type.
     * Adds a deleter to clean up the subscription by calling db_cancel_event.
     */
    void subscribe(dbEventCtx context,
                   const Channel& pChan,
                   EVENTFUNC *user_sub, void *user_arg, unsigned select)
    {
        auto chan(pChan); // bind by value
        sub.reset(db_add_event(context, chan,
                               user_sub, user_arg, select),
                  [chan](dbEventSubscription sub) mutable
        {
            if(sub)
                db_cancel_event(sub);
            chan = Channel(); // dbChannel* must outlive subscription
        });
        if(!sub)
            throw std::runtime_error("Failed to create db subscription");
        mask = select;
    }
    void cancel() {
        sub.reset();
    }
    void enable() {
        if(sub) {
            db_event_enable(sub.get());
            db_post_single_event(sub.get());
        }
    }
    void disable() {
        if(sub)
            db_event_disable(sub.get());
    }
};

/**
 * A subscription context
 */
class SubscriptionCtx {
public:
// For locking access to subscription context
    Subscription pValueEventSubscription;
    Subscription pPropertiesEventSubscription;
    bool hadValueEvent = false;
    bool hadPropertyEvent = false;
    void cancel() {
        pValueEventSubscription.cancel();
        pPropertiesEventSubscription.cancel();
    }
};

} // ioc
} // pvxs

#endif //PVXS_SUBSCRIPTIONCTX_H
