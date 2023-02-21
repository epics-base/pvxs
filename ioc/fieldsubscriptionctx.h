/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */


#ifndef PVXS_FIELDSUBSCRIPTIONCTX_H
#define PVXS_FIELDSUBSCRIPTIONCTX_H

#include <map>

#include <pvxs/source.h>

#include "dbeventcontextdeleter.h"
#include "group.h"
#include "subscriptionctx.h"

namespace pvxs {
namespace ioc {

class GroupSourceSubscriptionCtx;

/**
 * Field subscription context.  This object is the user object that is supplied when one of a group subscription's
 * fields are updated, and their subscription event is triggered.
 *
 * It contains a pointer to the group subscription of which it forms a part, as well as the field it is monitoring.
 */
class FieldSubscriptionCtx : public SubscriptionCtx {
public:
    GroupSourceSubscriptionCtx* const pGroupCtx;
    Field* const field;

    // Map channel to field index in group.fields
    void subscribeField(dbEventCtx pEventCtx, EVENTFUNC (* subscriptionCallback),
            unsigned int selectOptions, bool forValues = true);

/**
 * Constructor for a field subscription context takes a field and a group subscription context
 *
 * @param field the field this subscription context will be used to monitor
 * @param groupSourceSubscriptionCtx the group subscription context this is a part of
 */
    explicit FieldSubscriptionCtx(Field& field, GroupSourceSubscriptionCtx* groupSourceSubscriptionCtx)
            :pGroupCtx(groupSourceSubscriptionCtx), field(&field)
    {
        if(!field.value) {
            // no associated dbChannel, so nothing to wait for
            hadValueEvent = hadPropertyEvent = true;
        }
    };

    FieldSubscriptionCtx(FieldSubscriptionCtx&&) = default;
};

} // pvcs
} // ioc

#endif //PVXS_FIELDSUBSCRIPTIONCTX_H
