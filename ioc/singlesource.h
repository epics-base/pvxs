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
#include "metadata.h"
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

	// Create request and subscription handlers for single record sources
	void createRequestAndSubscriptionHandlers(std::unique_ptr<server::ChannelControl>&& channelControl,
			const std::shared_ptr<dbChannel>& dbChannelSharedPtr);
	// Handles all get, put and subscribe requests
	static void onOp(const std::shared_ptr<dbChannel>& forceProcessingOption, const Value& valuePrototype,
			std::unique_ptr<server::ConnectOp>&& channelConnectOperation);
	// Helper function to create a value prototype for the given channel
	static Value getValuePrototype(const std::shared_ptr<dbChannel>& dbChannelSharedPtr);

    //////////////////////////////
    // Get
    //////////////////////////////
    // Handle the get operation
    static void get(dbChannel* pDbChannel, std::unique_ptr<server::ExecOp>& getOperation,
            const Value& valuePrototype);

    //////////////////////////////
    // Subscriptions
    //////////////////////////////
/**
 * This callback handles notifying of updates to subscribed-to pv values.  The macro addSubscriptionEvent(...)
 * creates the call to this function, so your IDE may mark it as unused (don't believe it :) )
 *
 * @param userArg the user argument passed to the callback function from the framework: the subscriptionContext
 * @param pDbFieldLog the database field log containing the changes to notify
 */
    static void subscriptionValueCallback(void* userArg, struct dbChannel*, int, struct db_field_log* pDbFieldLog) {
        auto subscriptionContext = (SingleSourceSubscriptionCtx*)userArg;
        subscriptionContext->hadValueEvent = true;
        subscriptionCallback(subscriptionContext, FOR_VALUE, pDbFieldLog);
    }

/**
 * This callback handles notifying of updates to subscribed-to pv properties.  The macro addSubscriptionEvent(...)
 * creates the call to this function, so your IDE may mark it as unused (don't believe it :) )
 *
 * @param userArg the user argument passed to the callback function from the framework: the subscriptionContext
 * @param pDbFieldLog the database field log containing the changes to notify
 */
    static void subscriptionPropertiesCallback(void* userArg, struct dbChannel*, int,
            struct db_field_log* pDbFieldLog) {
        auto subscriptionContext = (SingleSourceSubscriptionCtx*)userArg;
        subscriptionContext->hadPropertyEvent = true;
        subscriptionCallback(subscriptionContext, FOR_PROPERTIES, pDbFieldLog);
    }

    // General subscriptions callback
    static void
    subscriptionCallback(SingleSourceSubscriptionCtx* subscriptionCtx, GetOperationType getOperationType,
            struct db_field_log* pDbFieldLog);
/**
 * Called when a client pauses / stops a subscription it has been subscribed to
 *
 * @param subscriptionContext the subscription context
 */
    static void onDisableSubscription(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext) {
        db_event_disable(subscriptionContext->pValueEventSubscription.get());
        db_event_disable(subscriptionContext->pPropertiesEventSubscription.get());
    }

    // Called by onStart() when a client starts a subscription it has subscribed to
    static void onStartSubscription(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext);
    // Called when a subscription is being set up
    void onSubscribe(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext,
            std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) const;
    // Called when a client starts or stops a subscription. isStarting flag determines which
    static void onStart(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext, bool isStarting);

    static int putCallback(processNotify* notify, notifyPutType type);
	static void doneCallback(processNotify* notify);
};

} // ioc
} // pvxs


#endif //PVXS_SINGLESOURCE_H
