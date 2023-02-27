/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <algorithm>
#include <cmath>
#include <string>

#include <dbAccess.h>
#include <dbChannel.h>
#include <dbEvent.h>
#include <dbStaticLib.h>
#include <special.h>

#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/source.h>
#include <dbNotify.h>

#include "dbentry.h"
#include "dberrormessage.h"
#include "dblocker.h"
#include "iocsource.h"
#include "singlesource.h"
#include "singlesrcsubscriptionctx.h"
#include "credentials.h"
#include "securitylogger.h"
#include "securityclient.h"
#include "typeutils.h"
#include "localfieldlog.h"

namespace pvxs {
namespace ioc {

DEFINE_LOGGER(_logname, "pvxs.ioc.single.source");

/**
 * Constructor for SingleSource registrar.
 */
SingleSource::SingleSource()
        :eventContext(db_init_events()) // Initialise event context
{
    auto names(std::make_shared<std::set<std::string >>());

    //  For each record type and for each record in that type, add record name to the list of all records
    DBEntry dbEntry;
    for (long status = dbFirstRecordType(dbEntry); !status; status = dbNextRecordType(dbEntry)) {
        for (status = dbFirstRecord(dbEntry); !status; status = dbNextRecord(dbEntry)) {
            names->insert(dbEntry->precnode->recordname);
        }
    }

    allRecords.names = names;

    // Start event pump
    if (!eventContext) {
        throw std::runtime_error("Single Source: Event Context failed to initialise: db_init_events()");
    }

    if (db_start_events(eventContext.get(), "qsrvSingle", nullptr, nullptr, epicsThreadPriorityCAServerLow - 1)) {
        throw std::runtime_error("Could not start event thread: db_start_events()");
    }
}

/**
 * Handle the create source operation.  This is called once when the source is created.
 * We will register all of the database records that have been loaded until this time as pv names in this
 * source.
 * @param channelControl
 */
void SingleSource::onCreate(std::unique_ptr<server::ChannelControl>&& channelControl) {
    auto sourceName(channelControl->name().c_str());
    dbChannel* pDbChannel = dbChannelCreate(sourceName);
    if (!pDbChannel) {
        log_debug_printf(_logname, "Ignore requested source '%s'\n", sourceName);
        return;
    }
    log_debug_printf(_logname, "Accepting channel for '%s'\n", sourceName);

    // Set up a shared pointer to the database channel and provide a deleter lambda for when it will eventually be deleted
    std::shared_ptr<dbChannel> dbChannelSharedPtr(pDbChannel, [](dbChannel* ch) { dbChannelDelete(ch); });

    DBErrorMessage dbErrorMessage(dbChannelOpen(dbChannelSharedPtr.get()));
    if (dbErrorMessage) {
        log_debug_printf(_logname, "Error opening database channel for '%s: %s'\n", sourceName,
                dbErrorMessage.c_str());
        throw std::runtime_error(dbErrorMessage.c_str());
    }

    // Create callbacks for handling requests and channel subscriptions
    createRequestAndSubscriptionHandlers(std::move(channelControl), dbChannelSharedPtr);
}

/**
 * Respond to search requests.  For each matching pv, claim that pv
 *
 * @param searchOperation the search operation
 */
void SingleSource::onSearch(Search& searchOperation) {
    for (auto& pv: searchOperation) {
        if (!dbChannelTest(pv.name())) {
            pv.claim();
            log_debug_printf(_logname, "Claiming '%s'\n", pv.name());
        }
    }
}

/**
 * Respond to the show request by displaying a list of all the PVs hosted in this ioc
 *
 * @param outputStream the stream to show the list on
 */
void SingleSource::show(std::ostream& outputStream) {
    outputStream << "IOC";
    for (auto& name: *SingleSource::allRecords.names) {
        outputStream << "\n" << indent{} << name;
    }
}

/**
 * Create request and subscription handlers for single record sources
 *
 * @param channelControl the control channel pointer that we got from onCreate
 * @param dbChannelSharedPtr the pointer to the database channel to set up the handlers for
 */
void SingleSource::createRequestAndSubscriptionHandlers(std::unique_ptr<server::ChannelControl>&& channelControl,
        const std::shared_ptr<dbChannel>& dbChannelSharedPtr) {

    Value valuePrototype = getValuePrototype(dbChannelSharedPtr);

    // Get and Put requests
    channelControl
            ->onOp([dbChannelSharedPtr, valuePrototype](std::unique_ptr<server::ConnectOp>&& channelConnectOperation) {
                onOp(dbChannelSharedPtr, valuePrototype, std::move(channelConnectOperation));
            });

    // Subscription requests
    channelControl
            ->onSubscribe([this, valuePrototype, dbChannelSharedPtr](
                    std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) {
                // The subscription must be kept alive
                // We accomplish this further on during the binding of the onStart()
                auto subscriptionContext(std::make_shared<SingleSourceSubscriptionCtx>(dbChannelSharedPtr));
                subscriptionContext->currentValue = valuePrototype;
                onSubscribe(subscriptionContext, std::move(subscriptionOperation));
            });
}

/**
 * Create a Value Prototype for storing values returned by the given channel.
 *
 * @param dbChannelSharedPtr pointer to the channel
 * @return a value prototype for the given channel
 */
Value SingleSource::getValuePrototype(const std::shared_ptr<dbChannel>& dbChannelSharedPtr) {
    auto dbChannel(dbChannelSharedPtr.get());
    short dbrType(dbChannelFinalFieldType(dbChannel));
    auto valueType(IOCSource::getChannelValueType(dbChannelSharedPtr.get()));

    Value valuePrototype;
    // To control optional metadata set to true to include in the output
    bool display = true;
    bool control = true;
    bool valueAlarm = true;

    if (dbrType == DBR_ENUM) {
        valuePrototype = nt::NTEnum{}.create();
    } else {
        valuePrototype = nt::NTScalar{ valueType, display, control, valueAlarm }.create();
    }
    return valuePrototype;
}

/**
 * Handle the get operation
 *
 * @param pDbChannel the channel that the request comes in on
 * @param getOperation the current executing operation
 * @param valuePrototype a value prototype that is made based on the expected type to be returned
 */
void SingleSource::get(dbChannel* pDbChannel, std::unique_ptr<server::ExecOp>& getOperation,
        const Value& valuePrototype) {
    try {
        auto returnValue = valuePrototype.cloneEmpty();
        {
            DBLocker F(pDbChannel->addr.precord); // lock
            LocalFieldLog localFieldLog(pDbChannel);
            IOCSource::get(pDbChannel, nullptr, returnValue, FOR_VALUE_AND_PROPERTIES, localFieldLog.pFieldLog);
        }
        getOperation->reply(returnValue);
    } catch (const std::exception& getException) {
        getOperation->error(getException.what());
    }
}

/**
 * Handler for the onOp event raised by pvxs Sources when they are started, in order to define the get and put handlers
 * on a per source basis.
 * This is called after the event has been intercepted and we add the channel and value prototype to the call.
 *
 * @param dbChannelSharedPtr the channel to which the get/put operation pertains
 * @param valuePrototype the value prototype that is appropriate for the given channel
 * @param channelConnectOperation the channel connect operation object
 */
void SingleSource::onOp(const std::shared_ptr<dbChannel>& dbChannelSharedPtr, const Value& valuePrototype,
        std::unique_ptr<server::ConnectOp>&& channelConnectOperation) {
    // Announce the channel type with a `connect()` call.  This happens only once
    channelConnectOperation->connect(valuePrototype);

    // Set up handler for get requests
    channelConnectOperation
            ->onGet([dbChannelSharedPtr, valuePrototype](std::unique_ptr<server::ExecOp>&& getOperation) {
                get(dbChannelSharedPtr.get(), getOperation, valuePrototype);
            });

    // Make a security cache for this client's connection to this pv
    // Each time the same client calls put we will re-use the cached security client
    // The security cache will be deleted when the client disconnects from this pv
    auto putOperationCache = std::make_shared<PutOperationCache>();

    // Set up handler for put requests
    channelConnectOperation
            ->onPut([dbChannelSharedPtr, valuePrototype, putOperationCache](
                    std::unique_ptr<server::ExecOp>&& putOperation,
                    Value&& value) {
                try {
                    auto pDbChannel = dbChannelSharedPtr.get();
                    if (!putOperationCache->done) {
                        putOperationCache->credentials.reset(new Credentials(*putOperation->credentials()));
                        putOperationCache->securityClient.update(pDbChannel, *putOperationCache->credentials);
                        putOperationCache->notify.usrPvt = putOperationCache.get();
                        putOperationCache->notify.chan = pDbChannel;
                        putOperationCache->notify.putCallback = putCallback;
                        putOperationCache->notify.doneCallback = doneCallback;

                        auto& pvRequest = putOperation->pvRequest();
                        pvRequest["record._options.block"].as<bool>(putOperationCache->doWait);
                        IOCSource::setForceProcessingFlag(pvRequest, putOperationCache);
                        if (putOperationCache->forceProcessing) {
                            putOperationCache->doWait = false; // no point in waiting
                        }
                        putOperationCache->done = true;
                    }

                    SecurityLogger securityLogger;

                    IOCSource::doPreProcessing(pDbChannel,
                            securityLogger,
                            *putOperationCache->credentials,
                            putOperationCache->securityClient); // pre-process
                    IOCSource::doFieldPreProcessing(putOperationCache->securityClient); // pre-process field
                    if (putOperationCache->doWait) {
                        putOperationCache->valueToSet = value;
                        // TODO prevent concurrent put with callbacks (notifyBusy)

                        putOperationCache->notify.requestType = value["value"].isMarked() ? putProcessRequest
                                                                                          : processRequest;
                        putOperationCache->putOperation = std::move(putOperation);
                        dbProcessNotify(&putOperationCache->notify);
                        return;
                    } else if (dbChannelFieldType(pDbChannel) >= DBF_INLINK
                            && dbChannelFieldType(pDbChannel) <= DBF_FWDLINK) {
                        // Locking is handled by dbPutField() called as a special case in IOCSource::put() for links
                        IOCSource::put(pDbChannel, value); // put
                    } else {
                        // All other field types call dbChannelPut() directly, so we have to perform locking here
                        DBLocker F(pDbChannel->addr.precord); // lock
                        IOCSource::put(pDbChannel, value); // put
                        IOCSource::doPostProcessing(pDbChannel, putOperationCache->forceProcessing); // post-process
                    }
                    putOperation->reply();
                } catch (std::exception& e) {
                    putOperation->error(e.what());
                }
            });
}
/**
 * Callback for asynchronous put operations to handle the actual put value operation
 *
 * @param notify the process notify object to use
 * @param type the put notification type
 * @return 1 for success and 0 for errors
 */
int SingleSource::putCallback(struct processNotify* notify, notifyPutType type) {
    if (notify->status != notifyOK) {
        return 0;
    }

    auto pPutOperationCache = (PutOperationCache*)notify->usrPvt;
    auto valueToSet = std::move(pPutOperationCache->valueToSet);

    switch (type) {
    case putDisabledType:
        // Request has been made but the record has been disabled, so noop and only call done callback
        return 0;
    case putFieldType:
        // As this type will be only called for Links the IOCSource::put() will handle the locking as a special case
    case putType:
        // For this type, the caller has already locked the record, so we'll not lock either
        IOCSource::put(pPutOperationCache->notify.chan, valueToSet); // put
        break;
    }
    return 1;
}

/**
 * Callback when asynchronous put's are complete
 *
 * @param notify the process notify object to use
 */
void SingleSource::doneCallback(struct processNotify* notify) {
    // Get our put operation cache object from the user pointer
    auto pPutOperationCache = (PutOperationCache*)notify->usrPvt;

    // Get the cached putOperation controller
    auto putOperation = std::move(pPutOperationCache->putOperation);

    // TODO handle cancelled requests
//	int expected = 1;
//	if (std::atomic_compare_exchange_weak(&pPutOperationCache->notifyBusy, &expected, 0) == 0) {
//		std::cerr << "SinglePut dbNotify state error?\n";
//	}

    switch (notify->status) {
    case notifyOK:
        // If everything is ok then notify the caller
        putOperation->reply();
        break;
    case notifyCanceled:
        return; // skip notification
    case notifyError:
        putOperation->error("Error in dbNotify");
        break;
    case notifyPutDisabled:
        putOperation->error("Put disabled");
        break;
    }
}

/**
 * Called by the framework when the monitoring client issues a start or stop subscription
 *
 * @param subscriptionContext the subscription context
 * @param isStarting true if the client issued a start subscription request, false otherwise
 */
void SingleSource::onStart(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext, bool isStarting) {
    if (isStarting) {
        onStartSubscription(subscriptionContext);
    } else {
        onDisableSubscription(subscriptionContext);
    }
}

/**
 * Called when a client starts a subscription it has subscribed to
 *
 * @param subscriptionContext the subscription context
 */
void SingleSource::onStartSubscription(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext) {
    db_event_enable(subscriptionContext->pValueEventSubscription.get());
    db_event_enable(subscriptionContext->pPropertiesEventSubscription.get());
    db_post_single_event(subscriptionContext->pValueEventSubscription.get());
    db_post_single_event(subscriptionContext->pPropertiesEventSubscription.get());
}

/**
 * Called by the framework when a client subscribes to a channel.  We intercept the call before this function is called
 * to add a new subscription context with a value prototype matching the channel definition.
 *
 * @param subscriptionContext a new subscription context with a value prototype matching the channel
 * @param subscriptionOperation the channel subscription operation
 */
void SingleSource::onSubscribe(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext,
        std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) const {
    // inform peer of data type and acquire control of the subscription queue
    subscriptionContext->subscriptionControl = subscriptionOperation->connect(subscriptionContext->currentValue);

    // Two subscription are made for pvxs
    // first subscription is for Value changes
    addSubscriptionEvent(Value, eventContext, subscriptionContext, DBE_VALUE | DBE_ALARM | DBE_ARCHIVE);
    // second subscription is for Property changes
    addSubscriptionEvent(Properties, eventContext, subscriptionContext, DBE_PROPERTY);

    // If either fail to complete then raise an error (removes last ref to shared_ptr subscriptionContext)
    if (!subscriptionContext->pValueEventSubscription
            || !subscriptionContext->pPropertiesEventSubscription) {
        throw std::runtime_error("Failed to create db subscription");
    }

    // If all goes well, Set up handlers for start and stop monitoring events
    // The subscription context is being kept alive because it is being bound into some internal storage by onStart
    subscriptionContext->subscriptionControl->onStart([subscriptionContext](bool isStarting) {
        onStart(subscriptionContext, isStarting);
    });
}

/**
 * Used by both value and property subscriptions, this function will get and return the database value to the monitor.
 *
 * @param subscriptionContext the subscription context
 * @param getOperationType the operation this callback serves
 * @param pDbFieldLog the database field log
 */
void SingleSource::subscriptionCallback(SingleSourceSubscriptionCtx* subscriptionContext,
        const GetOperationType getOperationType, struct db_field_log* pDbFieldLog) {

    // Get the current value of this subscription
    // We simply merge new field changes onto this value as events occur
    auto currentValue = subscriptionContext->currentValue;

    {
        DBLocker F(dbChannelRecord(subscriptionContext->pValueChannel.get()));
        IOCSource::get(subscriptionContext->pValueChannel.get(),
                ((getOperationType == FOR_PROPERTIES) ? subscriptionContext->pPropertiesChannel.get() : nullptr),
                currentValue, getOperationType, pDbFieldLog);
    }

    // Make sure that the initial subscription update has occurred on both channels before continuing
    // As we make two initial updates when opening a new subscription, we need both to have completed before continuing
    if (subscriptionContext->hadValueEvent && subscriptionContext->hadPropertyEvent) {
        // Return value
        subscriptionContext->subscriptionControl->post(currentValue.clone());
        currentValue.unmark();
    }
}

} // ioc
} // pvxs
