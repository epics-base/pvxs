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

DEFINE_INST_COUNTER(PutOperationCache);
DEFINE_INST_COUNTER(SingleInfo);

namespace {

void subscriptionCallback(SingleSourceSubscriptionCtx* subscriptionContext,
                          UpdateType::type change,
                          dbChannel* pChannel,
                          struct db_field_log* pDbFieldLog) noexcept {
    try {
        // Get the current value of this subscription
        // We simply merge new field changes onto this value as events occur
        auto currentValue = subscriptionContext->currentValue;

        {
            DBLocker F(dbChannelRecord(subscriptionContext->info->chan));
            // TODO MappingInfo::nsecMask
            IOCSource::get(currentValue, MappingInfo(), Value(), change, pChannel, pDbFieldLog);
        }

        // Make sure that the initial subscription update has occurred on both channels before continuing
        // As we make two initial updates when opening a new subscription, we need both to have completed before continuing
        if (subscriptionContext->hadValueEvent && subscriptionContext->hadPropertyEvent) {
            // Return value
            subscriptionContext->subscriptionControl->post(currentValue.clone());
            currentValue.unmark();
        }
    } catch(std::exception& e) {
        log_exc_printf(_logname, "Unhandled exception in %s\n", __func__);
    }
}

void subscriptionValueCallback(void* userArg, struct dbChannel* pChannel,
                               int, struct db_field_log* pDbFieldLog) noexcept {
    auto subscriptionContext = (SingleSourceSubscriptionCtx*)userArg;
    subscriptionContext->hadValueEvent = true;
    auto change = subscriptionContext->pValueEventSubscription.mask;
#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 6, 0)
    if(pDbFieldLog) {
        // when available, use DBE mask from db_field_log
        change = pDbFieldLog->mask;
    }
#endif
    // ARCHIVE events will get the same data fields as VALUE
    if(change & DBE_ARCHIVE)
        change = (change&~DBE_ARCHIVE)|DBE_VALUE;
    change &= UpdateType::Everything; // does not include DBE_ARCHIVE
    subscriptionCallback(subscriptionContext, UpdateType::type(change), pChannel, pDbFieldLog);
}

void subscriptionPropertiesCallback(void* userArg, struct dbChannel* pChannel, int,
                                    struct db_field_log* pDbFieldLog) noexcept {
    auto subscriptionContext = (SingleSourceSubscriptionCtx*)userArg;
    subscriptionContext->hadPropertyEvent = true;
    subscriptionCallback(subscriptionContext, UpdateType::Property, pChannel, pDbFieldLog);
}

/**
 * Called by the framework when a client subscribes to a channel.  We intercept the call before this function is called
 * to add a new subscription context with a value prototype matching the channel definition.
 *
 * @param subscriptionContext a new subscription context with a value prototype matching the channel
 * @param subscriptionOperation the channel subscription operation
 */
void onSubscribe(const std::shared_ptr<SingleSourceSubscriptionCtx>& subscriptionContext,
                 const DBEventContext& eventContext,
                 std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation)
{
    auto pvReq(subscriptionOperation->pvRequest());
    unsigned dbe = 0;
    if(auto fld = pvReq["record._options.DBE"].ifMarked()) {
        switch(fld.type().kind()) {
        case Kind::String: {
            auto mask(fld.as<std::string>());
            // name and sloppy parsing a la. caProvider...
#define CASE(EVENT) if(mask.find(#EVENT)!=mask.npos) dbe |= DBE_ ## EVENT
            CASE(VALUE);
            CASE(ARCHIVE);
            CASE(ALARM);
//            CASE(PROPERTY); // handled as special case
#undef CASE
            if(!dbe && !mask.empty()) {
                subscriptionOperation->logRemote(Level::Warn,
                                                 SB()<<pvReq.nameOf(fld)<<"=\""<<mask<<"\" selects empty mask");
            }
            break;
        }
        case Kind::Integer:
        case Kind::Real:
            dbe = fld.as<uint8_t>();
            break;
        default:
            break;
        }
    }
    dbe &= (DBE_VALUE | DBE_ARCHIVE | DBE_ALARM);
    if(!dbe)
        dbe = DBE_VALUE | DBE_ALARM;

    // inform peer of data type and acquire control of the subscription queue
    subscriptionContext->subscriptionControl = subscriptionOperation->connect(subscriptionContext->currentValue);

    IOCSource::initialize(subscriptionContext->currentValue,
                          *subscriptionContext->info,
                          subscriptionContext->info->chan);

    // Two subscription are made for pvxs
    // first subscription is for Value changes
    subscriptionContext->pValueEventSubscription.subscribe(eventContext.get(),
                                                           subscriptionContext->info->chan,
                                                           subscriptionValueCallback,
                                                           subscriptionContext.get(),
                                                           dbe
                                                           );
    // second subscription is for Property changes
    subscriptionContext->pPropertiesEventSubscription.subscribe(eventContext.get(),
                                                                subscriptionContext->pPropertiesChannel,
                                                                subscriptionPropertiesCallback,
                                                                subscriptionContext.get(),
                                                                DBE_PROPERTY
                                                                );

    // If all goes well, Set up handlers for start and stop monitoring events
    // The subscription context is being kept alive because it is being bound into some internal storage by onStart
    subscriptionContext->subscriptionControl->onStart([subscriptionContext](bool isStarting) {
        if (isStarting) {
            subscriptionContext->eventsEnabled = true;
            subscriptionContext->pValueEventSubscription.enable();
            subscriptionContext->pPropertiesEventSubscription.enable();
        } else {
            subscriptionContext->pValueEventSubscription.disable();
            subscriptionContext->pPropertiesEventSubscription.disable();
            subscriptionContext->eventsEnabled = false;
        }
    });
}
/**
 * Create a Value Prototype for storing values returned by the given channel.
 *
 * @param dbChannelSharedPtr pointer to the channel
 * @return a value prototype for the given channel
 */
Value getValuePrototype(const std::shared_ptr<SingleInfo>& sinfo) {
    auto& chan(sinfo->chan);
    short dbrType(dbChannelFinalFieldType(chan));
    auto valueType(IOCSource::getChannelValueType(chan));

    Value valuePrototype;
    // To control optional metadata set to true to include in the output
    bool display = true;
    bool control = true;
    bool valueAlarm = true;

    if (dbrType == DBR_ENUM) {
        valuePrototype = nt::NTEnum{}.create();
    } else {
        valuePrototype = nt::NTScalar{ valueType, display, control, valueAlarm, true }.create();
    }
    return valuePrototype;
}

/**
 * Callback for asynchronous put operations to handle the actual put value operation
 *
 * @param notify the process notify object to use
 * @param type the put notification type
 * @return 1 for success and 0 for errors
 */
int putCallback(struct processNotify* notify, notifyPutType type) {
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
        IOCSource::put(pPutOperationCache->notify.chan, valueToSet, MappingInfo()); // put
        break;
    }
    return 1;
}

/**
 * Callback when asynchronous put's are complete
 *
 * @param notify the process notify object to use
 */
void doneCallback(struct processNotify* notify) {
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
 * Handle the get operation
 *
 * @param pDbChannel the channel that the request comes in on
 * @param getOperation the current executing operation
 * @param valuePrototype a value prototype that is made based on the expected type to be returned
 */
void singleGet(const SingleInfo& info,
               std::unique_ptr<server::ExecOp>& getOperation,
               const Value& valuePrototype) {
    auto& pDbChannel(info.chan);
    try {
        auto returnValue = valuePrototype.cloneEmpty();
        // TODO: MappingInfo::nsecMask
        IOCSource::initialize(returnValue, info, pDbChannel);
        {
            DBLocker F(pDbChannel->addr.precord); // lock
            LocalFieldLog localFieldLog(pDbChannel);
            IOCSource::get(returnValue, info,
                           Value(), UpdateType::Everything,
                           pDbChannel, localFieldLog.pFieldLog);
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
void onOp(const std::shared_ptr<SingleInfo>& sInfo, const Value& valuePrototype,
        std::unique_ptr<server::ConnectOp>&& channelConnectOperation) {
    // Announce the channel type with a `connect()` call.  This happens only once
    channelConnectOperation->connect(valuePrototype);

    // Set up handler for get requests
    channelConnectOperation
            ->onGet([sInfo, valuePrototype](std::unique_ptr<server::ExecOp>&& getOperation) {
                singleGet(*sInfo, getOperation, valuePrototype);
            });

    // Make a security cache for this client's connection to this pv
    // Each time the same client calls put we will reuse the cached security client
    // The security cache will be deleted when the client disconnects from this pv
    auto putOperationCache = std::make_shared<PutOperationCache>();

    // Set up handler for put requests
    channelConnectOperation
            ->onPut([sInfo, putOperationCache](
                    std::unique_ptr<server::ExecOp>&& putOperation,
                    Value&& value) {
                try {
                    dbChannel* pDbChannel = sInfo->chan;
                    if (!putOperationCache->done) {
                        putOperationCache->credentials.reset(new Credentials(*putOperation->credentials()));
                        putOperationCache->securityClient.update(pDbChannel, *putOperationCache->credentials);
                        putOperationCache->notify.usrPvt = putOperationCache.get();
                        putOperationCache->notify.chan = pDbChannel;
                        putOperationCache->notify.putCallback = putCallback;
                        putOperationCache->notify.doneCallback = doneCallback;

                        auto& pvRequest = putOperation->pvRequest();
                        pvRequest["record._options.block"].as<bool>(putOperationCache->doWait);
                        IOCSource::setForceProcessingFlag(putOperation.get(), pvRequest, putOperationCache);
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

                        putOperationCache->notify.requestType = value["value"].isMarked(true, true)
                                ? putProcessRequest : processRequest;
                        putOperationCache->putOperation = std::move(putOperation);
                        dbProcessNotify(&putOperationCache->notify);
                        return;
                    }

                    CurrentOp op(putOperation.get());

                    if (dbChannelFieldType(pDbChannel) >= DBF_INLINK
                            && dbChannelFieldType(pDbChannel) <= DBF_FWDLINK) {
                        // Locking is handled by dbPutField() called as a special case in IOCSource::put() for links
                        IOCSource::put(pDbChannel, value, MappingInfo()); // put
                    } else {
                        // All other field types call dbChannelPut() directly, so we have to perform locking here
                        DBLocker F(pDbChannel->addr.precord); // lock
                        IOCSource::put(pDbChannel, value, MappingInfo()); // put
                        IOCSource::doPostProcessing(pDbChannel, putOperationCache->forceProcessing); // post-process
                    }
                    putOperation->reply();
                } catch (std::exception& e) {
                    putOperation->error(e.what());
                }
            });
}

} // namespace

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
    Channel pDbChannel;
    try {
        pDbChannel = Channel(sourceName);
    }  catch (std::exception& e) {
        log_debug_printf(_logname, "Ignore requested channel '%s' : %s\n", sourceName, e.what());
        return;
    }

    log_debug_printf(_logname, "Accepting channel for '%s'\n", sourceName);

    auto sInfo(std::make_shared<SingleInfo>(std::move(pDbChannel)));

    // Create callbacks for handling requests and channel subscriptions
    Value valuePrototype = getValuePrototype(sInfo);

    // Get and Put requests
    channelControl
            ->onOp([sInfo, valuePrototype](std::unique_ptr<server::ConnectOp>&& channelConnectOperation) {
                onOp(sInfo, valuePrototype, std::move(channelConnectOperation));
            });

    // binding 'this' safe as Server shutdown will close connections before dropping Source
    channelControl
            ->onSubscribe([this, valuePrototype, sInfo](
                    std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) {
                // The subscription must be kept alive
                // We accomplish this further on during the binding of the onStart()
                auto subscriptionContext(std::make_shared<SingleSourceSubscriptionCtx>(sInfo));
                subscriptionContext->currentValue = valuePrototype.cloneEmpty();
                onSubscribe(subscriptionContext, eventContext, std::move(subscriptionOperation));
            });
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

} // ioc
} // pvxs
