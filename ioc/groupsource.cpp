/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>

#include <dbEvent.h>
#include <dbChannel.h>
#include <special.h>

#include <pvxs/source.h>
#include <pvxs/log.h>

#include "credentials.h"
#include "dberrormessage.h"
#include "dblocker.h"
#include "dbmanylocker.h"
#include "fieldsubscriptionctx.h"
#include "groupsource.h"
#include "groupsrcsubscriptionctx.h"
#include "iocshcommand.h"
#include "iocsource.h"
#include "securitylogger.h"
#include "securityclient.h"
#include "localfieldlog.h"

namespace pvxs {
namespace ioc {

DEFINE_LOGGER(_logname, "pvxs.ioc.group.source");

/**
 * Constructor for GroupSource registrar.
 */
GroupSource::GroupSource()
        :eventContext(db_init_events()) // Initialise event context
{
    // Get GroupPv configuration and register each pv name in the server
    runOnPvxsServer([this](IOCServer* pPvxsServer) {
        auto names(std::make_shared<std::set<std::string >>());

        // Lock map and get names
        {
            epicsGuard<epicsMutex> G(pPvxsServer->groupMapMutex);

            // For each defined group, add group name to the list of all records
            for (auto& groupMapEntry: pPvxsServer->groupMap) {
                auto& groupName = groupMapEntry.first;
                names->insert(groupName);
            }
        }

        allRecords.names = names;

        // Start event pump
        if (!eventContext) {
            throw std::runtime_error("Group Source: Event Context failed to initialise: db_init_events()");
        }

        if (db_start_events(eventContext.get(), "qsrvGroup", nullptr, nullptr, epicsThreadPriorityCAServerLow - 1)) {
            throw std::runtime_error("Could not start event thread: db_start_events()");
        }
    });
}

/**
 * Handle the create source operation.  This is called once when the source is created.
 * We will register all of the database records that have been loaded until this time as pv names in this
 * source.
 *
 * @param channelControl channel control object provided by the pvxs framework
 */
void GroupSource::onCreate(std::unique_ptr<server::ChannelControl>&& channelControl) {
    auto& sourceName = channelControl->name();
    log_debug_printf(_logname, "Accepting channel for '%s'\n", sourceName.c_str());

    runOnPvxsServer([&](IOCServer* pPvxsServer) {
        // Create callbacks for handling requests and group subscriptions
        auto& group = pPvxsServer->groupMap[sourceName];
        createRequestAndSubscriptionHandlers(channelControl, group);
    });

}

/**
 * Respond to search requests.  For each matching pv, claim that pv
 *
 * @param searchOperation the search operation
 */
void GroupSource::onSearch(Search& searchOperation) {
    runOnPvxsServer([&](IOCServer* pPvxsServer) {
        for (auto& pv: searchOperation) {
            if (allRecords.names->count(pv.name()) == 1) {
                pv.claim();
                log_debug_printf(_logname, "Claiming '%s'\n", pv.name());
            }
        }
    });
}

/**
 * Respond to the show request by displaying a list of all the PVs hosted in this ioc
 *
 * @param outputStream the stream to show the list on
 */
void GroupSource::show(std::ostream& outputStream) {
    outputStream << "IOC";
    for (auto& name: *GroupSource::allRecords.names) {
        outputStream << "\n" << indent{} << name;
    }
}

/**
 * Create request and subscription handlers for group record sources
 *
 * @param channelControl the control channel pointer that we got from onCreate
 * @param group the group that we're creating the request and subscription handlers for
 */
void GroupSource::createRequestAndSubscriptionHandlers(std::unique_ptr<server::ChannelControl>& channelControl,
        Group& group) {
    // Get and Put requests
    channelControl->onOp([&](std::unique_ptr<server::ConnectOp>&& channelConnectOperation) {
        onOp(group, std::move(channelConnectOperation));
    });

    channelControl
            ->onSubscribe([this, &group](std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) {
                // The group subscription must be kept alive
                // We accomplish this further on during the binding of the onStart()
                auto subscriptionContext(std::make_shared<GroupSourceSubscriptionCtx>(group));
                onSubscribe(subscriptionContext, std::move(subscriptionOperation));
            });
}

/**
 * Called when a client pauses / stops a subscription it has been subscribed to.
 * This function loops over all fields event subscriptions the group subscription context and disables each of them.
 *
 * @param groupSubscriptionCtx the group subscription context
 */
void GroupSource::onDisableSubscription(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx) {
    for (auto& fieldSubscriptionCtx: groupSubscriptionCtx->fieldSubscriptionContexts) {
        auto pValueEventSubscription = fieldSubscriptionCtx.pValueEventSubscription.get();
        auto pPropertiesEventSubscription = fieldSubscriptionCtx.pPropertiesEventSubscription.get();
        db_event_disable(pValueEventSubscription);
        db_event_disable(pPropertiesEventSubscription);
    }
}

/**
 * Handler for the onOp event raised by pvxs Sources when they are started, in order to define the get and put handlers
 * on a per source basis.
 * This is called after the event has been intercepted and we add the group to the call.
 *
 * @param group the group to which the get/put operation pertains
 * @param channelConnectOperation the channel connect operation object
 */
void GroupSource::onOp(Group& group,
        std::unique_ptr<server::ConnectOp>&& channelConnectOperation) {
    // First stage for handling any request is to announce the channel type with a `connect()` call
    // @note The type signalled here must match the eventual type returned by a pvxs get
    channelConnectOperation->connect(group.valueTemplate);

    // register handler for pvxs group get
    channelConnectOperation->onGet([&group](std::unique_ptr<server::ExecOp>&& getOperation) {
        get(group, getOperation);
    });

    // Make a security cache for this client's connection to this group
    // Each time the same client calls put we will re-use the cached security client
    // The security cache will be deleted when the client disconnects from this group pv
    auto securityCache = std::make_shared<GroupSecurityCache>();

    // register handler for pvxs group put
    channelConnectOperation
            ->onPut([&group, securityCache](std::unique_ptr<server::ExecOp>&& putOperation, Value&& value) {
                if (!securityCache->done) {
                    // First time we call put we need to initialise the security cache
                    securityCache->securityClients.resize(group.fields.size());
                    securityCache->credentials.reset(new Credentials(*putOperation->credentials()));
                    auto fieldIndex = 0u;
                    for (auto& field: group.fields) {
                        if (field.value.channel) {
                            securityCache->securityClients[fieldIndex]
                                    .update(field.value.channel, *securityCache->credentials);
                        }
                        fieldIndex++;
                    }
                    auto& pvRequest = putOperation->pvRequest();
                    IOCSource::setForceProcessingFlag(pvRequest, securityCache);
                    securityCache->done = true;
                }

                putGroup(group, putOperation, value, *securityCache);
            });
}

/**
 * Called by the framework when the monitoring client issues a start or stop subscription.  We
 * intercept the framework's call prior to entering here, and add the group subscription context
 * containing a list of field contexts and their event subscriptions to manage.
 *
 * @param groupSubscriptionCtx the group subscription context
 * @param isStarting true if the client issued a start subscription request, false otherwise
 */
void GroupSource::onStart(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx, bool isStarting) {
    if (isStarting) {
        onStartSubscription(groupSubscriptionCtx);
    } else {
        onDisableSubscription(groupSubscriptionCtx);
    }
}

/**
 * Called when a client starts a subscription it has subscribed to.  For each field in the subscription,
 * enable events and post a single event to both the values and properties event channels to kick things off.
 *
 * @param groupSubscriptionCtx the group subscription context containing the field event subscriptions to start
 */
void GroupSource::onStartSubscription(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx) {
    for (auto& fieldSubscriptionCtx: groupSubscriptionCtx->fieldSubscriptionContexts) {
        auto pValueEventSubscription = fieldSubscriptionCtx.pValueEventSubscription.get();
        auto pPropertiesEventSubscription = fieldSubscriptionCtx.pPropertiesEventSubscription.get();
        db_event_enable(pValueEventSubscription);
        db_event_enable(pPropertiesEventSubscription);
        db_post_single_event(pValueEventSubscription);
        db_post_single_event(pPropertiesEventSubscription);
    }
}

/**
 * Called by the framework when a client subscribes to a channel.  We intercept the call before this function is called
 * to add a new group subscription context containing a reference to the group.
 * This function must initialise all of the field's subscription contexts.
 *
 * @param groupSubscriptionCtx a new group subscription context
 * @param subscriptionOperation the group subscription operation
 */
void GroupSource::onSubscribe(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx,
        std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) const {
    // inform peer of data type and acquire control of the subscription queue
    groupSubscriptionCtx->subscriptionControl = subscriptionOperation
            ->connect(groupSubscriptionCtx->group.valueTemplate);

    // Initialise the field subscription contexts.  One for each group field.
    // This is stored in the group context
    groupSubscriptionCtx->fieldSubscriptionContexts.reserve(groupSubscriptionCtx->group.fields.size());
    for (auto& field: groupSubscriptionCtx->group.fields) {
        groupSubscriptionCtx->fieldSubscriptionContexts.emplace_back(field, groupSubscriptionCtx.get());
        auto& fieldSubscriptionContext = groupSubscriptionCtx->fieldSubscriptionContexts.back();

        // Two subscription are made for each group channel for pvxs
        if (field.isMeta) {
            fieldSubscriptionContext
                    .subscribeField(eventContext.get(), subscriptionValueCallback, DBE_ALARM);
        } else {
            fieldSubscriptionContext
                    .subscribeField(eventContext.get(), subscriptionValueCallback, DBE_VALUE | DBE_ALARM | DBE_ARCHIVE);
        }
        fieldSubscriptionContext
                .subscribeField(eventContext.get(), subscriptionPropertiesCallback, DBE_PROPERTY, false);
    }

    // If all goes well, set up handlers for start and stop monitoring events
    // The group subscription context is being kept alive because it is being bound into some internal storage by onStart
    groupSubscriptionCtx->subscriptionControl->onStart([groupSubscriptionCtx](bool isStarting) {
        onStart(groupSubscriptionCtx, isStarting);
    });
}

/**
 * Handle the get operation
 *
 * @param group the group to get
 * @param getOperation the current executing operation
 */
void GroupSource::get(Group& group, std::unique_ptr<server::ExecOp>& getOperation) {
    groupGet(group, [&getOperation](Value& value) {
        getOperation->reply(value);
    }, [&getOperation](const char* errorMessage) {
        getOperation->error(errorMessage);
    });
}

/**
 * Get each field and make up the whole group structure
 *
 * @param group group to base result on
 * @param returnFn function to call with the result
 * @param errorFn function to call on errors
 */
void GroupSource::groupGet(Group& group, const std::function<void(Value&)>& returnFn,
        const std::function<void(const char*)>& errorFn) {

    // Make an empty value to return
    auto returnValue(group.valueTemplate.cloneEmpty());

    // If the group is configured for an atomic get operation,
    // then we need to get all the fields at once, so we lock them all together
    // and do the operation in one go
    if (group.atomicPutGet) {
        // Lock all the fields
        DBManyLocker G(group.value.lock);
        // Loop through all fields
        for (auto& field: group.fields) {
            // ignore all zero length named fields that are not meta
            if (field.name.empty() && !field.isMeta) {
                continue;
            }

            // find the leaf node in which to set the value
            auto leafNode = field.findIn(returnValue);

            if (leafNode) {
                if (!getGroupField(field, leafNode, group.name, errorFn)) {
                    return;
                }
            }
        }

        // Unlock the all group fields when the locker goes out of scope

    } else {
        // Otherwise, this is a non-atomic operation, and we need to `put` each field individually,
        // locking each of them independently of each other.

        // Loop through all fields
        for (auto& field: group.fields) {
            // ignore all zero length fields that are not meta
            if (field.name.empty() && !field.isMeta) {
                continue;
            }

            // find the leaf node in which to set the value
            auto leafNode = field.findIn(returnValue);

            if (leafNode) {
                // Lock this field
                dbChannel* pDbChannel = field.value.channel;
                DBLocker F(pDbChannel->addr.precord);
                if (!getGroupField(field, leafNode, group.name, errorFn)) {
                    return;
                }
            }
        }
    }

    // Send reply
    returnFn(returnValue);
}

/**
 * Get a group field into the specified Value target object.  The group name is provided in case there are errors
 * to better identify the location of the error when the error function is called with the error text
 *
 * @param field the field to get
 * @param valueTarget the place to store the value retrieved
 * @param groupName the name of the group that the field is a part of
 * @param errorFn the function to call if errors occur
 * @return true if retrieved successfully, false otherwise
 */
bool GroupSource::getGroupField(const Field& field, Value valueTarget, const std::string& groupName,
        const std::function<void(const char*)>& errorFn) {
    try {
        LocalFieldLog localFieldLog(field.value.channel);
        IOCSource::get(field.value.channel, nullptr, valueTarget,
                field.isMeta ? FOR_METADATA : FOR_VALUE_AND_PROPERTIES, localFieldLog.pFieldLog);
    } catch (std::exception& e) {
        std::stringstream errorString;
        errorString << "Error retrieving value for pvName: " << groupName << (field.name.empty() ? "/" : ".")
                    << field.fullName << " : "
                    << e.what();
        errorFn(errorString.str().c_str());
        return false;
    }
    return true;
}

/**
 * Handler invoked when a peer sends data on a PUT
 *
 * @param group the group to which the data is posted
 * @param putOperation the put operation object to use to interact with the client
 * @param value the value being posted
 * @param groupSecurityCache the object that caches the security context of client connections
 */
void GroupSource::putGroup(Group& group, std::unique_ptr<server::ExecOp>& putOperation, const Value& value,
        const GroupSecurityCache& groupSecurityCache) {
    try {
        std::vector<SecurityLogger> securityLoggers(group.fields.size());

        // Prepare group put operation
        auto fieldIndex = 0;
        for (auto& field: group.fields) {
            dbChannel* pDbChannel = field.value.channel;
            if (pDbChannel) {
                IOCSource::doPreProcessing(pDbChannel,
                        securityLoggers[fieldIndex], *groupSecurityCache.credentials,
                        groupSecurityCache.securityClients[fieldIndex]);
                if (dbChannelFinalFieldType(pDbChannel) >= DBF_INLINK
                        && dbChannelFinalFieldType(pDbChannel) <= DBF_FWDLINK) {
                    throw std::runtime_error("Links not supported for put");
                }
            }
            fieldIndex++;
        }

        // Reset index for subsequent loops
        fieldIndex = 0;

        // If the group is configured for an atomic put operation,
        // then we need to put all the fields at once, so we lock them all together
        // and do the operation in one go
        if (group.atomicPutGet) {
            // Lock all the fields
            DBManyLocker G(group.value.lock);
            // Loop through all fields
            for (auto& field: group.fields) {
                // Put the field
                putGroupField(value, field, groupSecurityCache.securityClients[fieldIndex]);
                // Do processing if required
                IOCSource::doPostProcessing(field.value.channel, groupSecurityCache.forceProcessing);
                fieldIndex++;
            }

            // Unlock the all group fields when the locker goes out of scope

        } else {
            // Otherwise, this is a non-atomic operation, and we need to `put` each field individually,
            // locking each of them independently of each other.

            // Loop through all fields
            for (auto& field: group.fields) {
                dbChannel* pDbChannel = field.value.channel;
                // Lock this field
                DBLocker F(pDbChannel->addr.precord);
                // Put the field
                putGroupField(value, field, groupSecurityCache.securityClients[fieldIndex]);
                // Do processing if required
                IOCSource::doPostProcessing(field.value.channel, groupSecurityCache.forceProcessing);
                // Unlock this field when locker goes out of scope
                fieldIndex++;
            }
        }

    } catch (std::exception& e) {
        // Unlock all locked fields when lockers go out of scope
        // Post error message to put operation object
        putOperation->error(e.what());
        return;
    }

    // If all went ok then let the client know
    putOperation->reply();
}

/**
 * Called by putGroup() to perform the actual put of the given value into the group field specified.
 * The value will be the whole value template that the group represents but only the fields passed in by
 * the client will be set.  So we simply check to see whether the parts of value that are referenced by the
 * provided field parameter are included in the given value, and if so, we pull them out and do a low level
 * database put.
 *
 * @param value the sparsely populated value to put into the group's field
 * @param field the group field to check against
 * @param securityClient the security client to use to authorise the operation
 */
void GroupSource::putGroupField(const Value& value, const Field& field, const SecurityClient& securityClient) {
    // find the leaf node that the field refers to in the given value
    auto leafNode = field.findIn(value);

    // If the field references a valid part of the given value then we can send it to the database
    if (leafNode && leafNode.isMarked()) {
        SecurityLogger securityLogger;
        IOCSource::doFieldPreProcessing(securityClient); // pre-process field
        IOCSource::put(field.value.channel, leafNode);
    }
}

/**
 * Used by both value and property subscriptions, this function will get the database value and return it
 * to the monitor.  It is called whenever a field subscription event is received.
 *
 * @param fieldSubscriptionCtx the field subscription context
 * @param getOperationType the operation this callback serves
 * @param pDbFieldLog the database field log
 */
void GroupSource::subscriptionCallback(FieldSubscriptionCtx* fieldSubscriptionCtx,
        const GetOperationType getOperationType, struct db_field_log* pDbFieldLog) {

    // Find the group subscription context from the field subscription context
    auto& pGroupCtx = fieldSubscriptionCtx->pGroupCtx;
    // Also find the field
    auto field = fieldSubscriptionCtx->field;

    // Get the current value of this group subscription
    // We simply merge new field changes onto this value as events occur
    auto currentValue = pGroupCtx->currentValue;

    // Lock only fields triggered by this field
    DBManyLocker G(getOperationType <= FOR_METADATA ? field->value.lock : field->properties.lock);

    // for all triggered fields get the values.  Assumes that self has been added to triggered list
    for (auto& pTriggeredField: field->triggers) {
        // Find leaf node within the current value.  This will be a reference into the currentValue.
        // So that if we assign the leafNode with the value we `get()` back, then currentValue will be updated
        auto leafNode = pTriggeredField->findIn(currentValue);
        if (leafNode) {
            dbChannel* channelToUse = (getOperationType == FOR_PROPERTIES) ? pTriggeredField->properties.channel
                                                                           : pTriggeredField->value.channel;
            LocalFieldLog localFieldLog(channelToUse, (pTriggeredField == field) ? pDbFieldLog : nullptr);
            IOCSource::get(pTriggeredField->value.channel, pTriggeredField->properties.channel,
                    leafNode, getOperationType, localFieldLog.pFieldLog);
        }
    }

    // Make sure that the initial subscription update has occurred on all channels before replying
    // As we make two initial updates when opening a new subscription, for each field,
    // we need all updates for all fields to have completed before continuing
    if (!pGroupCtx->eventsPrimed) {
        for (auto& fieldCtx: pGroupCtx->fieldSubscriptionContexts) {
            if (!fieldCtx.hadValueEvent || !fieldCtx.hadPropertyEvent) {
                return;
            }
        }
        pGroupCtx->eventsPrimed = true;
    }

    // If events have been primed then return the value to the subscriber,
    // and unmark all accumulated changes
    pGroupCtx->subscriptionControl->post(currentValue.clone());
    currentValue.unmark();

    // Unlock fields in group when locker goes out of scope
}

/**
 * This callback handles notifying of updates to subscribed-to pv values.
 *
 * @param userArg the user argument passed to the callback function from the framework: a FieldSubscriptionCtx
 * @param pDbFieldLog the database field log containing the changes being notified
 */
void GroupSource::subscriptionValueCallback(void* userArg, dbChannel*, int, struct db_field_log* pDbFieldLog) {
    auto subscriptionContext = (FieldSubscriptionCtx*)userArg;
    {
        epicsGuard<epicsMutex> G((subscriptionContext->pGroupCtx)->eventLock);
        subscriptionContext->hadValueEvent = true;
    }
    subscriptionCallback(subscriptionContext,
            subscriptionContext->field->isMeta ? FOR_METADATA : FOR_VALUE, pDbFieldLog);
}

/**
 * This callback handles notifying of updates to subscribed-to pv properties.
 *
 * @param userArg the user argument passed to the callback function from the framework: a FieldSubscriptionCtx
 * @param pDbFieldLog the database field log containing the changes being notified
 */
void GroupSource::subscriptionPropertiesCallback(void* userArg, dbChannel*, int, struct db_field_log* pDbFieldLog) {
    auto subscriptionContext = (FieldSubscriptionCtx*)userArg;
    {
        epicsGuard<epicsMutex> G((subscriptionContext->pGroupCtx)->eventLock);
        subscriptionContext->hadPropertyEvent = true;
    }
    if (!subscriptionContext->field->isMeta) {
        subscriptionCallback(subscriptionContext, FOR_PROPERTIES, pDbFieldLog);
    }
}

} // ioc
} // pvxs
