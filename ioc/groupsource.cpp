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

DEFINE_INST_COUNTER(GroupSourceSubscriptionCtx);
DEFINE_INST_COUNTER(GroupSecurityCache);

/**
 * Constructor for GroupSource registrar.
 */
GroupSource::GroupSource()
        :eventContext(db_init_events()) // Initialise event context
        ,config(IOCGroupConfig::instance())
{
    // Get GroupPv configuration and register each pv name in the server
    auto names(std::make_shared<std::set<std::string >>());

    // Lock map and get names
    {
        epicsGuard<epicsMutex> G(config.groupMapMutex);

        // For each defined group, add group name to the list of all records
        for (auto& groupMapEntry: config.groupMap) {
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

    // Create callbacks for handling requests and group subscriptions
    auto it(config.groupMap.find(sourceName));
    if(it != config.groupMap.end()) {
        auto& group(it->second);
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
}

/**
 * Respond to search requests.  For each matching pv, claim that pv
 *
 * @param searchOperation the search operation
 */
void GroupSource::onSearch(Search& searchOperation) {
    for (auto& pv: searchOperation) {
        if (allRecords.names->count(pv.name()) == 1) {
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
void GroupSource::show(std::ostream& outputStream) {
    outputStream << "IOC";
    for (auto& name: *GroupSource::allRecords.names) {
        outputStream << "\n" << indent{} << name;
    }
}

/**
 * Called when a client pauses / stops a subscription it has been subscribed to.
 * This function loops over all fields event subscriptions the group subscription context and disables each of them.
 *
 * @param groupSubscriptionCtx the group subscription context
 */
void GroupSource::onDisableSubscription(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx) {
    for (auto& fieldSubscriptionCtx: groupSubscriptionCtx->fieldSubscriptionContexts) {
        fieldSubscriptionCtx.pValueEventSubscription.disable();
        fieldSubscriptionCtx.pPropertiesEventSubscription.disable();
    }
    groupSubscriptionCtx->eventsEnabled = false;
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
    // Each time the same client calls put we will reuse the cached security client
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
                        if (field.value) {
                            securityCache->securityClients[fieldIndex]
                                    .update(field.value, *securityCache->credentials);
                        }
                        fieldIndex++;
                    }
                    auto& pvRequest = putOperation->pvRequest();
                    IOCSource::setForceProcessingFlag(putOperation.get(), pvRequest, securityCache);
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

static
void subscriptionPost(GroupSourceSubscriptionCtx *pGroupCtx)
{
    // Make sure that the initial subscription update has occurred on all channels before replying
    // As we make two initial updates when opening a new subscription, for each field,
    // we need all updates for all fields to have completed before continuing
    bool first = false;
    if (!pGroupCtx->eventsPrimed) {
        for (auto& fieldCtx: pGroupCtx->fieldSubscriptionContexts) {
            if (!fieldCtx.hadValueEvent || !fieldCtx.hadPropertyEvent) {
                return;
            }
        }
        pGroupCtx->eventsPrimed = first = true;
    }

    auto& currentValue = pGroupCtx->currentValue;

    bool empty(!currentValue.isMarked(false, true));

    Level lvl = first && empty ? Level::Warn : Level::Debug;
    log_printf(_logname, lvl, "%s%s%s : %s\n", __func__,
               first ? " first" : "", empty ? " empty" : "",
               pGroupCtx->group.name.c_str());
    if(empty && !first)
        return;

    // If events have been primed then return the value to the subscriber,
    // and unmark all accumulated changes
    pGroupCtx->subscriptionControl->post(currentValue.clone());
    currentValue.unmark();
}

/**
 * Called when a client starts a subscription it has subscribed to.  For each field in the subscription,
 * enable events and post a single event to both the values and properties event channels to kick things off.
 *
 * @param groupSubscriptionCtx the group subscription context containing the field event subscriptions to start
 */
void GroupSource::onStartSubscription(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx) {
    groupSubscriptionCtx->eventsEnabled = true;
    for (auto& fieldSubscriptionCtx: groupSubscriptionCtx->fieldSubscriptionContexts) {
        fieldSubscriptionCtx.pValueEventSubscription.enable();
        fieldSubscriptionCtx.pPropertiesEventSubscription.enable();
    }
    // maybe post initial here in pathological case with no +channel.  (eg. all const)
    subscriptionPost(groupSubscriptionCtx.get());
}

/**
 * This callback handles notifying of updates to subscribed-to pv values.
 *
 * @param userArg the user argument passed to the callback function from the framework: a FieldSubscriptionCtx
 * @param pDbFieldLog the database field log containing the changes being notified
 */
static
void subscriptionValueCallback(void* userArg, dbChannel* pChannel,
                               int, struct db_field_log* pDbFieldLog) noexcept {
    try {
        auto fieldSubscriptionCtx = (FieldSubscriptionCtx*)userArg;
        auto first = !fieldSubscriptionCtx->hadValueEvent;
        fieldSubscriptionCtx->hadValueEvent = true;

        // Find the group subscription context from the field subscription context
        auto& pGroupCtx = fieldSubscriptionCtx->pGroupCtx;
        // Also find the field
        auto& field = *fieldSubscriptionCtx->field;
        auto& currentValue = pGroupCtx->currentValue;

        log_debug_printf(_logname, "%s%s %s %s.%s\n", __func__,
                         first ? " first" : "",
                         pChannel ? pChannel->name : "<null>",
                         pGroupCtx->group.name.c_str(), field.fullName.c_str());

        // lock all records to be triggered
        DBManyLocker G(field.lock);

        for (auto& pTriggeredField: field.triggers) {
            auto leafNode = pTriggeredField->findIn(currentValue);
            dbChannel *channelToUse = pTriggeredField->value;
            bool isSelfTrig = channelToUse==pChannel;
            auto change = UpdateType::type(UpdateType::Value | UpdateType::Alarm);
#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 6, 0)
            if(isSelfTrig && pDbFieldLog) {
                // when available, use DBE mask from db_field_log
                change = UpdateType::type(pDbFieldLog->mask & UpdateType::Everything);
            }
#endif
            log_debug_printf(_logname, "%s trig %s %s.%s\n", __func__,
                             pTriggeredField->value ? pTriggeredField->value->name : "<null>",
                             pGroupCtx->group.name.c_str(), pTriggeredField->fullName.c_str());

            LocalFieldLog localFieldLog(channelToUse, isSelfTrig ? pDbFieldLog : nullptr);
            IOCSource::get(leafNode, pTriggeredField->info, pTriggeredField->anyType,
                           change, channelToUse, localFieldLog.pFieldLog);
        }

        subscriptionPost(pGroupCtx);

    } catch(std::exception& e) {
        log_exc_printf(_logname, "Unhandled exception in %s\n", __func__);
    }
}

static
void subscriptionPropertiesCallback(void* userArg, dbChannel* pChannel,
                                    int, struct db_field_log* pDbFieldLog) noexcept {
    try {
        auto subscriptionContext = (FieldSubscriptionCtx*)userArg;
        bool first = subscriptionContext->hadPropertyEvent;
        subscriptionContext->hadPropertyEvent = true;

        auto& field(*subscriptionContext->field);

        auto fieldValue(field.findIn(subscriptionContext->pGroupCtx->currentValue));

        log_debug_printf(_logname, "%s%s %s %s.%s\n", __func__, first ? " first" : "",
                         pChannel ? pChannel->name : "<null>",
                         subscriptionContext->pGroupCtx->group.name.c_str(), field.fullName.c_str());

        /* For a property update, we (may) only post changes to the field mapping
         * in question.  But never the triggered fields.
         */

        DBLocker L(dbChannelRecord(pChannel));
        LocalFieldLog localFieldLog(pChannel, pDbFieldLog);
        IOCSource::get(fieldValue, field.info, field.anyType,
                       UpdateType::Property, pChannel, pDbFieldLog);

        subscriptionPost(subscriptionContext->pGroupCtx);

    } catch(std::exception& e) {
        log_exc_printf(_logname, "Unhandled exception in %s\n", __func__);
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

    server::MonitorStat stats;
    groupSubscriptionCtx->subscriptionControl->stats(stats);
    // include actual negotiated queue size with initial update
    groupSubscriptionCtx->currentValue["record._options.queueSize"] = stats.limitQueue;
    groupSubscriptionCtx->currentValue["record._options.atomic"] = true;

    // Initialise the field subscription contexts.  One for each group field.
    // This is stored in the group context
    groupSubscriptionCtx->fieldSubscriptionContexts.reserve(groupSubscriptionCtx->group.fields.size());
    for (auto& field: groupSubscriptionCtx->group.fields) {
        groupSubscriptionCtx->fieldSubscriptionContexts.emplace_back(field, groupSubscriptionCtx.get());
        auto& fieldSubscriptionContext = groupSubscriptionCtx->fieldSubscriptionContexts.back();

        if(field.info.type == MappingInfo::Const) {
            auto fld(field.findIn(groupSubscriptionCtx->currentValue));
            // only populate const values once
            fld.assign(field.info.cval);
            continue; // nothing to subscribe

        } else if(!field.value) {
            continue; // no associated dbChannel
        }

        auto leafNode = field.findIn(groupSubscriptionCtx->currentValue);
        IOCSource::initialize(leafNode, field.info, field.value);

        // Two subscription are made for each group channel for pvxs
        // one for value|alarm changes
        if (field.info.type == MappingInfo::Meta) {
            fieldSubscriptionContext
                    .subscribeField(eventContext.get(), subscriptionValueCallback, DBE_ALARM);
        } else {
            fieldSubscriptionContext
                    .subscribeField(eventContext.get(), subscriptionValueCallback, DBE_VALUE | DBE_ALARM | DBE_ARCHIVE);
        }
        // one for property changes
        if (field.info.type == MappingInfo::Meta || field.info.type == MappingInfo::Scalar) {
            // only scalar and meta mappings include property metadata (display, control, ...)
            fieldSubscriptionContext
                    .subscribeField(eventContext.get(), subscriptionPropertiesCallback, DBE_PROPERTY, false);
        } else {
            fieldSubscriptionContext.hadPropertyEvent = true;
        }
    }

    // If all goes well, set up handlers for start and stop monitoring events
    // The group subscription context is being kept alive because it is being bound into some internal storage by onStart
    groupSubscriptionCtx->subscriptionControl->onStart([groupSubscriptionCtx](bool isStarting) {
        onStart(groupSubscriptionCtx, isStarting);
    });
}

static
bool getGroupField(const Field& field, Value valueTarget, const std::string& groupName,
        const std::unique_ptr<server::ExecOp>& getOperation) {
    try {
        IOCSource::initialize(valueTarget, field.info, field.value);
        LocalFieldLog localFieldLog(field.value);
        IOCSource::get(valueTarget, field.info, field.anyType,
                       UpdateType::Everything, field.value, localFieldLog.pFieldLog);
    } catch (std::exception& e) {
        std::stringstream errorString;
        errorString << "Error retrieving value for pvName: " << groupName << (field.name.empty() ? "/" : ".")
                    << field.fullName << " : "
                    << e.what();
        getOperation->error(errorString.str());
        return false;
    }
    return true;
}

/**
 * Handle the get operation
 *
 * @param group the group to get
 * @param getOperation the current executing operation
 */
void GroupSource::get(Group& group, const std::unique_ptr<server::ExecOp>& getOperation) {
    bool atomic = group.atomicPutGet;
    getOperation->pvRequest()["record._options.atomic"].as(atomic);

    // Make an empty value to return
    auto returnValue(group.valueTemplate.cloneEmpty());
    returnValue["record._options.atomic"] = atomic;

    // If the group is configured for an atomic get operation,
    // then we need to get all the fields at once, so we lock them all together
    // and do the operation in one go
    if (atomic) {
        // Lock all the fields
        DBManyLocker G(group.value.lock);
        // Loop through all fields
        for (auto& field: group.fields) {
            if(field.info.type == MappingInfo::Proc || field.info.type==MappingInfo::Structure)
                continue;
            // find the leaf node in which to set the value
            auto leafNode = field.findIn(returnValue);

            if (!getGroupField(field, leafNode, group.name, getOperation)) {
                return;
            }
        }

        // Unlock the all group fields when the locker goes out of scope

    } else {
        // Otherwise, this is a non-atomic operation, and we need to `put` each field individually,
        // locking each of them independently of each other.

        // Loop through all fields
        for (auto& field: group.fields) {
            dbChannel* pDbChannel = field.value;

            // find the leaf node in which to set the value
            auto leafNode = field.findIn(returnValue);

            if (pDbChannel && leafNode) {
                // Lock this field
                DBLocker F(pDbChannel->addr.precord);
                if (!getGroupField(field, leafNode, group.name, getOperation)) {
                    return;
                }
            }
        }
    }

    // Send reply
    getOperation->reply(returnValue);
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
static
bool putGroupField(const Value& value,
                   const Field& field,
                   const SecurityClient& securityClient,
                   const GroupSecurityCache& groupSecurityCache) {
    // find the leaf node that the field refers to in the given value
    auto leafNode = field.findIn(value);
    bool marked = leafNode.isMarked() && field.value && field.info.putOrder!=std::numeric_limits<int64_t>::min();

    // If the field references a valid part of the given value then we can send it to the database
    if (marked) {
        IOCSource::doFieldPreProcessing(securityClient); // pre-process field
        IOCSource::put(field.value, leafNode, field.info);
    }
    if (marked || field.info.type==MappingInfo::Proc) {
        // Do processing if required
        IOCSource::doPostProcessing(field.value, groupSecurityCache.forceProcessing);
        return true;
    }
    return false;
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
        CurrentOp op(putOperation.get());

        bool atomic = group.atomicPutGet;
        putOperation->pvRequest()["record._options.atomic"].as(atomic);

        log_debug_printf(_logname, "%s %s\n", __func__, group.name.c_str());

        std::vector<SecurityLogger> securityLoggers(group.fields.size());

        // Prepare group put operation
        auto fieldIndex = 0;
        for (auto& field: group.fields) {
            if (dbChannel* pDbChannel = field.value) {
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

        bool didSomething = false;

        // If the group is configured for an atomic put operation,
        // then we need to put all the fields at once, so we lock them all together
        // and do the operation in one go
        if (atomic) {
            // Lock all the fields
            DBManyLocker G(group.value.lock);
            // Loop through all fields
            for (auto& field: group.fields) {
                // Put the field
                didSomething |= putGroupField(value, field,
                                              groupSecurityCache.securityClients[fieldIndex],
                                              groupSecurityCache);
                fieldIndex++;
            }

            // Unlock the all group fields when the locker goes out of scope

        } else {
            // Otherwise, this is a non-atomic operation, and we need to `put` each field individually,
            // locking each of them independently of each other.

            // Loop through all fields
            for (auto& field: group.fields) {
                dbChannel* pDbChannel = field.value;
                if(!pDbChannel)
                    continue;
                // Lock this field
                DBLocker F(pDbChannel->addr.precord);
                // Put the field
                didSomething |= putGroupField(value, field,
                                              groupSecurityCache.securityClients[fieldIndex],
                                              groupSecurityCache);
                fieldIndex++;
                // Unlock this field when locker goes out of scope
            }
        }

        if(!didSomething && value.isMarked(true, true)) {
            // not fields actually changed, but client intended to change something.
            throw std::runtime_error("No fields changed");
        }

    } catch (std::exception& e) {
        log_debug_printf(_logname, "%s %s remote error: %s\n",
                         __func__, group.name.c_str(), e.what());
        // Unlock all locked fields when lockers go out of scope
        // Post error message to put operation object
        putOperation->error(e.what());
        return;
    }

    // If all went ok then let the client know
    putOperation->reply();
}

} // ioc
} // pvxs
