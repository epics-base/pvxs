/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUPSOURCE_H
#define PVXS_GROUPSOURCE_H

#include "dbeventcontextdeleter.h"
#include "groupsrcsubscriptionctx.h"
#include "iocsource.h"
#include "securityclient.h"

namespace pvxs {
namespace ioc {

class GroupSource : public server::Source {
public:
    GroupSource();
    void onCreate(std::unique_ptr<server::ChannelControl>&& channelControl) final;

/**
 * Implementation of the onList() interface of pvxs::server::Source to return a list of all records
 * managed by this source.
 *
 * @return all records managed by this source
 */
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

    IOCGroupConfig& config;

    // Handles all get, put and subscribe requests
    static void onOp(Group& group, std::unique_ptr<server::ConnectOp>&& channelConnectOperation);

    //////////////////////////////
    // Get
    //////////////////////////////
    static void get(Group& group, const std::unique_ptr<server::ExecOp>& getOperation);

    //////////////////////////////
    // Put
    //////////////////////////////
    static void putGroup(Group& group, std::unique_ptr<server::ExecOp>& putOperation, const Value& value,
            const GroupSecurityCache& groupSecurityCache);

    //////////////////////////////
    // Subscriptions
    //////////////////////////////
	static void onDisableSubscription(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx);
	static void onStartSubscription(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx);
	void onSubscribe(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx,
			std::unique_ptr<server::MonitorSetupOp>&& subscriptionOperation) const;
    static void onStart(const std::shared_ptr<GroupSourceSubscriptionCtx>& groupSubscriptionCtx, bool isStarting);
};

} // ioc
} // pvxs


#endif //PVXS_GROUPSOURCE_H
