/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include "singlesrcsubscriptionctx.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {

DEFINE_INST_COUNTER(SingleSourceSubscriptionCtx);

/**
 * Constructor for single source subscription context using a pointer to a db channel
 *
 * @param dbChannelSharedPtr pointer to the db channel to use to construct the single source subscription context
 */
SingleSourceSubscriptionCtx::SingleSourceSubscriptionCtx(const std::shared_ptr<SingleInfo> &sInfo)
    :pPropertiesChannel(dbChannelName(sInfo->chan))
    ,info(sInfo)
{}
} // iocs
} // pvxs
