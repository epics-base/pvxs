/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <string.h>

#include <alarm.h>

#include <pvxs/log.h>

#include "pvalink.h"

DEFINE_LOGGER(_logger, "pvxs.ioc.link.link");

namespace pvxs {
namespace ioc {

pvaLink::pvaLink()
{
    //TODO: valgrind tells me these aren't initialized by Base, but probably should be.
    parseDepth = 0;
    parent = 0;
}

pvaLink::~pvaLink()
{
    alive = false;

    if(lchan) { // may be NULL if parsing fails
        Guard G(lchan->lock);

        lchan->links.erase(this);
        lchan->links_changed = true;

        bool new_debug = false;
        for(auto pval : lchan->links) {
            if(pval->debug) {
                new_debug = true;
                break;
            }
        }

        lchan->debug = new_debug;
    }
}

Value pvaLink::makeRequest()
{
    // TODO: cache TypeDef in global
    using namespace pvxs::members;
    return TypeDef(TypeCode::Struct, {
                       Struct("field", {}),
                       Struct("record", {
                           Struct("_options", {
                               Bool("pipeline"),
                               Bool("atomic"),
                               UInt32("queueSize"),
                           }),
                       }),
                   }).create()
            .update("record._options.pipeline", pipeline)
            .update("record._options.atomic", true)
            .update("record._options.queueSize", uint32_t(queueSize));
}

// caller must lock lchan->lock
bool pvaLink::valid() const
{
    return lchan->connected && lchan->root;
}

// call with channel lock held
void pvaLink::onDisconnect()
{
    log_debug_printf(_logger, "%s disconnect\n", plink->precord->name);
    // TODO: option to remain queue'd while disconnected

    used_queue = used_scratch = false;
}

void pvaLink::onTypeChange()
{
    assert(lchan->connected && lchan->root); // we should only be called when connected

    fld_value = fld_severity = fld_nanoseconds = fld_usertag
            = fld_message = fld_severity = fld_meta = Value();

    Value root;
    if(fieldName.empty()) {
        root = lchan->root;
    } else {
        root = lchan->root[fieldName];
    }
    if(!root) {
        log_warn_printf(_logger, "%s has no %s\n", lchan->key.first.c_str(), fieldName.c_str());

    } else if(root.type()!=TypeCode::Struct) {
        log_debug_printf(_logger, "%s has no meta\n", lchan->key.first.c_str());
        fld_value = root;

    } else {
        fld_value = root["value"];
        fld_seconds = root["timeStamp.secondsPastEpoch"];
        fld_nanoseconds = root["timeStamp.nanoseconds"];
        fld_usertag = root["timeStamp.userTag"];
        fld_severity = root["alarm.severity"];
        fld_message = root["alarm.message"];
        fld_meta = std::move(root);
    }

    log_debug_printf(_logger, "%s type change V=%c S=%c N=%c S=%c M=%c\n",
                     plink->precord->name,
                     fld_value ? 'Y' : 'N',
                     fld_seconds ? 'Y' : 'N',
                     fld_nanoseconds ? 'Y' : 'N',
                     fld_severity ? 'Y' : 'N',
                     fld_meta ? 'Y' : 'N');
}

pvaLink::scanOnUpdate_t pvaLink::scanOnUpdate() const
{
    if(!plink)
        return scanOnUpdateNo;
    if(type!=DBF_INLINK)
        return scanOnUpdateNo;
    if(proc == pvaLink::CP)
        return scanOnUpdateYes;
    if(proc == pvaLink::CPP)
        return scanOnUpdatePassive;
    return scanOnUpdateNo;
}

}} // namespace pvxs::ioc
