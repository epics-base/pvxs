/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <string.h>

#include <alarm.h>

#include <pvxs/log.h>

#include "pvalink.h"

DEFINE_LOGGER(_logger, "ioc.pvalink.link");

namespace pvxlink {

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
        for(pvaLinkChannel::links_t::const_iterator it(lchan->links.begin()), end(lchan->links.end())
            ; it!=end; ++it)
        {
            const pvaLink *pval = *it;
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
    return lchan->state == pvaLinkChannel::Connected && lchan->root;
}

// caller must lock lchan->lock
Value pvaLink::getSubField(const char *name)
{
    Value ret;
    if(valid()) {
        if(fieldName.empty()) {
            // we access the top level struct
            ret = lchan->root[name];

        } else {
            // we access a sub-struct
            ret = lchan->root[fieldName];
            if(!ret) {
                // noop
            } else if(ret.type()!=TypeCode::Struct) {
                // addressed sub-field isn't a sub-structure
                if(strcmp(name, "value")!=0) {
                    // unless we are trying to fetch the "value", we fail here
                    ret = Value();
                }
            } else {
                ret = ret[name];
            }
        }
    }
    return ret;
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
    log_debug_printf(_logger, "%s type change\n", plink->precord->name);

    assert(lchan->state == pvaLinkChannel::Connected && lchan->root); // we should only be called when connected

    fld_value = getSubField("value");
    fld_seconds = getSubField("timeStamp.secondsPastEpoch");
    fld_nanoseconds = getSubField("timeStamp.nanoseconds");
    fld_severity = getSubField("alarm.severity");
    fld_display = getSubField("display");
    fld_control = getSubField("control");
    fld_valueAlarm = getSubField("valueAlarm");

    // build mask of all "changed" bits associated with our .value
    // CP/CPP input links will process this link only for updates where
    // the changed mask and proc_changed share at least one set bit.
//    if(fld_value) {
//        // bit for this field
//        proc_changed.set(fld_value->getFieldOffset());

//        // bits of all parent fields
//        for(const pvd::PVStructure* parent = fld_value->getParent(); parent; parent = parent->getParent()) {
//            proc_changed.set(parent->getFieldOffset());
//        }

//        if(fld_value->getField()->getType()==pvd::structure)
//        {
//            // bits of all child fields
//            const pvd::PVStructure *val = static_cast<const pvd::PVStructure*>(fld_value.get());
//            for(size_t i=val->getFieldOffset(), N=val->getNextFieldOffset(); i<N; i++)
//                proc_changed.set(i);
//        }
//    }
}

} // namespace pvalink
