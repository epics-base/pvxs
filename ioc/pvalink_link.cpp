#include <pv/reftrack.h>
#include <alarm.h>

#include "pvalink.h"

namespace pvalink {

pvaLink::pvaLink()
    :alive(true)
    ,type((dbfType)-1)
    ,plink(0)
    ,used_scratch(false)
    ,used_queue(false)
{
    REFTRACE_INCREMENT(num_instances);

    snap_severity = INVALID_ALARM;
    snap_time.secPastEpoch = 0;
    snap_time.nsec = 0;

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

    REFTRACE_DECREMENT(num_instances);
}

static
pvd::StructureConstPtr monitorRequestType = pvd::getFieldCreate()->createFieldBuilder()
        ->addNestedStructure("field")
        ->endNested()
        ->addNestedStructure("record")
            ->addNestedStructure("_options")
                ->add("pipeline", pvd::pvBoolean)
                ->add("atomic", pvd::pvBoolean)
                ->add("queueSize", pvd::pvUInt)
            ->endNested()
        ->endNested()
        ->createStructure();

pvd::PVStructurePtr pvaLink::makeRequest()
{
    pvd::PVStructurePtr ret(pvd::getPVDataCreate()->createPVStructure(monitorRequestType));
    ret->getSubFieldT<pvd::PVBoolean>("record._options.pipeline")->put(pipeline);
    ret->getSubFieldT<pvd::PVBoolean>("record._options.atomic")->put(true);
    ret->getSubFieldT<pvd::PVUInt>("record._options.queueSize")->put(queueSize);
    return ret;
}

// caller must lock lchan->lock
bool pvaLink::valid() const
{
    return lchan->connected_latched && lchan->op_mon.root;
}

// caller must lock lchan->lock
pvd::PVField::const_shared_pointer pvaLink::getSubField(const char *name)
{
    pvd::PVField::const_shared_pointer ret;
    if(valid()) {
        if(fieldName.empty()) {
            // we access the top level struct
            ret = lchan->op_mon.root->getSubField(name);

        } else {
            // we access a sub-struct
            ret = lchan->op_mon.root->getSubField(fieldName);
            if(!ret) {
                // noop
            } else if(ret->getField()->getType()!=pvd::structure) {
                // addressed sub-field isn't a sub-structure
                if(strcmp(name, "value")!=0) {
                    // unless we are trying to fetch the "value", we fail here
                    ret.reset();
                }
            } else {
                ret = static_cast<const pvd::PVStructure*>(ret.get())->getSubField(name);
            }
        }
    }
    return ret;
}

// call with channel lock held
void pvaLink::onDisconnect()
{
    DEBUG(this,<<plink->precord->name<<" disconnect");
    // TODO: option to remain queue'd while disconnected

    used_queue = used_scratch = false;
}

void pvaLink::onTypeChange()
{
    DEBUG(this,<<plink->precord->name<<" type change");

    assert(lchan->connected_latched && !!lchan->op_mon.root); // we should only be called when connected

    fld_value = getSubField("value");
    fld_seconds = std::tr1::dynamic_pointer_cast<const pvd::PVScalar>(getSubField("timeStamp.secondsPastEpoch"));
    fld_nanoseconds = std::tr1::dynamic_pointer_cast<const pvd::PVScalar>(getSubField("timeStamp.nanoseconds"));
    fld_severity = std::tr1::dynamic_pointer_cast<const pvd::PVScalar>(getSubField("alarm.severity"));
    fld_display = std::tr1::dynamic_pointer_cast<const pvd::PVStructure>(getSubField("display"));
    fld_control = std::tr1::dynamic_pointer_cast<const pvd::PVStructure>(getSubField("control"));
    fld_valueAlarm = std::tr1::dynamic_pointer_cast<const pvd::PVStructure>(getSubField("valueAlarm"));

    proc_changed.clear();

    // build mask of all "changed" bits associated with our .value
    // CP/CPP input links will process this link only for updates where
    // the changed mask and proc_changed share at least one set bit.
    if(fld_value) {
        // bit for this field
        proc_changed.set(fld_value->getFieldOffset());

        // bits of all parent fields
        for(const pvd::PVStructure* parent = fld_value->getParent(); parent; parent = parent->getParent()) {
            proc_changed.set(parent->getFieldOffset());
        }

        if(fld_value->getField()->getType()==pvd::structure)
        {
            // bits of all child fields
            const pvd::PVStructure *val = static_cast<const pvd::PVStructure*>(fld_value.get());
            for(size_t i=val->getFieldOffset(), N=val->getNextFieldOffset(); i<N; i++)
                proc_changed.set(i);
        }
    }
}

} // namespace pvalink
