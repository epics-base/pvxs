
#include <alarm.h>

#include <pv/reftrack.h>

#include "pvalink.h"

int pvaLinkNWorkers = 1;

namespace pvalink {

pvaGlobal_t *pvaGlobal;


pvaGlobal_t::pvaGlobal_t()
    :create(pvd::getPVDataCreate())
    ,queue("PVAL")
    ,running(false)
{
    // worker should be above PVA worker priority?
    queue.start(std::max(1, pvaLinkNWorkers), epicsThreadPriorityMedium);
}

pvaGlobal_t::~pvaGlobal_t()
{
}

size_t pvaLinkChannel::num_instances;
size_t pvaLink::num_instances;


bool pvaLinkChannel::LinkSort::operator()(const pvaLink *L, const pvaLink *R) const {
    if(L->monorder==R->monorder)
        return L < R;
    return L->monorder < R->monorder;
}

// being called with pvaGlobal::lock held
pvaLinkChannel::pvaLinkChannel(const pvaGlobal_t::channels_key_t &key, const pvd::PVStructure::const_shared_pointer& pvRequest)
    :key(key)
    ,pvRequest(pvRequest)
    ,num_disconnect(0u)
    ,num_type_change(0u)
    ,connected(false)
    ,connected_latched(false)
    ,isatomic(false)
    ,queued(false)
    ,debug(false)
    ,links_changed(false)
    ,AP(new AfterPut)
{}

pvaLinkChannel::~pvaLinkChannel() {
    {
        Guard G(pvaGlobal->lock);
        pvaGlobal->channels.erase(key);
    }

    Guard G(lock);

    assert(links.empty());
    REFTRACE_DECREMENT(num_instances);
}

void pvaLinkChannel::open()
{
    Guard G(lock);

    try {
        chan = pvaGlobal->provider_local.connect(key.first);
        DEBUG(this, <<key.first<<" OPEN Local");
        providerName = pvaGlobal->provider_local.name();
    } catch(std::exception& e){
        // The PDBProvider doesn't have a way to communicate to us
        // whether this is an invalid record or group name,
        // or if this is some sort of internal error.
        // So we are forced to assume it is an invalid name.
        DEBUG(this, <<key.first<<" OPEN Not local "<<e.what());
    }
    if(!pvaLinkIsolate && !chan) {
        chan = pvaGlobal->provider_remote.connect(key.first);
        DEBUG(this, <<key.first<<" OPEN Remote ");
        providerName = pvaGlobal->provider_remote.name();
    }

    op_mon = chan.monitor(this, pvRequest);

    REFTRACE_INCREMENT(num_instances);
}

static
pvd::StructureConstPtr putRequestType = pvd::getFieldCreate()->createFieldBuilder()
        ->addNestedStructure("field")
        ->endNested()
        ->addNestedStructure("record")
            ->addNestedStructure("_options")
                ->add("block", pvd::pvBoolean)
                ->add("process", pvd::pvString) // "true", "false", or "passive"
            ->endNested()
        ->endNested()
        ->createStructure();

// call with channel lock held
void pvaLinkChannel::put(bool force)
{
    pvd::PVStructurePtr pvReq(pvd::getPVDataCreate()->createPVStructure(putRequestType));
    pvReq->getSubFieldT<pvd::PVBoolean>("record._options.block")->put(!after_put.empty());

    unsigned reqProcess = 0;
    bool doit = force;
    for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
    {
        pvaLink *link = *it;

        if(!link->used_scratch) continue;

        pvd::shared_vector<const void> temp;
        temp.swap(link->put_scratch);
        link->used_scratch = false;
        temp.swap(link->put_queue);
        link->used_queue = true;

        doit = true;

        switch(link->pp) {
        case pvaLink::NPP:
            reqProcess |= 1;
            break;
        case pvaLink::Default:
            break;
        case pvaLink::PP:
        case pvaLink::CP:
        case pvaLink::CPP:
            reqProcess |= 2;
            break;
        }
    }

    /* By default, use remote default (passive).
     * Request processing, or not, if any link asks.
     * Prefer PP over NPP if both are specified.
     *
     * TODO: per field granularity?
     */
    const char *proc = "passive";
    if((reqProcess&2) || force) {
        proc = "true";
    } else if(reqProcess&1) {
        proc = "false";
    }
    pvReq->getSubFieldT<pvd::PVString>("record._options.process")->put(proc);

    DEBUG(this, <<key.first<<"Start put "<<doit);
    if(doit) {
        // start net Put, cancels in-progress put
        op_put = chan.put(this, pvReq);
    }
}

void pvaLinkChannel::putBuild(const epics::pvData::StructureConstPtr& build, pvac::ClientChannel::PutCallback::Args& args)
{
    Guard G(lock);

    pvd::PVStructurePtr top(pvaGlobal->create->createPVStructure(build));

    for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
    {
        pvaLink *link = *it;

        if(!link->used_queue) continue;
        link->used_queue = false; // clear early so unexpected exception won't get us in a retry loop

        pvd::PVFieldPtr value(link->fieldName.empty() ? pvd::PVFieldPtr(top) : top->getSubField(link->fieldName));
        if(value && value->getField()->getType()==pvd::structure) {
            // maybe drill into NTScalar et al.
            pvd::PVFieldPtr sub(static_cast<pvd::PVStructure*>(value.get())->getSubField("value"));
            if(sub)
                value.swap(sub);
        }

        if(!value) continue; // TODO: how to signal error?

        pvd::PVStringArray::const_svector choices; // TODO populate from op_mon

        DEBUG(this, <<key.first<<" <- "<<value->getFullName());
        copyDBF2PVD(link->put_queue, value, args.tosend, choices);

        link->put_queue.clear();
    }
    DEBUG(this, <<key.first<<" Put built");

    args.root = top;
}

namespace {
// soo much easier with c++11 std::shared_ptr...
struct AFLinker {
    std::tr1::shared_ptr<pvaLinkChannel> chan;
    AFLinker(const std::tr1::shared_ptr<pvaLinkChannel>& chan) :chan(chan) {}
    void operator()(pvaLinkChannel::AfterPut *) {
        chan.reset();
    }
};
} // namespace

void pvaLinkChannel::putDone(const pvac::PutEvent& evt)
{
    if(evt.event==pvac::PutEvent::Fail) {
        errlogPrintf("%s PVA link put ERROR: %s\n", key.first.c_str(), evt.message.c_str());
    }

    bool needscans;
    {
        Guard G(lock);

        DEBUG(this, <<key.first<<" Put result "<<evt.event);

        needscans = !after_put.empty();
        op_put = pvac::Operation();

        if(evt.event==pvac::PutEvent::Success) {
            // see if we need start a queue'd put
            put();
        }
    }

    if(needscans) {
        pvaGlobal->queue.add(AP);
    }
}

void pvaLinkChannel::AfterPut::run()
{
    std::set<dbCommon*> toscan;
    std::tr1::shared_ptr<pvaLinkChannel> link(lc.lock());
    if(!link)
        return;

    {
        Guard G(link->lock);
        toscan.swap(link->after_put);
    }

    for(after_put_t::iterator it=toscan.begin(), end=toscan.end();
        it!=end; ++it)
    {
        dbCommon *prec = *it;
        dbScanLock(prec);
        if(prec->pact) { // complete async. processing
            (prec)->rset->process(prec);

        } else {
            // maybe the result of "cancellation" or some record support logic error?
            errlogPrintf("%s : not PACT when async PVA link completed.  Logic error?\n", prec->name);
        }
        dbScanUnlock(prec);
    }

}

void pvaLinkChannel::monitorEvent(const pvac::MonitorEvent& evt)
{
    bool queue = false;

    {
        DEBUG(this, <<key.first<<" EVENT "<<evt.event);
        Guard G(lock);

        switch(evt.event) {
        case pvac::MonitorEvent::Disconnect:
        case pvac::MonitorEvent::Data:
            connected = evt.event == pvac::MonitorEvent::Data;
            queue = true;
            break;
        case pvac::MonitorEvent::Cancel:
            break; // no-op
        case pvac::MonitorEvent::Fail:
            connected = false;
            queue = true;
            errlogPrintf("%s: PVA link monitor ERROR: %s\n", chan.name().c_str(), evt.message.c_str());
            break;
        }

        if(queued)
            return; // already scheduled

        queued = queue;
    }

    if(queue) {
        pvaGlobal->queue.add(shared_from_this());
    }
}

// the work in calling dbProcess() which is common to
// both dbScanLock() and dbScanLockMany()
void pvaLinkChannel::run_dbProcess(size_t idx)
{
    dbCommon *precord = scan_records[idx];

    if(scan_check_passive[idx] && precord->scan!=0) {
        return;

    } else if(connected_latched && !op_mon.changed.logical_and(scan_changed[idx])) {
        return;

    } else if (precord->pact) {
        if (precord->tpro)
            printf("%s: Active %s\n",
                epicsThreadGetNameSelf(), precord->name);
        precord->rpro = TRUE;

    }
    dbProcess(precord);
}

// Running from global WorkQueue thread
void pvaLinkChannel::run()
{
    bool requeue = false;
    {
        Guard G(lock);

        queued = false;

        connected_latched = connected;

        // pop next update from monitor queue.
        // still under lock to safeguard concurrent calls to lset functions
        if(connected && !op_mon.poll()) {
            DEBUG(this, <<key.first<<" RUN "<<"empty");
            run_done.signal();
            return; // monitor queue is empty, nothing more to do here
        }

        DEBUG(this, <<key.first<<" RUN "<<(connected_latched?"connected":"disconnected"));

        assert(!connected || !!op_mon.root);

        if(!connected) {
            num_disconnect++;

            // cancel pending put operations
            op_put = pvac::Operation();

            for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
            {
                pvaLink *link = *it;
                link->onDisconnect();
            }

            // Don't clear previous_root on disconnect.
            // We will usually re-connect with the same type,
            // and may get back the same PVStructure.

        } else if(previous_root.get() != (const void*)op_mon.root.get()) {
            num_type_change++;

            for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
            {
                pvaLink *link = *it;
                link->onTypeChange();
            }

            previous_root = std::tr1::static_pointer_cast<const void>(op_mon.root);
        }

        // at this point we know we will re-queue, but not immediately
        // so an expected error won't get us stuck in a tight loop.
        requeue = queued = connected_latched;

        if(links_changed) {
            // a link has been added or removed since the last update.
            // rebuild our cached list of records to (maybe) process.

            scan_records.clear();
            scan_check_passive.clear();
            scan_changed.clear();

            for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
            {
                pvaLink *link = *it;
                assert(link && link->alive);

                if(!link->plink) continue;

                // only scan on monitor update for input links
                if(link->type!=DBF_INLINK)
                    continue;

                // NPP and none/Default don't scan
                // PP, CP, and CPP do scan
                // PP and CPP only if SCAN=Passive
                if(link->pp != pvaLink::PP && link->pp != pvaLink::CPP && link->pp != pvaLink::CP)
                    continue;

                scan_records.push_back(link->plink->precord);
                scan_check_passive.push_back(link->pp != pvaLink::CP);
                scan_changed.push_back(link->proc_changed);
            }

            DBManyLock ML(scan_records);

            atomic_lock.swap(ML);

            links_changed = false;
        }
    }

    if(scan_records.empty()) {
        // Nothing to do, so don't bother locking

    } else if(isatomic && scan_records.size() > 1u) {
        DBManyLocker L(atomic_lock);

        for(size_t i=0, N=scan_records.size(); i<N; i++) {
            run_dbProcess(i);
        }

    } else {
        for(size_t i=0, N=scan_records.size(); i<N; i++) {
            DBScanLocker L(scan_records[i]);
            run_dbProcess(i);
        }
    }

    if(requeue) {
        // re-queue until monitor queue is empty
        pvaGlobal->queue.add(shared_from_this());
    } else {
        run_done.signal();
    }
}

} // namespace pvalink
