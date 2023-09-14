/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <alarm.h>
#include <sstream>

#include <pvxs/log.h>

#include "pvalink.h"
#include "dblocker.h"
#include "dbmanylocker.h"

DEFINE_LOGGER(_logger, "ioc.pvalink.channel");

int pvaLinkNWorkers = 1;

namespace pvxlink {
using namespace pvxs;

pvaGlobal_t *pvaGlobal;


pvaGlobal_t::pvaGlobal_t()
    :queue()
    ,running(false)
    ,worker(*this,
            "pvxlink",
            epicsThreadGetStackSize(epicsThreadStackBig),
            // worker should be above PVA worker priority?
            epicsThreadPriorityMedium)
{
    // TODO respect pvaLinkNWorkers?
    worker.start();
}

pvaGlobal_t::~pvaGlobal_t()
{
}

void pvaGlobal_t::run()
{
    while(1) {
        auto w = queue.pop();
        if(auto chan = w.lock()) {
            chan->run();
        }
        {
            Guard G(lock);
            if(workerStop)
                break;
        }
    }

}

void pvaGlobal_t::close()
{
    {
        Guard G(lock);
        workerStop = true;
    }
    queue.push(std::weak_ptr<epicsThreadRunable>());
    worker.exitWait();
}

size_t pvaLinkChannel::num_instances;
size_t pvaLink::num_instances;


bool pvaLinkChannel::LinkSort::operator()(const pvaLink *L, const pvaLink *R) const {
    if(L->monorder==R->monorder)
        return L < R;
    return L->monorder < R->monorder;
}

// being called with pvaGlobal::lock held
pvaLinkChannel::pvaLinkChannel(const pvaGlobal_t::channels_key_t &key, const Value& pvRequest)
    :key(key)
    ,pvRequest(pvRequest)
    ,AP(new AfterPut)
{}

pvaLinkChannel::~pvaLinkChannel() {
    {
        Guard G(pvaGlobal->lock);
        pvaGlobal->channels.erase(key);
    }

    Guard G(lock);

    assert(links.empty());
}

void pvaLinkChannel::open()
{
    Guard G(lock);

    op_mon = pvaGlobal->provider_remote.monitor(key.first)
            .maskConnected(true)
            .maskDisconnected(false)
            .rawRequest(pvRequest)
            .event([this](const client::Subscription&)
    {
        log_debug_printf(_logger, "Received message: %s %s\n", key.first.c_str(), key.second.c_str());
        pvaGlobal->queue.push(shared_from_this());
    })
            .exec();
    providerName = "remote";
}

static
Value linkBuildPut(pvaLinkChannel *self, Value&& prototype)
{
    Guard G(self->lock);

    auto top(std::move(prototype));

    for(auto link : self->links)
    {
        if(!link->used_queue) continue;
        link->used_queue = false; // clear early so unexpected exception won't get us in a retry loop

        auto value(link->fieldName.empty() ? top : top[link->fieldName]);
        if(value.type()==TypeCode::Struct) {
            // maybe drill into NTScalar et al.
            if(auto sub = value["value"])
                value = std::move(sub);
        }

        if(!value) continue; // TODO: how to signal error?

        auto tosend(std::move(link->put_queue));

        if(value.type().isarray()) {
            value = tosend;
        } else {
            if (tosend.empty())
                continue; // TODO: Signal error

            if (value.type() == TypeCode::Struct && value.id() == "enum_t") {
                value = value["index"]; // We want to assign to the index for enum types
            }

            switch (tosend.original_type())
            {
            case ArrayType::Int8:    value = tosend.castTo<const int8_t>()[0]; break;
            case ArrayType::Int16:   value = tosend.castTo<const int16_t>()[0]; break;
            case ArrayType::Int32:   value = tosend.castTo<const int32_t>()[0]; break;
            case ArrayType::Int64:   value = tosend.castTo<const int64_t>()[0]; break;
            case ArrayType::UInt8:   value = tosend.castTo<const uint8_t>()[0]; break;
            case ArrayType::UInt16:  value = tosend.castTo<const uint16_t>()[0]; break;
            case ArrayType::UInt32:  value = tosend.castTo<const uint32_t>()[0]; break;
            case ArrayType::UInt64:  value = tosend.castTo<const uint64_t>()[0]; break;
            case ArrayType::Float32: value = tosend.castTo<const float>()[0]; break;
            case ArrayType::Float64: value = tosend.castTo<const double>()[0]; break;
            case ArrayType::String:  value = tosend.castTo<const std::string>()[0]; break;
            case ArrayType::Bool:
            case ArrayType::Null:
            case ArrayType::Value:
                std::ostringstream buffer;
                buffer << tosend.original_type();
                log_exc_printf(_logger, "Unsupported type %s\n", buffer.str().c_str());
            }
        }
    }
    log_debug_printf(_logger, "%s put built\n", self->key.first.c_str());

    return top;
}

void linkPutDone(pvaLinkChannel *self, client::Result&& result)
{
    bool ok = false;
    try {
        result();
        ok = true;
    }catch(std::exception& e){
        errlogPrintf("%s PVA link put ERROR: %s\n", self->key.first.c_str(), e.what());
    }

    bool needscans;
    {
        Guard G(self->lock);

        log_debug_printf(_logger, "%s put result %s\n", self->key.first.c_str(), ok ? "OK" : "Not OK");

        needscans = !self->after_put.empty();
        self->op_put.reset();

        if(ok) {
            // see if we need start a queue'd put
            self->put();
        }
    }

    log_debug_printf(_logger, "linkPutDone: %s, needscans = %i\n", self->key.first.c_str(), needscans);

    if(needscans) {
        pvaGlobal->queue.push(self->AP);
    }
}

// call with channel lock held
void pvaLinkChannel::put(bool force)
{
    // TODO cache TypeDef in global
    using namespace pvxs::members;
    auto pvReq(TypeDef(TypeCode::Struct, {
                           Struct("field", {}),
                           Struct("record", {
                               Struct("_options", {
                                   Bool("block"),
                                   String("process"),
                               }),
                           }),                       }).create()
               .update("record._options.block", !after_put.empty()));

    unsigned reqProcess = 0;
    bool doit = force;
    for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
    {
        pvaLink *link = *it;

        if(!link->used_scratch) continue;

        link->put_queue = std::move(link->put_scratch);
        link->used_scratch = false;
        link->used_queue = true;

        doit = true;

        switch(link->proc) {
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
    pvReq["record._options.process"] = proc;

    log_debug_printf(_logger, "%s Start put %s\n", key.first.c_str(), doit ? "true": "false");
    if(doit) {
        // start net Put, cancels in-progress put
        op_put = pvaGlobal->provider_remote.put(key.first)
                .build([this](Value&& prototype) -> Value
        {
                return linkBuildPut(this, std::move(prototype)); // TODO
        })
                .result([this](client::Result&& result)
        {
            linkPutDone(this, std::move(result));
        })
                .exec();
    }
}

void pvaLinkChannel::AfterPut::run()
{
    std::set<dbCommon*> toscan;
    std::shared_ptr<pvaLinkChannel> link(lc.lock());
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
        log_debug_printf(_logger, "AfterPut start processing %s\n", prec->name);
        if(prec->pact) { // complete async. processing
            (prec)->rset->process(prec);

        } else {
            // maybe the result of "cancellation" or some record support logic error?
            errlogPrintf("%s : not PACT when async PVA link completed.  Logic error?\n", prec->name);
        }
        dbScanUnlock(prec);
    }

}

// the work in calling dbProcess() which is common to
// both dbScanLock() and dbScanLockMany()
void pvaLinkChannel::run_dbProcess(size_t idx)
{
    dbCommon *precord = scan_records[idx];

    if(scan_check_passive[idx] && precord->scan!=0) {
        return;

    // TODO: This relates to caching of the individual links and comparing it to
    //       the posted monitor. This is, as I understand it, an optimisation and
    //       we can sort of ignore it for now.
    //} else if(state_latched == Connected && !op_mon.changed.logical_and(scan_changed[idx])) {
    //    return;

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

        log_debug_printf(_logger,"Running task %s\n", this->key.first.c_str());

        Value top;
        try {
            top = op_mon->pop();
            if(!top) {
                log_debug_printf(_logger, "Queue empty %s\n", this->key.first.c_str());
                run_done.signal();
                return;
            }
            state = Connected;
        } catch(client::Disconnect&) {
            log_debug_printf(_logger, "PVA link %s received disonnection event\n", this->key.first.c_str());
            
            state = Disconnected;

            num_disconnect++;

            // cancel pending put operations
            op_put.reset();

            for(links_t::iterator it(links.begin()), end(links.end()); it!=end; ++it)
            {
                pvaLink *link = *it;
                link->onDisconnect();
            }

            // Don't clear previous_root on disconnect.
            // We will usually re-connect with the same type,
            // and may get back the same PVStructure.

        } catch(std::exception& e) {
            errlogPrintf("pvalinkChannel::run: Unexpected exception while reading from monitor queue: %s\n", e.what());
        }

        if (state == Connected) {
            // Fetch the data from the incoming monitor
            if (root.equalType(top))
            {
                log_debug_printf(_logger, "pvalinkChannel update value %s\n", this->key.first.c_str());

                root.assign(top);
            }
            else
            {
                log_debug_printf(_logger, "pvalinkChannel %s update type\n", this->key.first.c_str());
                root = top;
                num_type_change++;

                for (links_t::iterator it(links.begin()), end(links.end()); it != end; ++it)
                {
                    pvaLink *link = *it;
                    link->onTypeChange();
                }
            }

            requeue = true;
        } 

        if(links_changed) {
            // a link has been added or removed since the last update.
            // rebuild our cached list of records to (maybe) process.

            scan_records.clear();
            scan_check_passive.clear();

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
                if(link->proc != pvaLink::PP && link->proc != pvaLink::CPP && link->proc != pvaLink::CP)
                    continue;

                scan_records.push_back(link->plink->precord);
                scan_check_passive.push_back(link->proc != pvaLink::CP);
            }

            log_debug_printf(_logger, "Links changed, scan_records size = %lu\n", scan_records.size());

            atomic_lock = ioc::DBManyLock(scan_records);

            links_changed = false;
        }
    }

    if(scan_records.empty()) {
        // Nothing to do, so don't bother locking

    } else if(isatomic && scan_records.size() > 1u) {
        ioc::DBManyLocker L(atomic_lock);

        for(size_t i=0, N=scan_records.size(); i<N; i++) {
            run_dbProcess(i);
        }

    } else {
        for(size_t i=0, N=scan_records.size(); i<N; i++) {
            log_debug_printf(_logger, "Processing %s\n", scan_records[i]->name);

            ioc::DBLocker L(scan_records[i]);
            run_dbProcess(i);
        }
    }

    if(requeue) {
        log_debug_printf(_logger, "Requeueing %s\n", key.first.c_str());
        // re-queue until monitor queue is empty
        pvaGlobal->queue.push(shared_from_this());
    } else {
        log_debug_printf(_logger, "Run done instead of requeue %s\n", key.first.c_str());
        run_done.signal();
    }
}

} // namespace pvalink
