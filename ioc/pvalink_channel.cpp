/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <alarm.h>
#include <sstream>

#include <pvxs/log.h>

#include "utilpvt.h"
#include "pvalink.h"
#include "dblocker.h"
#include "dbmanylocker.h"

DEFINE_LOGGER(_logger, "pvxs.ioc.link.channel");
DEFINE_LOGGER(_logupdate, "pvxs.ioc.link.channel.update");

int pvaLinkNWorkers = 1;

namespace pvxs {
namespace ioc {

linkGlobal_t *linkGlobal;


linkGlobal_t::linkGlobal_t()
    :queue()
    ,running(false)
    ,putReq(TypeDef(TypeCode::Struct, {
                        members::Struct("field", {}),
                        members::Struct("record", {
                            members::Struct("_options", {
                                members::Bool("block"),
                                members::String("process"),
                            }),
                        }),                       }).create())
    ,worker(*this,
            "pvxlink",
            epicsThreadGetStackSize(epicsThreadStackBig),
            // worker should be above PVA worker priority?
            epicsThreadPriorityMedium)
{
    // TODO respect pvaLinkNWorkers?
    worker.start();
}

linkGlobal_t::~linkGlobal_t()
{
}

void linkGlobal_t::run()
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

void linkGlobal_t::close()
{
    {
        Guard G(lock);
        workerStop = true;
    }
    queue.push(std::weak_ptr<epicsThreadRunable>());
    worker.exitWait();
}

DEFINE_INST_COUNTER(pvaLinkChannel);
DEFINE_INST_COUNTER(pvaLink);

bool pvaLinkChannel::LinkSort::operator()(const pvaLink *L, const pvaLink *R) const {
    if(L->monorder==R->monorder)
        return L < R;
    return L->monorder < R->monorder;
}

// being called with linkGlobal::lock held
pvaLinkChannel::pvaLinkChannel(const linkGlobal_t::channels_key_t &key, const Value& pvRequest)
    :key(key)
    ,pvRequest(pvRequest)
    ,AP(new AfterPut)
{}

pvaLinkChannel::~pvaLinkChannel() {
    {
        Guard G(linkGlobal->lock);
        linkGlobal->channels.erase(key);
    }

    Guard G(lock);

    assert(links.empty());
}

void pvaLinkChannel::open()
{
    Guard G(lock);

    op_mon = linkGlobal->provider_remote.monitor(key.first)
            .maskConnected(true)
            .maskDisconnected(false)
            .rawRequest(pvRequest)
            .event([this](const client::Subscription&)
    {
        log_debug_printf(_logger, "Monitor %s wakeup\n", key.first.c_str());
        try {
            linkGlobal->queue.push(shared_from_this());
        }catch(std::bad_weak_ptr&){
            log_err_printf(_logger, "channel '%s' open during dtor?", key.first.c_str());
        }
    })
            .exec();
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
                continue; // TODO: can't write empty array to scalar field Signal error

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
        // TODO: signal INVALID_ALARM ?
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
        linkGlobal->queue.push(self->AP);
    }
}

// call with channel lock held
void pvaLinkChannel::put(bool force)
{
    auto pvReq(linkGlobal->putReq.cloneEmpty()
               .update("record._options.block", !after_put.empty()));

    unsigned reqProcess = 0;
    bool doit = force;
    for(auto& link : links)
    {
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
        op_put = linkGlobal->provider_remote.put(key.first)
                .rawRequest(pvReq)
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

// caller has locked record
void pvaLinkChannel::ScanTrack::scan()
{
    if(check_passive && prec->scan!=0) {

    } else if (prec->pact) {
        if (prec->tpro)
            printf("%s: Active %s\n", epicsThreadGetNameSelf(), prec->name);
        prec->rpro = TRUE;

    } else {
        (void)dbProcess(prec);
    }
}

// Running from global WorkQueue thread
void pvaLinkChannel::run()
{
    {
        Guard G(lock);

        log_debug_printf(_logger,"Monitor %s work\n", this->key.first.c_str());

        Value top;
        try {
            top = op_mon->pop();
            if(!top) {
                log_debug_printf(_logger, "Monitor %s empty\n", this->key.first.c_str());
                return;
            }
            if(!connected) {
                // (re)connect implies type change
                log_debug_printf(_logger, "Monitor %s reconnect\n", this->key.first.c_str());

                root = top; // re-create cache
                connected = true;
                num_type_change++;

                for(auto link : links) {
                    link->onTypeChange();
                }

            } else { // update cache
                root.assign(top);
            }
            log_debug_printf(_logupdate, "Monitor %s value %s\n", this->key.first.c_str(),
                             std::string(SB()<<root.format().delta().arrayLimit(5u)).c_str());

        } catch(client::Disconnect& e) {
            log_debug_printf(_logger, "Monitor %s disconnect\n", this->key.first.c_str());
            
            connected = false;

            num_disconnect++;

            // cancel pending put operations
            op_put.reset();

            for(auto link : links) {
                link->onDisconnect();
                link->snap_time = e.time;
            }

            // Don't clear previous_root on disconnect.
            // while disconnected, we will provide the most recent value w/ LINK_ALARM

        } catch(std::exception& e) {
            log_exc_printf(_logger, "pvalinkChannel::run: Unexpected exception: %s\n", e.what());
        }

        if(links_changed) {
            // a link has been added or removed since the last update.
            // rebuild our cached list of records to (maybe) process.

            decltype(atomic_records) atomic, nonatomic;
            std::vector<dbCommon*> atomicrecs;

            for(auto link : links) {
                assert(link && link->alive);

                auto sou(link->scanOnUpdate());
                if(sou==pvaLink::scanOnUpdateNo)
                    continue;

                bool check_passive = sou==pvaLink::scanOnUpdatePassive;

                if(link->atomic) {
                    atomicrecs.push_back(link->plink->precord);
                    atomic.emplace_back(link->plink->precord, check_passive);
                } else {
                    nonatomic.emplace_back(link->plink->precord, check_passive);
                }
            }

            log_debug_printf(_logger, "Links changed, %zu with %zu atomic, %zu nonatomic\n",
                             links.size(), atomic.size(), nonatomic.size());

            atomic_lock = ioc::DBManyLock(atomicrecs);
            atomic_records = std::move(atomic);
            nonatomic_records = std::move(nonatomic);

            links_changed = false;
        }

        update_seq++;
        update_evt.signal();
        log_debug_printf(_logger, "%s Sequence point %u\n", key.first.c_str(), update_seq);
    }
    // unlock link

    if(!atomic_records.empty()) {
        ioc::DBManyLocker L(atomic_lock);
        for(auto& trac : atomic_records) {
            trac.scan();
        }
    }

    for(auto& trac : nonatomic_records) {
        ioc::DBLocker L(trac.prec);
        trac.scan();
    }

    log_debug_printf(_logger, "Requeueing %s\n", key.first.c_str());
    // re-queue until monitor queue is empty
    linkGlobal->queue.push(shared_from_this());
}

}} // namespace pvxs::ioc
