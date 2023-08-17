
#include <epicsString.h>
#include <alarm.h>
#include <recGbl.h>
#include <epicsStdio.h> // redirect stdout/stderr

#include <pv/current_function.h>

#include "pvalink.h"


namespace {

using namespace pvalink;

#define TRY pvaLink *self = static_cast<pvaLink*>(plink->value.json.jlink); assert(self->alive); try
#define CATCH() catch(std::exception& e) { \
    errlogPrintf("pvaLink %s fails %s: %s\n", CURRENT_FUNCTION, plink->precord->name, e.what()); \
}

#define CHECK_VALID() if(!self->valid()) { DEBUG(self, <<CURRENT_FUNCTION<<" "<<self->channelName<<" !valid"); return -1;}

dbfType getLinkType(DBLINK *plink)
{
    dbCommon *prec = plink->precord;
    pdbRecordIterator iter(prec);

    for(long status = dbFirstField(&iter.ent, 0); !status; status = dbNextField(&iter.ent, 0)) {
        if(iter.ent.pfield==plink)
            return iter.ent.pflddes->field_type;
    }
    throw std::logic_error("DBLINK* corrupt");
}

void pvaOpenLink(DBLINK *plink)
{
    try {
        pvaLink* self((pvaLink*)plink->value.json.jlink);
        self->type = getLinkType(plink);

        // workaround for Base not propagating info(base:lsetDebug to us
        {
            pdbRecordIterator rec(plink->precord);

            if(epicsStrCaseCmp(rec.info("base:lsetDebug", "NO"), "YES")==0) {
                self->debug = 1;
            }
        }

        DEBUG(self, <<plink->precord->name<<" OPEN "<<self->channelName);

        // still single threaded at this point.
        // also, no pvaLinkChannel::lock yet

        self->plink = plink;

        if(self->channelName.empty())
            return; // nothing to do...

        pvd::PVStructure::const_shared_pointer pvRequest(self->makeRequest());
        pvaGlobal_t::channels_key_t key;

        {
            std::ostringstream strm;
            strm<<*pvRequest; // print the request as a convient key for our channel cache

            key = std::make_pair(self->channelName, strm.str());
        }

        std::tr1::shared_ptr<pvaLinkChannel> chan;
        bool doOpen = false;
        {
            Guard G(pvaGlobal->lock);

            pvaGlobal_t::channels_t::iterator it(pvaGlobal->channels.find(key));

            if(it!=pvaGlobal->channels.end()) {
                // re-use existing channel
                chan = it->second.lock();
            }

            if(!chan) {
                // open new channel

                chan.reset(new pvaLinkChannel(key, pvRequest));
                chan->AP->lc = chan;
                pvaGlobal->channels.insert(std::make_pair(key, chan));
                doOpen = true;
            }

            doOpen &= pvaGlobal->running; // if not running, then open from initHook
        }

        if(doOpen) {
            chan->open(); // start subscription
        }

        if(!self->local || chan->providerName=="QSRV"){
            Guard G(chan->lock);

            chan->links.insert(self);
            chan->links_changed = true;

            self->lchan.swap(chan); // we are now attached

            self->lchan->debug |= !!self->debug;
        } else {
            // TODO: only print duing iocInit()?
            fprintf(stderr, "%s Error: local:true link to '%s' can't be fulfilled\n",
                   plink->precord->name, self->channelName.c_str());
            plink->lset = NULL;
        }

        return;
    }CATCH()
    // on error, prevent any further calls to our lset functions
    plink->lset = NULL;
}

void pvaRemoveLink(struct dbLocker *locker, DBLINK *plink)
{
    try {
        p2p::auto_ptr<pvaLink> self((pvaLink*)plink->value.json.jlink);
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName);
        assert(self->alive);

    }CATCH()
}

int pvaIsConnected(const DBLINK *plink)
{
    TRY {
        Guard G(self->lchan->lock);

        bool ret = self->valid();
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<ret);
        return ret;

    }CATCH()
    return 0;
}

int pvaGetDBFtype(const DBLINK *plink)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        // if fieldName is empty, use top struct value
        // if fieldName not empty
        //    if sub-field is struct, use sub-struct .value
        //    if sub-field not struct, treat as value

        pvd::PVField::const_shared_pointer value(self->getSubField("value"));

        pvd::ScalarType ftype = pvd::pvInt; // default for un-mapable types.
        if(!value) {
            // no-op
        } else if(value->getField()->getType()==pvd::scalar)
            ftype = static_cast<const pvd::Scalar*>(value->getField().get())->getScalarType();
        else if(value->getField()->getType()==pvd::scalarArray)
            ftype = static_cast<const pvd::ScalarArray*>(value->getField().get())->getElementType();

        int ret;
        switch(ftype) {
#define CASE(BASETYPE, PVATYPE, DBFTYPE, PVACODE) case pvd::pv##PVACODE: ret = DBF_##DBFTYPE;
#define CASE_REAL_INT64
#include "pv/typemap.h"
#undef CASE_REAL_INT64
#undef CASE
        case pvd::pvString: ret = DBF_STRING; // TODO: long string?
        }

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<dbGetFieldTypeString(ret));
        return ret;

    }CATCH()
    return -1;
}

long pvaGetElements(const DBLINK *plink, long *nelements)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        long ret = 0;
        if(self->fld_value && self->fld_value->getField()->getType()==pvd::scalarArray)
            ret = static_cast<const pvd::PVScalarArray*>(self->fld_value.get())->getLength();

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<ret);

        return ret;
    }CATCH()
    return -1;
}

long pvaGetValue(DBLINK *plink, short dbrType, void *pbuffer,
        long *pnRequest)
{
    TRY {
        Guard G(self->lchan->lock);

        if(!self->valid()) {
            // disconnected
            if(self->ms != pvaLink::NMS) {
                recGblSetSevr(plink->precord, LINK_ALARM, self->snap_severity);
            }
            // TODO: better capture of disconnect time
            epicsTimeGetCurrent(&self->snap_time);
            if(self->time) {
                plink->precord->time = self->snap_time;
            }
            DEBUG(self, <<CURRENT_FUNCTION<<" "<<self->channelName<<" !valid");
            return -1;
        }

        if(self->fld_value) {
            long status = copyPVD2DBF(self->fld_value, pbuffer, dbrType, pnRequest);
            if(status) {
                DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<status);
                return status;
            }
        }

        if(self->fld_seconds) {
            self->snap_time.secPastEpoch = self->fld_seconds->getAs<pvd::uint32>() - POSIX_TIME_AT_EPICS_EPOCH;
            if(self->fld_nanoseconds) {
                self->snap_time.nsec = self->fld_nanoseconds->getAs<pvd::uint32>();
            } else {
                self->snap_time.nsec = 0u;
            }
        } else {
            self->snap_time.secPastEpoch = 0u;
            self->snap_time.nsec = 0u;
        }

        if(self->fld_severity) {
            self->snap_severity = self->fld_severity->getAs<pvd::uint16>();
        } else {
            self->snap_severity = NO_ALARM;
        }

        if((self->snap_severity!=NO_ALARM && self->ms == pvaLink::MS) ||
           (self->snap_severity==INVALID_ALARM && self->ms == pvaLink::MSI))
        {
            recGblSetSevr(plink->precord, LINK_ALARM, self->snap_severity);
        }

        if(self->time) {
            plink->precord->time = self->snap_time;
        }

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" OK");
        return 0;
    }CATCH()
    return -1;
}

long pvaGetControlLimits(const DBLINK *plink, double *lo, double *hi)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(self->fld_control) {
            pvd::PVScalar::const_shared_pointer value;
            if(lo) {
                value = std::tr1::static_pointer_cast<const pvd::PVScalar>(self->fld_control->getSubField("limitLow"));
                *lo = value ? value->getAs<double>() : 0.0;
            }
            if(hi) {
                value = std::tr1::static_pointer_cast<const pvd::PVScalar>(self->fld_control->getSubField("limitHigh"));
                *hi = value ? value->getAs<double>() : 0.0;
            }
        } else {
            *lo = *hi = 0.0;
        }
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<(lo ? *lo : 0)<<" "<<(hi ? *hi : 0));
        return 0;
    }CATCH()
    return -1;
}

long pvaGetGraphicLimits(const DBLINK *plink, double *lo, double *hi)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(self->fld_display) {
            pvd::PVScalar::const_shared_pointer value;
            if(lo) {
                value = std::tr1::static_pointer_cast<const pvd::PVScalar>(self->fld_display->getSubField("limitLow"));
                *lo = value ? value->getAs<double>() : 0.0;
            }
            if(hi) {
                value = std::tr1::static_pointer_cast<const pvd::PVScalar>(self->fld_display->getSubField("limitHigh"));
                *hi = value ? value->getAs<double>() : 0.0;
            }
        } else {
            *lo = *hi = 0.0;
        }
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<(lo ? *lo : 0)<<" "<<(hi ? *hi : 0));
        return 0;
    }CATCH()
    return -1;
}

long pvaGetAlarmLimits(const DBLINK *plink, double *lolo, double *lo,
        double *hi, double *hihi)
{
    TRY {
        //Guard G(self->lchan->lock);
        //CHECK_VALID();
        *lolo = *lo = *hi = *hihi = 0.0;
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<(lolo ? *lolo : 0)<<" "<<(lo ? *lo : 0)<<" "<<(hi ? *hi : 0)<<" "<<(hihi ? *hihi : 0));
        return 0;
    }CATCH()
    return -1;
}

long pvaGetPrecision(const DBLINK *plink, short *precision)
{
    TRY {
        //Guard G(self->lchan->lock);
        //CHECK_VALID();

        // No sane way to recover precision from display.format string.
        *precision = 0;
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<precision);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetUnits(const DBLINK *plink, char *units, int unitsSize)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(unitsSize==0) return 0;

        if(units && self->fld_display) {
            pvd::PVString::const_shared_pointer value(std::tr1::static_pointer_cast<const pvd::PVString>(self->fld_display->getSubField("units")));
            if(value) {
                const std::string& egu = value->get();
                strncpy(units, egu.c_str(), unitsSize);
            }
        } else if(units) {
            units[0] = '\0';
        }
        units[unitsSize-1] = '\0';
        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<units);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetAlarm(const DBLINK *plink, epicsEnum16 *status,
        epicsEnum16 *severity)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(severity) {
            *severity = self->snap_severity;
        }
        if(status) {
            *status = self->snap_severity ? LINK_ALARM : NO_ALARM;
        }

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<(severity ? *severity : 0)<<" "<<(status ? *status : 0));
        return 0;
    }CATCH()
    return -1;
}

long pvaGetTimeStamp(const DBLINK *plink, epicsTimeStamp *pstamp)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(pstamp) {
            *pstamp = self->snap_time;
        }

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<(pstamp ? pstamp->secPastEpoch : 0)<<":"<<(pstamp ? pstamp->nsec: 0));
        return 0;
    }CATCH()
    return -1;
}

// note that we handle DBF_ENUM differently than in pvif.cpp
pvd::ScalarType DBR2PVD(short dbr)
{
    switch(dbr) {
#define CASE(BASETYPE, PVATYPE, DBFTYPE, PVACODE) case DBR_##DBFTYPE: return pvd::pv##PVACODE;
#define CASE_SKIP_BOOL
#define CASE_REAL_INT64
#include "pv/typemap.h"
#undef CASE_SKIP_BOOL
#undef CASE_REAL_INT64
#undef CASE
    case DBF_ENUM: return pvd::pvUShort;
    case DBF_STRING: return pvd::pvString;
    }
    throw std::invalid_argument("Unsupported DBR code");
}

long pvaPutValueX(DBLINK *plink, short dbrType,
        const void *pbuffer, long nRequest, bool wait)
{
    TRY {
        (void)self;
        Guard G(self->lchan->lock);

        if(nRequest < 0) return -1;

        if(!self->retry && !self->valid()) {
            DEBUG(self, <<CURRENT_FUNCTION<<" "<<self->channelName<<" !valid");
            return -1;
        }

        pvd::ScalarType stype = DBR2PVD(dbrType);

        pvd::shared_vector<const void> buf;

        if(dbrType == DBF_STRING) {
            const char *sbuffer = (const char*)pbuffer;
            pvd::shared_vector<std::string> sval(nRequest);

            for(long n=0; n<nRequest; n++, sbuffer += MAX_STRING_SIZE) {
                sval[n] = std::string(sbuffer, epicsStrnLen(sbuffer, MAX_STRING_SIZE));
            }

            self->put_scratch = pvd::static_shared_vector_cast<const void>(pvd::freeze(sval));

        } else {
            pvd::shared_vector<void> val(pvd::ScalarTypeFunc::allocArray(stype, size_t(nRequest)));

            assert(size_t(dbValueSize(dbrType)*nRequest) == val.size());

            memcpy(val.data(), pbuffer, val.size());

            self->put_scratch = pvd::freeze(val);
        }

        self->used_scratch = true;

#ifdef USE_MULTILOCK
        if(wait)
            self->lchan->after_put.insert(plink->precord);
#endif

        if(!self->defer) self->lchan->put();

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<self->lchan->op_put.valid());
        return 0;
    }CATCH()
    return -1;
}

long pvaPutValue(DBLINK *plink, short dbrType,
        const void *pbuffer, long nRequest)
{
    return pvaPutValueX(plink, dbrType, pbuffer, nRequest, false);
}

long pvaPutValueAsync(DBLINK *plink, short dbrType,
        const void *pbuffer, long nRequest)
{
    return pvaPutValueX(plink, dbrType, pbuffer, nRequest, true);
}

void pvaScanForward(DBLINK *plink)
{
    TRY {
        Guard G(self->lchan->lock);

        if(!self->retry && !self->valid()) {
            return;
        }

        // FWD_LINK is never deferred, and always results in a Put
        self->lchan->put(true);

        DEBUG(self, <<plink->precord->name<<" "<<CURRENT_FUNCTION<<" "<<self->channelName<<" "<<self->lchan->op_put.valid());
    }CATCH()
}

#undef TRY
#undef CATCH

} //namespace

namespace pvalink {

lset pva_lset = {
    0, 1, // non-const, volatile
    &pvaOpenLink,
    &pvaRemoveLink,
    NULL, NULL, NULL,
    &pvaIsConnected,
    &pvaGetDBFtype,
    &pvaGetElements,
    &pvaGetValue,
    &pvaGetControlLimits,
    &pvaGetGraphicLimits,
    &pvaGetAlarmLimits,
    &pvaGetPrecision,
    &pvaGetUnits,
    &pvaGetAlarm,
    &pvaGetTimeStamp,
    &pvaPutValue,
    &pvaPutValueAsync,
    &pvaScanForward
    //&pvaReportLink,
};

} //namespace pvalink
