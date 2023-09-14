/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsString.h>
#include <alarm.h>
#include <recGbl.h>

#include <pvxs/log.h>
#include "dbentry.h"
#include "pvalink.h"
#include "utilpvt.h"

#include <epicsStdio.h> // redirect stdout/stderr; include after libevent/util.h

DEFINE_LOGGER(_logger, "pvxs.pvalink.lset");

namespace pvxlink {
namespace {
using namespace pvxs;

#define TRY pvaLink *self = static_cast<pvaLink*>(plink->value.json.jlink); assert(self->alive); try
#define CATCH() catch(std::exception& e) { \
    errlogPrintf("pvaLink %s fails %s: %s\n", __func__, plink->precord->name, e.what()); \
}

#define CHECK_VALID() if(!self->valid()) { log_debug_printf(_logger, "%s: %s not valid\n", __func__, self->channelName.c_str()); return -1;}

dbfType getLinkType(DBLINK *plink)
{
    ioc::DBEntry ent(plink->precord);

    for(long status = dbFirstField(ent, 0); !status; status = dbNextField(ent, 0)) {
        if(ent->pfield==plink)
            return ent->pflddes->field_type;
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
            ioc::DBEntry rec(plink->precord);

            if(epicsStrCaseCmp(rec.info("base:lsetDebug", "NO"), "YES")==0) {
                self->debug = 1;
            }
        }

        log_debug_printf(_logger, "%s OPEN %s\n", plink->precord->name, self->channelName.c_str());

        // still single threaded at this point.
        // also, no pvaLinkChannel::lock yet

        self->plink = plink;

        if(self->channelName.empty())
            return; // nothing to do...

        auto pvRequest(self->makeRequest());
        pvaGlobal_t::channels_key_t key = std::make_pair(self->channelName, std::string(SB()<<pvRequest.format()));

        std::shared_ptr<pvaLinkChannel> chan;
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
        std::unique_ptr<pvaLink> self((pvaLink*)plink->value.json.jlink);
        log_debug_printf(_logger, "%s: %s %s\n", __func__, plink->precord->name, self->channelName.c_str());
        assert(self->alive);

    }CATCH()
}

int pvaIsConnected(const DBLINK *plink)
{
    TRY {
        Guard G(self->lchan->lock);

        bool ret = self->valid();
        log_debug_printf(_logger, "%s: %s %s\n", __func__, plink->precord->name, self->channelName.c_str());
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

        auto value(self->getSubField("value"));
        auto vtype(value.type());
        if(vtype.isarray())
            vtype = vtype.scalarOf();

        switch(value.type().code) {
        case TypeCode::Int8: return DBF_CHAR;
        case TypeCode::Int16: return DBF_SHORT;
        case TypeCode::Int32: return DBF_LONG;
        case TypeCode::Int64: return DBF_INT64;
        case TypeCode::UInt8: return DBF_UCHAR;
        case TypeCode::UInt16: return DBF_USHORT;
        case TypeCode::UInt32: return DBF_ULONG;
        case TypeCode::UInt64: return DBF_UINT64;
        case TypeCode::Float32: return DBF_FLOAT;
        case TypeCode::Float64: return DBF_DOUBLE;
        case TypeCode::String: return DBF_STRING;
        case TypeCode::Struct: {
            if(value.id()=="enum_t"
                    && value["index"].type().kind()==Kind::Integer
                    && value["choices"].type()==TypeCode::StringA)
                return DBF_ENUM;
        }
            // fall through
        default:
            return DBF_LONG; // default for un-mapable types.
        }

    }CATCH()
    return -1;
}

long pvaGetElements(const DBLINK *plink, long *nelements)
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        shared_array<const void> arr;
        if(!self->fld_value.type().isarray()) {
            *nelements = 1;
        } else if(self->fld_value.as(arr)) {
            *nelements = arr.size();
        }
        return 0;
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
            if(self->sevr != pvaLink::NMS) {
                recGblSetSevr(plink->precord, LINK_ALARM, self->snap_severity);
            }
            // TODO: better capture of disconnect time
            epicsTimeGetCurrent(&self->snap_time);
            if(self->time) {
                plink->precord->time = self->snap_time;
            }
            log_debug_printf(_logger, "%s: %s not valid", __func__, self->channelName.c_str());
            return -1;
        }

        auto nReq(pnRequest ? *pnRequest : 1);
        auto value(self->fld_value);

        if(value.type()==TypeCode::Any)
            value = value.lookup("->");

        if(nReq <= 0 || !value) {
            if(!pnRequest) {
                // TODO: fill in dummy scalar
                nReq = 1;
            }

        } else if(value.type().isarray()) {
            auto arr(value.as<shared_array<const void>>());

            if(size_t(nReq) > arr.size())
                nReq = arr.size();

            if(arr.original_type()==ArrayType::String) {
                auto sarr(arr.castTo<const std::string>());

                if(dbrType==DBR_STRING) {
                    auto cbuf(reinterpret_cast<char*>(pbuffer));
                    for(size_t i : range(size_t(nReq))) {
                        strncpy(cbuf + i*MAX_STRING_SIZE,
                                sarr[i].c_str(),
                                MAX_STRING_SIZE-1u);
                        cbuf[i*MAX_STRING_SIZE + MAX_STRING_SIZE-1] = '\0';
                    }
                } else {
                    return S_db_badDbrtype; // TODO: allow implicit parse?
                }

            } else {
                ArrayType dtype;
                switch(dbrType) {
                case DBR_CHAR: dtype = ArrayType::Int8; break;
                case DBR_SHORT: dtype = ArrayType::Int16; break;
                case DBR_LONG: dtype = ArrayType::Int32; break;
                case DBR_INT64: dtype = ArrayType::Int64; break;
                case DBR_UCHAR: dtype = ArrayType::UInt8; break;
                case DBR_USHORT: dtype = ArrayType::UInt16; break;
                case DBR_ULONG: dtype = ArrayType::UInt32; break;
                case DBR_UINT64: dtype = ArrayType::UInt64; break;
                case DBR_FLOAT: dtype = ArrayType::Float32; break;
                case DBR_DOUBLE: dtype = ArrayType::Float64; break;
                default:
                    return S_db_badDbrtype;
                }

                detail::convertArr(dtype, pbuffer,
                                   arr.original_type(), arr.data(),
                                   size_t(nReq));
            }

        } else { // scalar
            // TODO: special case for "long string"

            if(value.type()==TypeCode::Struct && self->fld_value.id()=="enum_t") { // NTEnum
                auto index(value["index"].as<int32_t>());
                switch(dbrType) {
                case DBR_CHAR: *reinterpret_cast<epicsInt8*>(pbuffer) = index; break;
                case DBR_SHORT: *reinterpret_cast<epicsInt16*>(pbuffer) = index; break;
                case DBR_LONG: *reinterpret_cast<epicsInt32*>(pbuffer) = index; break;
                case DBR_INT64: *reinterpret_cast<epicsUInt64*>(pbuffer) = index; break;
                case DBR_UCHAR: *reinterpret_cast<epicsUInt8*>(pbuffer) = index; break;
                case DBR_USHORT: *reinterpret_cast<epicsUInt16*>(pbuffer) = index; break;
                case DBR_ULONG: *reinterpret_cast<epicsUInt32*>(pbuffer) = index; break;
                case DBR_UINT64: *reinterpret_cast<epicsUInt64*>(pbuffer) = index; break;
                case DBR_FLOAT: *reinterpret_cast<float*>(pbuffer) = index; break;
                case DBR_DOUBLE: *reinterpret_cast<double*>(pbuffer) = index; break;
                case DBR_STRING: {
                    auto cbuf(reinterpret_cast<char*>(pbuffer));
                    auto choices(value["choices"].as<shared_array<const std::string>>());
                    if(index>=0 && size_t(index) < choices.size()) {
                        auto& choice(choices[index]);
                        strncpy(cbuf, choice.c_str(), MAX_STRING_SIZE-1u);

                    } else {
                        epicsSnprintf(cbuf, MAX_STRING_SIZE-1u, "%u", unsigned(index));
                    }
                    cbuf[MAX_STRING_SIZE-1u] = '\0';
                    break;
                }
                default:
                    return S_db_badDbrtype;
                }

            } else { // plain scalar
                switch(dbrType) {
                case DBR_CHAR: *reinterpret_cast<epicsInt8*>(pbuffer) = value.as<int8_t>(); break;
                case DBR_SHORT: *reinterpret_cast<epicsInt16*>(pbuffer) = value.as<int16_t>(); break;
                case DBR_LONG: *reinterpret_cast<epicsInt32*>(pbuffer) = value.as<int32_t>(); break;
                case DBR_INT64: *reinterpret_cast<epicsInt64*>(pbuffer) = value.as<int64_t>(); break;
                case DBR_UCHAR: *reinterpret_cast<epicsUInt8*>(pbuffer) = value.as<uint8_t>(); break;
                case DBR_USHORT: *reinterpret_cast<epicsUInt16*>(pbuffer) = value.as<uint16_t>(); break;
                case DBR_ULONG: *reinterpret_cast<epicsUInt32*>(pbuffer) = value.as<uint32_t>(); break;
                case DBR_UINT64: *reinterpret_cast<epicsUInt64*>(pbuffer) = value.as<uint64_t>(); break;
                case DBR_FLOAT: *reinterpret_cast<float*>(pbuffer) = value.as<float>(); break;
                case DBR_DOUBLE: *reinterpret_cast<double*>(pbuffer) = value.as<double>(); break;
                case DBR_STRING: {
                    auto cbuf(reinterpret_cast<char*>(pbuffer));
                    auto sval(value.as<std::string>());
                    strncpy(cbuf, sval.c_str(), MAX_STRING_SIZE-1u);
                    cbuf[MAX_STRING_SIZE-1u] = '\0';
                    break;
                }
                default:
                    return S_db_badDbrtype;
                }
            }
            nReq = 1;
        }

        if(pnRequest)
            *pnRequest = nReq;

        if(self->fld_seconds) {
            self->snap_time.secPastEpoch = self->fld_seconds.as<uint32_t>() - POSIX_TIME_AT_EPICS_EPOCH;
            if(self->fld_nanoseconds) {
                self->snap_time.nsec = self->fld_nanoseconds.as<uint32_t>();
            } else {
                self->snap_time.nsec = 0u;
            }
        } else {
            self->snap_time.secPastEpoch = 0u;
            self->snap_time.nsec = 0u;
        }

        if(self->fld_severity) {
            self->snap_severity = self->fld_severity.as<uint16_t>();
        } else {
            self->snap_severity = NO_ALARM;
        }

        if((self->snap_severity!=NO_ALARM && self->sevr == pvaLink::MS) ||
           (self->snap_severity==INVALID_ALARM && self->sevr == pvaLink::MSI))
        {
            recGblSetSevr(plink->precord, LINK_ALARM, self->snap_severity);
        }

        if(self->time) {
            plink->precord->time = self->snap_time;
        }

        log_debug_printf(_logger, "%s: %s %s OK\n", __func__, plink->precord->name, self->channelName.c_str());
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
            Value value;
            if(lo) {
                if(!self->fld_control["limitLow"].as<double>(*lo))
                    *lo = 0.0;
            }
            if(hi) {
                if(!self->fld_control["limitHigh"].as<double>(*hi))
                    *hi = 0.0;
            }
        } else {
            *lo = *hi = 0.0;
        }
        log_debug_printf(_logger, "%s: %s %s %f %f\n",
            __func__, plink->precord->name, self->channelName.c_str(), lo ? *lo : 0, hi ? *hi : 0);
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
            Value value;
            if(lo) {
                if(!self->fld_display["limitLow"].as<double>(*lo))
                    *lo = 0.0;
            }
            if(hi) {
                if(!self->fld_display["limitHigh"].as<double>(*hi))
                    *hi = 0.0;
            }
        } else {
            *lo = *hi = 0.0;
        }
        log_debug_printf(_logger, "%s: %s %s %f %f\n",
            __func__, plink->precord->name, self->channelName.c_str(), lo ? *lo : 0, hi ? *hi : 0);
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
        log_debug_printf(_logger, "%s: %s %s %f %f %f %f\n",
            __func__, plink->precord->name, self->channelName.c_str(),
            lo ? *lo : 0, lolo ? *lolo : 0, hi ? *hi : 0, hihi ? *hihi : 0);
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
        log_debug_printf(_logger, "%s: %s %s %i\n", __func__, plink->precord->name, self->channelName.c_str(), *precision);
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

        std::string egu;
        if(units && self->fld_display.as<std::string>(egu)) {
            strncpy(units, egu.c_str(), unitsSize-1u);
            units[unitsSize-1u] = '\0';
        } else if(units) {
            units[0] = '\0';
        }
        units[unitsSize-1] = '\0';
        log_debug_printf(_logger, "%s: %s %s %s\n", __func__, plink->precord->name, self->channelName.c_str(), units);
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
        log_debug_printf(_logger, "%s: %s %s %i %i\n",
                         __func__, plink->precord->name, self->channelName.c_str(), severity ? *severity : 0, status ? *status : 0);
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
        log_debug_printf(_logger, "%s: %s %s %i %i\n", __func__, plink->precord->name, self->channelName.c_str(), pstamp ? pstamp->secPastEpoch : 0, pstamp ? pstamp->nsec : 0);
        return 0;
    }CATCH()
    return -1;
}

long pvaPutValueX(DBLINK *plink, short dbrType,
                  const void *pbuffer, long nRequest, bool wait)
{
    TRY {
        (void)self;
        Guard G(self->lchan->lock);

        if(nRequest < 0) return -1;

        if(!self->retry && !self->valid()) {
            log_debug_printf(_logger, "%s: %s not valid\n", __func__, self->channelName.c_str());
            return -1;
        }

        shared_array<const void> buf;

        if(dbrType == DBF_STRING) {
            const char *sbuffer = (const char*)pbuffer;
            shared_array<std::string> sval(nRequest);

            for(long n=0; n<nRequest; n++, sbuffer += MAX_STRING_SIZE) {
                sval[n] = std::string(sbuffer, epicsStrnLen(sbuffer, MAX_STRING_SIZE));
            }

            self->put_scratch = sval.freeze().castTo<const void>();

        } else {
            ArrayType dtype;
            switch(dbrType) {
            case DBR_CHAR: dtype = ArrayType::Int8; break;
            case DBR_SHORT: dtype = ArrayType::Int16; break;
            case DBR_LONG: dtype = ArrayType::Int32; break;
            case DBR_INT64: dtype = ArrayType::Int64; break;
            case DBR_UCHAR: dtype = ArrayType::UInt8; break;
            case DBR_USHORT: dtype = ArrayType::UInt16; break;
            case DBR_ULONG: dtype = ArrayType::UInt32; break;
            case DBR_UINT64: dtype = ArrayType::UInt64; break;
            case DBR_FLOAT: dtype = ArrayType::Float32; break;
            case DBR_DOUBLE: dtype = ArrayType::Float64; break;
            default:
                return S_db_badDbrtype;
            }

            auto val(detail::copyAs(dtype, dtype, pbuffer, size_t(nRequest)));

            self->put_scratch = val.freeze().castTo<const void>();
        }

        self->used_scratch = true;

#ifdef USE_MULTILOCK
        if(wait)
            self->lchan->after_put.insert(plink->precord);
#endif

        if(!self->defer) self->lchan->put();

        log_debug_printf(_logger, "%s: %s %s %s\n", __func__, plink->precord->name, self->channelName.c_str(), self->lchan->root.valid() ? "valid": "not valid");
        
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

        log_debug_printf(_logger, "%s: %s %s %s\n",
            __func__, plink->precord->name, self->channelName.c_str(), self->lchan->root.valid() ? "valid": "not valid");
    }CATCH()
}

#undef TRY
#undef CATCH

} //namespace

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

} // namespace pvxlink
