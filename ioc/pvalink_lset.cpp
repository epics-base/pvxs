/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsString.h>
#include <alarm.h>
#include <recGbl.h>
#include <dbLink.h>

#include <pvxs/log.h>
#include "dbentry.h"
#include "pvalink.h"
#include "utilpvt.h"

#include <epicsStdio.h> // redirect stdout/stderr; include after libevent/util.h

DEFINE_LOGGER(_logger, "pvxs.ioc.link.lset");

#if EPICS_VERSION_INT <= VERSION_INT(3, 16, 1, 0)
static
const char * dbLinkFieldName(const struct link *plink)
{
    const struct dbCommon *precord = plink->precord;
    const dbRecordType *pdbRecordType = precord->rdes;
    dbFldDes * const *papFldDes = pdbRecordType->papFldDes;
    const short *link_ind = pdbRecordType->link_ind;
    int i;

    for (i = 0; i < pdbRecordType->no_links; i++) {
        const dbFldDes *pdbFldDes = papFldDes[link_ind[i]];

        if (plink == (DBLINK *)((char *)precord + pdbFldDes->offset))
            return pdbFldDes->name;
    }
    return "????";
}
#endif

namespace pvxs {
namespace ioc {
namespace {

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

void pvaOpenLink(DBLINK *plink) noexcept
{
    try {
        pvaLink* self((pvaLink*)plink->value.json.jlink);
        self->type = getLinkType(plink);

        if(self->local && dbChannelTest(self->channelName.c_str())!=0) {
            // TODO: only print duing iocInit()?
            fprintf(stderr, "%s Error: local:true link to '%s' can't be fulfilled\n",
                   plink->precord->name, self->channelName.c_str());
            plink->lset = NULL;
            return;
        }

        // workaround for Base not propagating info(base:lsetDebug to us
        {
            ioc::DBEntry rec(plink->precord);

            if(epicsStrCaseCmp(rec.info("base:lsetDebug", "NO"), "YES")==0) {
                self->debug = 1;
            }
        }

        log_debug_printf(_logger, "%s OPEN %s sevr=%d\n",
                         plink->precord->name, self->channelName.c_str(),
                         self->sevr);

        // still single threaded at this point.
        // also, no pvaLinkChannel::lock yet

        self->plink = plink;
        self->pfieldname = dbLinkFieldName(plink);

        if(self->channelName.empty())
            return; // nothing to do...

        auto pvRequest(self->makeRequest());
        linkGlobal_t::channels_key_t key = std::make_pair(self->channelName, std::string(SB()<<pvRequest.format()));

        std::shared_ptr<pvaLinkChannel> chan;
        bool doOpen = false;
        {
            Guard G(linkGlobal->lock);

            linkGlobal_t::channels_t::iterator it(linkGlobal->channels.find(key));

            if(it!=linkGlobal->channels.end()) {
                // reuse existing channel
                chan = it->second.lock();
            }

            if(!chan) {
                // open new channel

                log_debug_printf(_logger, "%s CREATE %s\n",
                                 plink->precord->name, self->channelName.c_str());

                chan.reset(new pvaLinkChannel(key, pvRequest));
                chan->AP->lc = chan;
                linkGlobal->channels.insert(std::make_pair(key, chan));
                doOpen = true;

            } else {
                log_debug_printf(_logger, "%s REUSE %s\n",
                                 plink->precord->name, self->channelName.c_str());
            }

            doOpen &= linkGlobal->running; // if not running, then open from initHook
        }

        if(doOpen) {
            chan->open(); // start subscription
        }

        bool scanInit = false;
        {
            Guard G(chan->lock);

            chan->links.insert(self);
            chan->links_changed = true;

            self->lchan = std::move(chan); // we are now attached

            self->lchan->debug |= !!self->debug;

            if(self->lchan->connected) {
                self->onTypeChange();
                auto sou(self->scanOnUpdate());
                switch(sou) {
                case pvaLink::scanOnUpdateNo:
                    break;
                case pvaLink::scanOnUpdatePassive:
                    // record is locked
                    scanInit = plink->precord->scan==menuScanPassive;
                    break;
                case pvaLink::scanOnUpdateYes:
                    scanInit = true;
                    break;
                }
            }
        }
        if(scanInit) {
            // TODO: initial scan on linkGlobal worker?
            scanOnce(plink->precord);
        }

        return;
    }CATCH()
    // on error, prevent any further calls to our lset functions
    plink->lset = NULL;
}

void pvaRemoveLink(struct dbLocker *locker, DBLINK *plink) noexcept
{
    (void)locker;
    try {
        std::unique_ptr<pvaLink> self((pvaLink*)plink->value.json.jlink);
        log_debug_printf(_logger, "%s: %s %s\n", __func__, plink->precord->name, self->channelName.c_str());
        assert(self->alive);

    }CATCH()
}

int pvaIsConnected(const DBLINK *plink) noexcept
{
    TRY {
        Guard G(self->lchan->lock);

        bool ret = self->valid();
        log_debug_printf(_logger, "%s: %s %s\n", __func__, plink->precord->name, self->channelName.c_str());
        return ret;

    }CATCH()
    return 0;
}

int pvaGetDBFtype(const DBLINK *plink) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        // if fieldName is empty, use top struct value
        // if fieldName not empty
        //    if sub-field is struct, use sub-struct .value
        //    if sub-field not struct, treat as value

        auto& value(self->fld_value);
        auto vtype(self->fld_value.type());
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

long pvaGetElements(const DBLINK *plink, long *nelements) noexcept
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

long pvaGetValue(DBLINK *plink, short dbrType, void *pbuffer, long *pnRequest) noexcept
{
    TRY {
        Guard G(self->lchan->lock);

        if(!self->valid()) {
            // disconnected
            (void)recGblSetSevrMsg(plink->precord, LINK_ALARM, INVALID_ALARM, "%s Disconn",
                                   self->pfieldname);
            if(self->time) {
                plink->precord->time = self->snap_time;
            }
            log_debug_printf(_logger, "%s: %s not valid\n", __func__, self->channelName.c_str());
            return -1;
        }

        auto nReq(pnRequest ? *pnRequest : 1);
        auto value(self->fld_value);

        if(value.type()==TypeCode::Any || value.type()==TypeCode::Union)
            value = value.lookup("->");

        if(nReq <= 0 || !value) {
            if(!pnRequest) {
                memset(pbuffer, 0, dbValueSize(dbrType));
                nReq = 1;
            }

        } else if(value.type().isarray()) {
            auto arr(value.as<shared_array<const void>>());

            if(size_t(nReq) > arr.size())
                nReq = arr.size();

            if(dbrType==DBR_STRING) {
                auto sarr(arr.castTo<const std::string>()); // may copy+convert

                auto cbuf(reinterpret_cast<char*>(pbuffer));
                for(size_t i : range(size_t(nReq))) {
                    strncpy(cbuf + i*MAX_STRING_SIZE,
                            sarr[i].c_str(),
                            MAX_STRING_SIZE-1u);
                    cbuf[i*MAX_STRING_SIZE + MAX_STRING_SIZE-1] = '\0';
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
                    log_debug_printf(_logger, "%s: %s unsupported array conversion\n",
                                     __func__, plink->precord->name);
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
                    log_debug_printf(_logger, "%s: %s unsupported enum conversion\n",
                                     __func__, plink->precord->name);
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
                    log_debug_printf(_logger, "%s: %s unsupported scalar conversion\n",
                                     __func__, plink->precord->name);
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

        if(self->fld_message && self->snap_severity!=0) {
            self->snap_message = self->fld_message.as<std::string>();
        } else {
            self->snap_message.clear();
        }

        if((self->snap_severity!=NO_ALARM && self->sevr == pvaLink::MS) ||
           (self->snap_severity==INVALID_ALARM && self->sevr == pvaLink::MSI))
        {
            log_debug_printf(_logger, "%s: %s recGblSetSevr %d\n", __func__, plink->precord->name,
                             self->snap_severity);
            recGblSetSevrMsg(plink->precord, LINK_ALARM, self->snap_severity,
                             "%s", self->snap_message.c_str());
        }

        if(self->time) {
            plink->precord->time = self->snap_time;
        }

        log_debug_printf(_logger, "%s: %s %s snapalrm=%d,\"%s\" OK\n", __func__, plink->precord->name,
                         self->channelName.c_str(), self->snap_severity, self->snap_message.c_str());
        return 0;
    }CATCH()
    return -1;
}

long pvaGetControlLimits(const DBLINK *plink, double *lo, double *hi) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(lo)
            (void)self->fld_meta["control.limitLow"].as(*lo);
        if(hi)
            (void)self->fld_meta["control.limitHigh"].as(*hi);

        log_debug_printf(_logger, "%s: %s %s %f %f\n",
            __func__, plink->precord->name, self->channelName.c_str(), lo ? *lo : 0, hi ? *hi : 0);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetGraphicLimits(const DBLINK *plink, double *lo, double *hi) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(lo)
            (void)self->fld_meta["display.limitLow"].as(*lo);
        if(hi)
            (void)self->fld_meta["display.limitHigh"].as(*hi);

        log_debug_printf(_logger, "%s: %s %s %f %f\n",
            __func__, plink->precord->name, self->channelName.c_str(), lo ? *lo : 0, hi ? *hi : 0);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetAlarmLimits(const DBLINK *plink, double *lolo, double *lo,
                       double *hi, double *hihi) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(lolo)
            (void)self->fld_meta["valueAlarm.lowAlarmLimit"].as(*lolo);
        if(lo)
            (void)self->fld_meta["valueAlarm.lowWarningLimit"].as(*lo);
        if(hi)
            (void)self->fld_meta["valueAlarm.highWarningLimit"].as(*hi);
        if(hihi)
            (void)self->fld_meta["valueAlarm.highAlarmLimit"].as(*hihi);


        log_debug_printf(_logger, "%s: %s %s %f %f %f %f\n",
            __func__, plink->precord->name, self->channelName.c_str(),
            lo ? *lo : 0, lolo ? *lolo : 0, hi ? *hi : 0, hihi ? *hihi : 0);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetPrecision(const DBLINK *plink, short *precision) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        uint16_t prec = 0;
        (void)self->fld_meta["display.precision"].as(prec);
        if(precision)
            *precision = prec;

        log_debug_printf(_logger, "%s: %s %s %i\n", __func__, plink->precord->name, self->channelName.c_str(), prec);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetUnits(const DBLINK *plink, char *units, int unitsSize) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(!units || unitsSize==0) return 0;


        std::string egu;
        (void)self->fld_meta["display.units"].as<std::string>(egu);
        strncpy(units, egu.c_str(), unitsSize-1);
        units[unitsSize-1] = '\0';

        log_debug_printf(_logger, "%s: %s %s %s\n", __func__, plink->precord->name, self->channelName.c_str(), units);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetAlarmMsg(const DBLINK *plink,
                    epicsEnum16 *status, epicsEnum16 *severity,
                    char *msgbuf, size_t msgbuflen) noexcept
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
        if(msgbuf && msgbuflen) {
            if(self->snap_message.empty()) {
                msgbuf[0] = '\0';
            } else {
                epicsSnprintf(msgbuf, msgbuflen-1u, "%s", self->snap_message.c_str());
                msgbuf[msgbuflen-1u] = '\0';
            }
        }
        log_debug_printf(_logger, "%s: %s %s %i %i\n",
                         __func__, plink->precord->name, self->channelName.c_str(), severity ? *severity : 0, status ? *status : 0);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetAlarm(const DBLINK *plink, epicsEnum16 *status,
                 epicsEnum16 *severity) noexcept
{
    return pvaGetAlarmMsg(plink, status, severity, nullptr, 0);
}

long pvaGetTimeStampTag(const DBLINK *plink, epicsTimeStamp *pstamp, epicsUTag *ptag) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        CHECK_VALID();

        if(pstamp) {
            *pstamp = self->snap_time;
        }
        if(ptag) {
            *ptag = self->snap_tag;
        }
        log_debug_printf(_logger, "%s: %s %s %i %i\n", __func__, plink->precord->name, self->channelName.c_str(), pstamp ? pstamp->secPastEpoch : 0, pstamp ? pstamp->nsec : 0);
        return 0;
    }CATCH()
    return -1;
}

long pvaGetTimeStamp(const DBLINK *plink, epicsTimeStamp *pstamp) noexcept
{
    return pvaGetTimeStampTag(plink, pstamp, nullptr);
}

long pvaPutValueX(DBLINK *plink, short dbrType,
                  const void *pbuffer, long nRequest, bool wait) noexcept
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

        if(wait)
            self->lchan->after_put.insert(plink->precord);

        if(!self->defer) self->lchan->put();

        log_debug_printf(_logger, "%s: %s %s %s\n", __func__, plink->precord->name, self->channelName.c_str(), self->lchan->root.valid() ? "valid": "not valid");
        
        return 0;
    }CATCH()
    return -1;
}

long pvaPutValue(DBLINK *plink, short dbrType, const void *pbuffer, long nRequest) noexcept
{
    return pvaPutValueX(plink, dbrType, pbuffer, nRequest, false);
}

long pvaPutValueAsync(DBLINK *plink, short dbrType, const void *pbuffer, long nRequest) noexcept
{
    return pvaPutValueX(plink, dbrType, pbuffer, nRequest, true);
}

void pvaScanForward(DBLINK *plink) noexcept
{
    TRY {
        Guard G(self->lchan->lock);

        if(!self->retry && !self->valid()) {
            (void)recGblSetSevrMsg(plink->precord, LINK_ALARM, INVALID_ALARM, "Disconn");
            return;
        }

        // FWD_LINK is never deferred, and always results in a Put
        self->lchan->put(true);

        log_debug_printf(_logger, "%s: %s %s %s\n",
            __func__, plink->precord->name, self->channelName.c_str(), self->lchan->root.valid() ? "valid": "not valid");
    }CATCH()
}

#if EPICS_VERSION_INT>=VERSION_INT(3,16,1,0)
long pvaDoLocked(struct link *plink, dbLinkUserCallback rtn, void *priv) noexcept
{
    TRY {
        Guard G(self->lchan->lock);
        return (*rtn)(plink, priv);
    }CATCH()
    return 1;
}
#endif // >= 3.16.1

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
    &pvaScanForward,
#if EPICS_VERSION_INT>=VERSION_INT(3,16,1,0)
    &pvaDoLocked,
#endif
#if EPICS_VERSION_INT>=VERSION_INT(7,0,6,0)
    &pvaGetAlarmMsg,
    &pvaGetTimeStampTag,
#endif
};

}} // namespace pvxs::ioc
