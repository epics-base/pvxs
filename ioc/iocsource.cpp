/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>
#include <algorithm>
#include <atomic>

#include <special.h>
#include <epicsTime.h>
#include <epicsStdlib.h>
#include <epicsString.h>

#include <pvxs/log.h>

#include "alarm.h"
#include "iocsource.h"
#include "dbentry.h"
#include "dberrormessage.h"
#include "typeutils.h"
#include "credentials.h"
#include "securityclient.h"
#include "securitylogger.h"
#include "utilpvt.h"

// include last to avoid clash of #define printf with other headers
#include <epicsStdio.h>

DEFINE_LOGGER(_log, "pvxs.ioc.db");

namespace pvxs {
namespace ioc {

void IOCSource::initialize(Value& value, const MappingInfo &info, const Channel& chan)
{
    if(info.type==MappingInfo::Scalar) {
        if(auto fld = value["display.form.choices"]) {
            shared_array<const std::string> choices({
                                                        "Default",
                                                        "String",
                                                        "Binary",
                                                        "Decimal",
                                                        "Hex",
                                                        "Exponential",
                                                        "Engineering",
                                                    });
            fld = choices;

            if(dbIsValueField(dbChannelFldDes(chan))) { // only apply Q:form to VAL
                auto tag(chan.format());
                for(auto i : range(choices.size())) {
                    if(choices[i] == tag) {
                        value["display.form.index"] = i;
                        break;
                    }
                }
            }
        }
    }
}

static
void getScalarValue(dbChannel* pChannel,
                    db_field_log *pfl,
                    Value& value)
{
    long nReq = 1;
    union {
        double _align;
        char _size[MAX_STRING_SIZE];
        char str[MAX_STRING_SIZE];
    } buf;

    DBErrorMessage dbErrorMessage(dbChannelGet(pChannel, dbChannelFinalFieldType(pChannel),
                                               &buf, nullptr, &nReq, pfl));
    if (dbErrorMessage) {
        throw std::runtime_error(SB()<<dbChannelName(pChannel)<<" "<<__func__<<" ERROR : "<<dbErrorMessage.c_str());
    } else if(nReq==0) {
        // this was an actual max length 1 array, which has zero elements now.
        memset(&buf, 0, sizeof(buf));
    }

    switch(value.type().code) {
    case TypeCode::String:
        buf.str[sizeof(buf.str)-1] = '\0';
        value = buf.str;
        break;
#define CASE(ENUM, TYPE) \
    case TypeCode::ENUM: value.from(*(const TYPE*)&buf); break
        CASE(Int8, int8_t);
        CASE(Int16, int16_t);
        CASE(Int32, int32_t);
        CASE(Int64, int64_t);
        CASE(UInt8, uint8_t);
        CASE(UInt16, uint16_t);
        CASE(UInt32, uint32_t);
        CASE(UInt64, uint64_t);
        CASE(Float32, float);
        CASE(Float64, double);
#undef CASE
    case TypeCode::Struct:
        if(auto index = value["index"]) {
            if(dbChannelFinalFieldType(pChannel)==DBR_ENUM) {
                index.from(*(epicsEnum16*)&buf);
                break;
            }
        }
    default:
        throw std::logic_error(SB()<<__func__<<" unsupported "<<value.type());
    }
}

static
void getArrayValue(dbChannel* pChannel,
                         db_field_log *pfl,
                         Value& value)
{
    auto final_type(dbChannelFinalFieldType(pChannel));
    auto buf(std::make_shared<std::vector<char>>(dbChannelFinalElements(pChannel) * dbChannelFinalFieldSize(pChannel)));
    long nReq = dbChannelFinalElements(pChannel);

    DBErrorMessage dbErrorMessage(dbChannelGet(pChannel, final_type,
                                               buf->data(), nullptr, &nReq, pfl));
    if (dbErrorMessage) {
        throw std::runtime_error(SB()<<dbChannelName(pChannel)<<" "<<__func__<<" ERROR : "<<dbErrorMessage.c_str());
    }

    if(final_type == DBR_CHAR && value.type()==TypeCode::String && !buf->empty()) {
        // long string
        (*buf)[buf->size()-1u] = '\0'; // paranoia?
        value = std::string(buf->data());

    } else if(final_type == DBR_STRING) {
        shared_array<std::string> arr(nReq);

        for(long n = 0; n < nReq; n++) {
            auto sval = &(*buf)[n*MAX_STRING_SIZE];
            auto nlen = strnlen(sval, MAX_STRING_SIZE);
            arr[n] = std::string(sval, nlen);
        }

        value.from(arr.freeze());
    } else {
        std::shared_ptr<char> cbuf(buf, buf->data());
        buf.reset(); // TODO: c++14 adds aliasing ctor by move()
        shared_array<void> arr(cbuf, nReq, value.type().arrayType());
        cbuf.reset();

        value.from(arr.freeze());
    }
}

// update timeStamp.* and maybe alarm.*
static
void getTimeAlarm(dbChannel* pChannel,
                  db_field_log *pfl,
                  Value& node,
                  const MappingInfo& info,
                  UpdateType::type change)
{
    long nReq = 0;
    long options = DBR_STATUS | DBR_AMSG | DBR_TIME | DBR_UTAG;
    struct ValueTimeAlarm {
        DBRstatus
        DBRamsg
        DBRtime
        DBRutag
    } meta;

    DBErrorMessage dbErrorMessage(dbChannelGet(pChannel, dbChannelFinalFieldType(pChannel),
                                               &meta, &options, &nReq, pfl));
    if (dbErrorMessage) {
        throw std::runtime_error(SB()<<dbChannelName(pChannel)<<" "<<__func__<<" ERROR : "<<dbErrorMessage.c_str());
    }
    // options may be updated.
    // as of base 7.0.6 time/alarm meta-data is always available

    if(change & UpdateType::Alarm) {
        const char* stsmsg = nullptr;
        if(options & DBR_STATUS) {
            // PVA status != DB status
            uint32_t status;
            switch(meta.status) {
            case NO_ALARM:
                status = 0;
                break;
            case READ_ALARM:
            case WRITE_ALARM:
            case HIHI_ALARM:
            case HIGH_ALARM:
            case LOLO_ALARM:
            case LOW_ALARM:
            case STATE_ALARM:
            case COS_ALARM:
            case HW_LIMIT_ALARM:
                status = 1; // DEVICE
                break;
            case COMM_ALARM:
            case TIMEOUT_ALARM:
            case UDF_ALARM:
                status = 2; // DRIVER
                break;
            case CALC_ALARM:
            case SCAN_ALARM:
            case LINK_ALARM:
            case SOFT_ALARM:
            case BAD_SUB_ALARM:
                status = 3; // RECORD
                break;
            case DISABLE_ALARM:
            case SIMM_ALARM:
            case READ_ACCESS_ALARM:
            case WRITE_ACCESS_ALARM:
                status = 4; // DB
                break;
            default:
                status = 6; // UNDEFINED
            }

            if(meta.status < ALARM_NSTATUS)
                stsmsg = epicsAlarmConditionStrings[meta.status];
            node["alarm.status"] = status;
            node["alarm.severity"] = meta.severity;
        }
#if DBR_AMSG
        if((options & DBR_AMSG) && meta.amsg[0]) {
            node["alarm.message"] = meta.amsg;
        } else
#endif
        {
            node["alarm.message"] = meta.status && stsmsg ? stsmsg : "";
        }
    } // DBE_ALARM
    if(options & DBR_TIME) {
        node["timeStamp.secondsPastEpoch"] = meta.time.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH;
        node["timeStamp.nanoseconds"] = meta.time.nsec & ~info.nsecMask;
    }
#if DBR_UTAG
    if(options & DBR_UTAG) {
        auto utag = meta.utag;
        if(info.nsecMask)
            utag = meta.time.nsec & info.nsecMask;
        node["timeStamp.userTag"] = utag;
    }
#endif
}

static
void getProperties(dbChannel* pChannel, db_field_log *pfl, Value& node)
{
    struct PropertyMeta {
        DBRunits
        DBRprecision
        DBRenumStrs
        DBRgrDouble
        DBRctrlDouble
        DBRalDouble
    } meta;
    long options = DBR_UNITS | DBR_PRECISION | DBR_ENUM_STRS | DBR_GR_DOUBLE | DBR_CTRL_DOUBLE | DBR_AL_DOUBLE;
    auto dbr_type = dbChannelFinalFieldType(pChannel);
    long nReq = 0; // only meta.  (so DBF type ignored)

    DBErrorMessage dbErrorMessage(dbChannelGet(pChannel, dbr_type,
                                               &meta, &options, &nReq, pfl));
    if (dbErrorMessage) {
        throw std::runtime_error(SB()<<dbChannelName(pChannel)<<" "<<__func__<<" ERROR : "<<dbErrorMessage.c_str());
    }
    // options has been updated to reflect meta-data actually updated.
    if(options & DBR_UNITS) {
        if(auto units = node["display.units"])
            units = meta.units;
    }
    if(options & DBR_ENUM_STRS) {
        if(auto choices = node["value.choices"]) {
            shared_array<std::string> arr(meta.no_str);
            for (epicsUInt32 i = 0; i < meta.no_str; i++) {
                arr[i] = meta.strs[i];
            }
            choices.from(arr.freeze());
        }
    }
    if(auto dlL = node["display.limitLow"]) { // if numeric
        if(options & DBR_GR_DOUBLE) {
            dlL = meta.lower_disp_limit;
            node["display.limitHigh"] = meta.upper_disp_limit;
            if(options & DBR_PRECISION) {
                node["display.precision"] = int32_t(meta.precision.dp);
            }
        }
        if(options & DBR_CTRL_DOUBLE) {
            node["control.limitLow"] = meta.lower_ctrl_limit;
            node["control.limitHigh"] = meta.upper_ctrl_limit;
        }
        if(options & DBR_AL_DOUBLE) {
            node["valueAlarm.lowAlarmLimit"] = meta.lower_alarm_limit;
            node["valueAlarm.lowWarningLimit"] = meta.lower_warning_limit;
            node["valueAlarm.highWarningLimit"] = meta.upper_warning_limit;
            node["valueAlarm.highAlarmLimit"] = meta.upper_alarm_limit;
        }
    }
    if(true) { // cheating at the moment.  DESC is not marked DBE_PROPERTY
        if(auto desc = node["display.description"])
            desc = dbChannelRecord(pChannel)->desc;
    }
}

void IOCSource::get(Value& node, // node within top level structure addressed by Field::fieldName
                    const MappingInfo &info,
                    const Value& anyType,
                    UpdateType::type change,
                    dbChannel *pChannel, // which type of event
                    db_field_log* pDbFieldLog)
{
    if(info.type==MappingInfo::Proc || info.type==MappingInfo::Structure)
        return;

    if(info.type==MappingInfo::Const) {
        node.assign(info.cval);
        return;
    }

    if((change & UpdateType::Property) && info.type==MappingInfo::Scalar) {
        getProperties(pChannel, pDbFieldLog, node);
    }

    if((info.type==MappingInfo::Scalar || info.type==MappingInfo::Meta) && (change & (UpdateType::Value | UpdateType::Alarm))) {
        getTimeAlarm(pChannel, pDbFieldLog, node, info, change);
    }

    if((change & UpdateType::Value) && info.type!=MappingInfo::Meta) {
        Value value;
        if(info.type==MappingInfo::Scalar) {
            value = node["value"];
        } else if(info.type==MappingInfo::Any) {
            value = anyType.cloneEmpty();
            node.from(value);
        } else {
            value = node;
        }

        if(dbChannelFinalElements(pChannel)==1) {
            getScalarValue(pChannel, pDbFieldLog, value);
        } else {
            getArrayValue(pChannel, pDbFieldLog, value);
        }
    }
}

/**
 * Do necessary preprocessing before put operations.  Check if put is allowed.
 *
 * @param pDbChannel channel to do preprocessing for
 * @param securityLogger the logger that will audit security events
 * @param credentials client credentials that are applied to this execution context
 * @param securityClient the security client.  Keep in scope around the put operation
 */
void
IOCSource::doPreProcessing(dbChannel* pDbChannel, SecurityLogger& securityLogger, const Credentials& credentials,
        const SecurityClient& securityClient) {
    if (pDbChannel->addr.special == SPC_ATTRIBUTE) {
        throw std::runtime_error("Unable to put value: Modifications not allowed: S_db_noMod");
    } else if (pDbChannel->addr.precord->disp && pDbChannel->addr.pfield != &pDbChannel->addr.precord->disp) {
        throw std::runtime_error("Unable to put value: Field Disabled: S_db_putDisabled");
    }

    SecurityLogger asWritePvt(pDbChannel, credentials, securityClient);

    securityLogger.swap(asWritePvt);

}

/**
 * Do necessary preprocessing before put operations.  Check if put is allowed.
 *
 * @param securityClient security client applied to this execution context
 */
void IOCSource::doFieldPreProcessing(const SecurityClient& securityClient) {
    if (!securityClient.canWrite()) {
        // TODO this will abort the whole group put operation, so may be a behavior change, need to check
        throw std::runtime_error("Put not permitted");
    }
}

/**
 * Do necessary post processing after put operations.  If this field is a processing record then do processing
 * and set status
 * Note: Only called when dbPutField() is not called.
 *
 * @param pDbChannel channel to do post processing for
 * @param forceProcessing whether to force processing, True, False
 */
void IOCSource::doPostProcessing(dbChannel* pDbChannel, TriState forceProcessing) {
    if (pDbChannel->addr.pfield == &pDbChannel->addr.precord->proc ||
            (forceProcessing == True) ||
            (pDbChannel->addr.pfldDes->process_passive &&
                    pDbChannel->addr.precord->scan == 0 &&
                    dbChannelFinalFieldType(pDbChannel) < DBR_PUT_ACKT &&
                    forceProcessing == Unset)) {
        if (pDbChannel->addr.precord->pact) {
#if EPICS_VERSION_INT >= VERSION_INT(3, 16, 2, 0)
            if (dbAccessDebugPUTF && pDbChannel->addr.precord->tpro) {
                printf("%s: single source onPut to Active '%s', setting RPRO=1\n",
                        epicsThreadGetNameSelf(), pDbChannel->addr.precord->name);
            }
#endif
            pDbChannel->addr.precord->rpro = TRUE;
        } else {
            pDbChannel->addr.precord->putf = TRUE;
            log_debug_printf(_log, "dbProcess %s\n", pDbChannel->name);
            DBErrorMessage dbErrorMessage(dbProcess(pDbChannel->addr.precord));
            if (dbErrorMessage) {
                throw std::runtime_error(dbErrorMessage.c_str());
            }
        }
    }
}

/**
 * Set a flag that will force processing of record in the specified security control object
 *
 * @param pvRequest the request
 * @param securityControlObject the security control object to update
 */
void IOCSource::setForceProcessingFlag(server::RemoteLogger *op, const Value& pvRequest,
                                       const std::shared_ptr<SecurityControlObject>& securityControlObject)
{
    auto proc = pvRequest["record._options.process"];
    bool b;
    std::string s;
    if(!proc) {
        return; // not provided

    } else if(proc.as(b)) { // actual bool, integer, or string parsable to bool
        securityControlObject->forceProcessing = b ? True : False;
        return;

    } else if(proc.as(s)) {
        if(s=="passive") {
            securityControlObject->forceProcessing = Unset;
            return;
        }
    }
    // oops, unsupported type or unexpected value
    op->logRemote(Level::Warn, SB()<<"Ignoring unsupported "<<pvRequest.nameOf(proc)<<": "<<proc);
}

static
void doDbPut(dbChannel* pDbChannel, short dbr, const void *pValueBuffer, size_t nElements)
{
    long status;
    if (dbChannelFieldType(pDbChannel) >= DBF_INLINK && dbChannelFieldType(pDbChannel) <= DBF_FWDLINK) {
        status = dbChannelPutField(pDbChannel, dbr, pValueBuffer, nElements);
    } else {
        status = dbChannelPut(pDbChannel, dbr, pValueBuffer, nElements);
    }
    DBErrorMessage dbErrorMessage(status);
    if (dbErrorMessage) {
        throw std::runtime_error(dbErrorMessage.c_str());
    }
}

static
void putScalar(dbChannel* pDbChannel, const Value& value)
{
    union {
        epicsUInt8 UCHAR;
        epicsUInt16 USHORT;
        epicsUInt32 ULONG;
        epicsUInt64 UINT64;
        epicsInt8 CHAR;
        epicsInt16 SHORT;
        epicsInt32 LONG;
        epicsInt64 INT64;
        float FLOAT;
        double DOUBLE;
        char STRING[MAX_STRING_SIZE];
    } buf;

    switch(dbChannelFinalFieldType(pDbChannel)) {
#define CASE(DBR, CTYPE) case DBR_ ## DBR: buf.DBR = value.as<CTYPE>(); break
    CASE(CHAR, int8_t);
    case DBR_ENUM:
    CASE(SHORT, int16_t);
    CASE(LONG, int32_t);
    CASE(UCHAR, uint8_t);
    CASE(USHORT, uint16_t);
    CASE(ULONG, uint32_t);
#ifdef DBR_INT64
    CASE(INT64, int64_t);
    CASE(UINT64, uint64_t);
#endif
    CASE(FLOAT, float);
    CASE(DOUBLE, double);
#undef CASE
    case DBR_STRING:
    {
        auto s(value.as<std::string>());
        strncpy(buf.STRING, s.c_str(), MAX_STRING_SIZE-1u);
        buf.STRING[MAX_STRING_SIZE-1u] = '\0';
        break;
    }
    default:
        throw std::logic_error(SB()<<__func__<<" unhandled case "<<dbChannelFinalFieldType(pDbChannel));
    }

    doDbPut(pDbChannel, dbChannelFinalFieldType(pDbChannel), &buf, 1u);
}

static
void putLongString(dbChannel* pDbChannel, const Value& value)
{
    auto str(value.as<std::string>());
    auto N = str.size()+1u; // include NIL

    doDbPut(pDbChannel, DBR_CHAR, str.c_str(), N);
}

static
void putStringArray(dbChannel* pDbChannel, const Value& value)
{
    auto arr = value.as<shared_array<const std::string>>();

    std::vector<char> buf(MAX_STRING_SIZE * arr.size());

    char* pCurrent = buf.data();
    for (auto& element: arr) {
        element.copy(pCurrent, MAX_STRING_SIZE - 1);
        pCurrent += MAX_STRING_SIZE;
    }

    doDbPut(pDbChannel, DBR_STRING, buf.data(), arr.size());
}

static
void putArray(dbChannel* pDbChannel, const Value& value)
{
    auto arr = value.as<shared_array<const void>>();

    short dbr;
    switch(arr.original_type()) {
    case ArrayType::Null:
        return;
    case ArrayType::Bool:
    case ArrayType::Value:
    default:
        throw std::runtime_error(SB()<<"Unsupported "<<__func__<<" from "<<arr.original_type());
    case ArrayType::Int8:    dbr = DBR_CHAR; break;
    case ArrayType::Int16:   dbr = DBR_SHORT; break;
    case ArrayType::Int32:   dbr = DBR_LONG; break;
    case ArrayType::UInt8:   dbr = DBR_UCHAR; break;
    case ArrayType::UInt16:  dbr = DBR_USHORT; break;
    case ArrayType::UInt32:  dbr = DBR_ULONG; break;
#ifdef DBR_INT64
    case ArrayType::Int64:   dbr = DBR_INT64; break;
    case ArrayType::UInt64:  dbr = DBR_UINT64; break;
#endif
    case ArrayType::Float32: dbr = DBR_FLOAT; break;
    case ArrayType::Float64: dbr = DBR_DOUBLE; break;
    case ArrayType::String:
        putStringArray(pDbChannel, value);
        return;
    }

    doDbPut(pDbChannel, dbr, arr.data(), arr.size());
}

/**
 * Put a given value to the specified channel.  Throw an exception if there are any errors.
 *
 * @param pDbChannel the channel to put the value into
 * @param value the value to put
 */
void IOCSource::put(dbChannel* pDbChannel, const Value& node, const MappingInfo &info) {
    Value value;
    switch(info.type) {
    case MappingInfo::Meta:
    case MappingInfo::Proc:
    case MappingInfo::Structure:
        return; // can't write
    case MappingInfo::Any:
        value = node["->"]; // de-ref into Any
        break;
    case MappingInfo::Plain:
        value = node;
        break;
    case MappingInfo::Scalar:
        value = node["value"];
        if(value.type()==TypeCode::Struct)
            value = value["index"]; // NTEnum
        break;
    case MappingInfo::Const:
        value = info.cval;
        break;
    }

    log_debug_printf(_log, "dbPut %s\n", pDbChannel->name);

    if (dbChannelFinalElements(pDbChannel) == 1) {
        putScalar(pDbChannel, value);
    } else if(dbChannelFinalFieldType(pDbChannel) == DBR_CHAR && value.type()==TypeCode::String) {
        putLongString(pDbChannel, value);
    } else if(dbChannelFinalFieldType(pDbChannel) == DBR_STRING) {
        putStringArray(pDbChannel, value);
    } else {
        putArray(pDbChannel, value);
    }
}

/**
 * Utility function to get the TypeCode that the given database channel is configured for
 *
 * @param pDbChannel the pointer to the database channel to get the TypeCode for
 * @param errOnLinks determines whether to throw an error on finding links, default no
 * @return the TypeCode that the channel is configured for
 */
TypeCode IOCSource::getChannelValueType(const Channel& chan, const bool errOnLinks) {
    /* for links, could check dbChannelFieldType().
     * for long strings, dbChannelCreate() '$' handling overwrites dbAddr::field_type
     *   (for some reason...)
     */
    if(!chan)
        throw std::runtime_error("Missing required +channel");
    auto field_type(dbChannelFldDes(chan)->field_type);
    auto final_field_type(dbChannelFinalFieldType(chan));

    if(errOnLinks && field_type >= DBF_INLINK && field_type <= DBF_OUTLINK)
        throw std::runtime_error("Link fields not allowed in this context");

    bool isArray = dbChannelFinalElements(chan)!=1;

    // string-like field being treated as single char[].  aka. long string
    if(final_field_type==DBR_CHAR && isArray && strcmp(chan.format(), "String")==0)
        return TypeCode::String;

    TypeCode valueType(fromDbrType(final_field_type));

    if(isArray)
        valueType = valueType.arrayOf();

    return valueType;
}

static
thread_local server::ExecOp* currentOp;

CurrentOp::CurrentOp(server::ExecOp *op)
    :prev(currentOp)
{
    currentOp = op;
}

CurrentOp::~CurrentOp()
{
    currentOp = prev;
}

server::ExecOp*
CurrentOp::current()
{
    return currentOp;
}

} // pvxs
} // ioc
