/* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <typeinfo>

#include <alarm.h>
#include <dbAccess.h>
#include <devSup.h>
#include <recSup.h>
#include <recGbl.h>
#include <dbStaticLib.h>
#include <epicsTime.h>

#include <pvxs/nt.h>
#include <pvxs/log.h>
#include <pvxs/iochooks.h>

#define GEN_SIZE_OFFSET
#include "qstringinRecord.h"
#undef GEN_SIZE_OFFSET

#include <epicsExport.h>

DEFINE_LOGGER(_log, "pvxs.ioc.qstringin");

namespace {
using namespace pvxs;

long init_record(struct dbCommon *pcommon, int pass) noexcept
{
    try {
        auto prec = reinterpret_cast<qstringinRecord*>(pcommon);
        auto pdset = reinterpret_cast<qstringindset*>(prec->dset);

        if (pass == 0) return 0;

        if (!pdset) {
            recGblRecordError(S_dev_noDSET, prec, "qstringin: init_record");
            return S_dev_noDSET;

        } else if ((pdset->common.number < 5) || (pdset->read_qstringin == NULL)) {
            recGblRecordError(S_dev_missingSup, prec, "qstringin: init_record");
            return S_dev_missingSup;
        }

        prec->val = nt::NTScalar{TypeCode::String}.create();

        if (pdset->common.init_record) {
            long status = pdset->common.init_record(pcommon);

            if (status)
                return status;
        }
        prec->val["alarm.severity"] = prec->sevr;
        prec->oval = prec->val.clone();
        return 0;
    } catch(std::exception& e) {
        log_exc_printf(_log, "%s: unhandled exception %s: %s\n", __func__,
                       typeid(e).name(), e.what());
    }
    return S_dbLib_noRecSup;
}

long readValue(qstringinRecord *prec)
{
    auto pdset = reinterpret_cast<qstringindset*>(prec->dset);

    try{
        return pdset->read_qstringin(prec);
    }catch(std::exception& e){
        recGblSetSevrMsg(prec, READ_ALARM, INVALID_ALARM, "%s", e.what());
        return S_db_BadSub;
    }
}

void monitor(qstringinRecord *prec)
{
    int monitor_mask = recGblResetAlarms(prec);

    auto fval(prec->val["value"]);
    auto foval(prec->oval["value"]);
    auto val = fval.as<std::string>();
    auto oval = foval.as<std::string>();

    if(prec->mpst==qstringinPOST_Always || val!=oval) {
        monitor_mask |= DBE_VALUE|DBE_ALARM;
    } else {
        fval.unmark();
    }

    if(monitor_mask & DBE_ALARM) {
        prec->val["alarm.severity"] = prec->sevr;
        // TODO: status/amsg
    }
    {
        prec->val["timeStamp.secondsPastEpoch"] = prec->time.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH;
        prec->val["timeStamp.nanoseconds"] = prec->time.nsec;
        prec->val["timeStamp.userTag"] = prec->utag;
    }

    ioc::qfield_post(&prec->val);
    ioc::qfield_post(&prec->oval);

    foval.from(val);
}

long process(struct dbCommon *pcommon) noexcept
{
    try {
        auto prec = reinterpret_cast<qstringinRecord*>(pcommon);
        auto pdset = reinterpret_cast<qstringindset*>(prec->dset);
        auto pact = prec->pact;

        if( (pdset==NULL) || (pdset->read_qstringin==NULL) ) {
            prec->pact=TRUE;
            recGblRecordError(S_dev_missingSup, prec, "read_qstringin");
            return (S_dev_missingSup);
        }

        prec->oval.unmark();
        prec->oval.from(prec->val);
        prec->val.unmark();

        auto status = readValue(prec); /* read the new value */
        /* check if device support set pact */
        if ( !pact && prec->pact ) return(0);

        prec->pact = TRUE;
        recGblGetTimeStamp(prec);

        /* check event list */
        monitor(prec);
        /* process the forward scan link record */
        recGblFwdLink(prec);

        prec->pact=FALSE;
        return(status);

    } catch(std::exception& e) {
        log_exc_printf(_log, "%s: unhandled exception %s: %s\n", __func__,
                       typeid(e).name(), e.what());
    }
    return S_dbLib_noRecSup;
}

rset qstringinRSET = {
    RSETNUMBER,
    nullptr,
    nullptr,
    init_record,
    process,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};
} // namespace

extern "C" {
epicsExportAddress(rset, qstringinRSET);
}
