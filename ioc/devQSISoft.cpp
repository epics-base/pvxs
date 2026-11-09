/* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define USE_TYPED_DSET

#include <alarm.h>
#include <dbAccess.h>
#include <dbLink.h>
#include <recGbl.h>

#include "qstringinRecord.h"

#include <epicsExport.h>

namespace {

long init_record(dbCommon *pcommon)
{
    auto prec = reinterpret_cast<qstringinRecord*>(pcommon);

    char scratch[MAX_STRING_SIZE];
    if(recGblInitConstantLink(&prec->inp, DBF_STRING, scratch)) {
        prec->udf = FALSE;
        prec->val["value"] = scratch;
    }
    return 0;
}

static long readLocked(struct link *pinp, void *dummy)
{
    auto prec = reinterpret_cast<qstringinRecord*>(pinp->precord);

    // TODO: peek into pvalink?
    char scratch[MAX_STRING_SIZE] = "<invalid>";
    long status = dbGetLink(pinp, DBR_STRING, scratch, 0, 0);

    if (status) return status;
    if (!dbLinkIsConstant(&prec->inp))
        prec->val["value"] = scratch;

    if (dbLinkIsConstant(&prec->tsel) && prec->tse == epicsTimeEventDeviceTime)
        status = dbGetTimeStamp(pinp, &prec->time);

    return status;
}

long read_qstringin(qstringinRecord *prec)
{
    long status = dbLinkDoLocked(&prec->inp, readLocked, NULL);

    if (status == S_db_noLSET)
        status = readLocked(&prec->inp, NULL);

    if (!status && !dbLinkIsConstant(&prec->inp))
        prec->udf = FALSE;

    return status;
}

qstringindset devQSISoft = {
    {5, NULL, NULL, init_record, NULL},
    read_qstringin
};
} // namespace

extern "C" {
epicsExportAddress(dset, devQSISoft);
}
