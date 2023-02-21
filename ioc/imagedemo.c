
#include <stdlib.h>

#include <epicsMath.h>
#include <dbAccess.h>
#include <dbScan.h>
#include <recGbl.h>
#include <alarm.h>
#include <registryFunction.h>

#include <aSubRecord.h>

#include <epicsExport.h>

/** Generate a test pattern
 *
 * A - width (ULONG)
 * B - height (ULONG)
 * VALA - pixel array (USHORT)
 */
static
long QSRV2_image_demo(aSubRecord* prec) {
    epicsUInt32 H = *(epicsUInt32*)prec->a,
            W = *(epicsUInt32*)prec->b;
    epicsUInt16* I = (epicsUInt16*)prec->vala;
    epicsUInt32 i, j;

    if (W * H > prec->nova) {
        (void)recGblSetSevr(prec, READ_ALARM, INVALID_ALARM);
        return 0;
    }

    for (i = 0; i < W; i++) {
        for (j = 0; j < H; j++) {
            if (i % 50 == 49 || j % 50 == 49)
                I[i * H + j] = 65535;
            else
                I[i * H + j] = ((epicsUInt32)j) * 65535 / H;
        }
    }

    prec->neva = W * H;
    return 0;
}

epicsRegisterFunction(QSRV2_image_demo);
