/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsExport.h>

static void installPVAAddLinkHook() {}

struct jlif {} lsetPVA;

extern "C" {
int pvaLinkDebug;
int pvaLinkNWorkers;

    epicsExportRegistrar(installPVAAddLinkHook);
    epicsExportAddress(jlif, lsetPVA);
    epicsExportAddress(int, pvaLinkDebug);
    epicsExportAddress(int, pvaLinkNWorkers);
}
