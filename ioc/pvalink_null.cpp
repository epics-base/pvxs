
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
