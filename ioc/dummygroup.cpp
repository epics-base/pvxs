#include <pvxs/iochooks.h>
#include "utilpvt.h"

#include <epicsStdio.h>
#include <epicsExport.h>

namespace pvxs {
namespace ioc {
long dbLoadGroup(const char* jsonFilename, const char* macros) {
    fprintf(stderr, "QSRV2 groups not supported with Base <3.16\n");
    return -1;
}

void IOCGroupConfigCleanup() {}

}}

static
void pvxsGroupSourceRegistrar() {}

extern "C" {
epicsExportRegistrar(pvxsGroupSourceRegistrar);
}
