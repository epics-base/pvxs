#include <epicsExport.h>

static
void pvxsSingleSourceRegistrar() {}

extern "C" {
epicsExportRegistrar(pvxsSingleSourceRegistrar);
}
