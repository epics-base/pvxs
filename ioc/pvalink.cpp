
#include <set>
#include <map>

#define EPICS_DBCA_PRIVATE_API
#include <epicsGuard.h>
#include <dbAccess.h>
#include <dbCommon.h>
#include <dbLink.h>
#include <dbScan.h>
#include <errlog.h>
#include <initHooks.h>
#include <alarm.h>
#include <epicsExit.h>
#include <epicsAtomic.h>
#include <link.h>
#include <dbJLink.h>
#include <epicsUnitTest.h>
#include <epicsString.h>

#include <epicsStdio.h> /* redirects stdout/stderr */

#include <pv/pvAccess.h>
#include <pv/clientFactory.h>
#include <pv/iocshelper.h>
#include <pv/reftrack.h>
#include <pva/client.h>

#include "pv/qsrv.h"
#include "helper.h"
#include "pvif.h"
#include "pvalink.h"

#include <epicsExport.h> /* defines epicsExportSharedSymbols */

#if EPICS_VERSION_INT>=VERSION_INT(7,0,6,0)
#  define HAVE_SHUTDOWN_HOOKS
#endif

int pvaLinkDebug;
int pvaLinkIsolate;

using namespace pvalink;

namespace {

// halt, and clear, scan workers before dbCloseLinks()  (cf. iocShutdown())
static void shutdownStep1()
{
    // no locking here as we assume that shutdown doesn't race startup
    if(!pvaGlobal) return;

    pvaGlobal->queue.close();
}

// Cleanup pvaGlobal, including PVA client and QSRV providers ahead of PDB cleanup
// specifically QSRV provider must be free'd prior to db_cleanup_events()
static void shutdownStep2()
{
    if(!pvaGlobal) return;

    {
        Guard G(pvaGlobal->lock);
        if(pvaGlobal->channels.size()) {
            fprintf(stderr, "pvaLink leaves %zu channels open\n",
                    pvaGlobal->channels.size());
        }
    }

    delete pvaGlobal;
    pvaGlobal = NULL;
}

#ifndef HAVE_SHUTDOWN_HOOKS
static void stopPVAPool(void*)
{
    try {
        shutdownStep1();
    }catch(std::exception& e){
        fprintf(stderr, "Error while stopping PVA link pool : %s\n", e.what());
    }
}

static void finalizePVA(void*)
{
    try {
        shutdownStep2();
    }catch(std::exception& e){
        fprintf(stderr, "Error initializing pva link handling : %s\n", e.what());
    }
}
#endif

/* The Initialization game...
 *
 * #   Parse links during dbPutString()  (calls our jlif*)
 * # announce initHookAfterCaLinkInit
 * #   dbChannelInit() (needed for QSRV to work)
 * #   Re-parse links (calls to our jlif*)
 * #   Open links.  Calls jlif::get_lset() and then lset::openLink()
 * # announce initHookAfterInitDatabase
 * #   ... scan threads start ...
 * # announce initHookAfterIocBuilt
 */
void initPVALink(initHookState state)
{
    try {
        if(state==initHookAfterCaLinkInit) {
            // before epicsExit(exitDatabase),
            // so hook registered here will be run after iocShutdown()
            // which closes links
            if(pvaGlobal) {
                cantProceed("# Missing call to testqsrvShutdownOk() and/or testqsrvCleanup()");
            }
            pvaGlobal = new pvaGlobal_t;

#ifndef HAVE_SHUTDOWN_HOOKS
            static bool atexitInstalled;
            if(!atexitInstalled) {
                epicsAtExit(finalizePVA, NULL);
                atexitInstalled = true;
            }
#endif

        } else if(state==initHookAfterInitDatabase) {
            pvac::ClientProvider local("server:QSRV"),
                                 remote("pva");
            pvaGlobal->provider_local = local;
            pvaGlobal->provider_remote = remote;

        } else if(state==initHookAfterIocBuilt) {
            // after epicsExit(exitDatabase)
            // so hook registered here will be run before iocShutdown()

#ifndef HAVE_SHUTDOWN_HOOKS
            epicsAtExit(stopPVAPool, NULL);
#endif

            Guard G(pvaGlobal->lock);
            pvaGlobal->running = true;

            for(pvaGlobal_t::channels_t::iterator it(pvaGlobal->channels.begin()), end(pvaGlobal->channels.end());
                it != end; ++it)
            {
                std::tr1::shared_ptr<pvaLinkChannel> chan(it->second.lock());
                if(!chan) continue;

                chan->open();
            }
#ifdef HAVE_SHUTDOWN_HOOKS
        } else if(state==initHookAtShutdown) {
            shutdownStep1();

        } else if(state==initHookAfterShutdown) {
            shutdownStep2();
#endif
        }
    }catch(std::exception& e){
        cantProceed("Error initializing pva link handling : %s\n", e.what());
    }
}

} // namespace

// halt, and clear, scan workers before dbCloseLinks()  (cf. iocShutdown())
void testqsrvShutdownOk(void)
{
    try {
        shutdownStep1();
    }catch(std::exception& e){
        testAbort("Error while stopping PVA link pool : %s\n", e.what());
    }
}

void testqsrvCleanup(void)
{
    try {
        shutdownStep2();
    }catch(std::exception& e){
        testAbort("Error initializing pva link handling : %s\n", e.what());
    }
}

void testqsrvWaitForLinkEvent(struct link *plink)
{
    std::tr1::shared_ptr<pvaLinkChannel> lchan;
    {
        DBScanLocker lock(plink->precord);

        if(plink->type!=JSON_LINK || !plink->value.json.jlink || plink->value.json.jlink->pif!=&lsetPVA) {
            testAbort("Not a PVA link");
        }
        pvaLink *pval = static_cast<pvaLink*>(plink->value.json.jlink);
        lchan = pval->lchan;
    }
    if(lchan) {
        lchan->run_done.wait();
    }
}

extern "C"
void dbpvar(const char *precordname, int level)
{
    try {
        if(!pvaGlobal) {
            printf("PVA links not initialized\n");
            return;
        }

        if (!precordname || precordname[0] == '\0' || !strcmp(precordname, "*")) {
            precordname = NULL;
            printf("PVA links in all records\n\n");
        } else {
            printf("PVA links in record named '%s'\n\n", precordname);
        }

        size_t nchans = 0, nlinks = 0, nconn = 0;

        pvaGlobal_t::channels_t channels;
        {
            Guard G(pvaGlobal->lock);
            channels = pvaGlobal->channels; // copy snapshot
        }

        for(pvaGlobal_t::channels_t::const_iterator it(channels.begin()), end(channels.end());
            it != end; ++it)
        {
            std::tr1::shared_ptr<pvaLinkChannel> chan(it->second.lock());
            if(!chan) continue;

            Guard G(chan->lock);

            if(precordname) {
                // only show links fields of these records
                bool match = false;
                for(pvaLinkChannel::links_t::const_iterator it2(chan->links.begin()), end2(chan->links.end());
                    it2 != end2; ++it2)
                {
                    const pvaLink *pval = *it2;
                    // plink==NULL shouldn't happen, but we are called for debugging, so be paranoid.
                    if(pval->plink && epicsStrGlobMatch(pval->plink->precord->name, precordname)) {
                        match = true;
                        nlinks++;
                    }
                }
                if(!match)
                    continue;
            }

            nchans++;
            if(chan->connected_latched)
                nconn++;

            if(!precordname)
                nlinks += chan->links.size();

            if(level<=0)
                continue;

            if(level>=2 || (!chan->connected_latched && level==1)) {
                if(chan->key.first.size()<=28) {
                    printf("%28s ", chan->key.first.c_str());
                } else {
                    printf("%s\t", chan->key.first.c_str());
                }

                printf("conn=%c %zu disconnects, %zu type changes",
                       chan->connected_latched?'T':'F',
                       chan->num_disconnect,
                       chan->num_type_change);
                if(chan->op_put.valid()) {
                    printf(" Put");
                }

                if(level>=3) {
                    printf(", provider '%s'", chan->providerName.c_str());
                }
                printf("\n");
                // level 4 reserved for channel/provider details

                if(level>=5) {
                    for(pvaLinkChannel::links_t::const_iterator it2(chan->links.begin()), end2(chan->links.end());
                        it2 != end2; ++it2)
                    {
                        const pvaLink *pval = *it2;

                        if(!pval->plink)
                            continue;
                        else if(precordname && !epicsStrGlobMatch(pval->plink->precord->name, precordname))
                            continue;

                        const char *fldname = "???";
                        pdbRecordIterator rec(pval->plink->precord);
                        for(bool done = !!dbFirstField(&rec.ent, 0); !done; done = !!dbNextField(&rec.ent, 0))
                        {
                            if(rec.ent.pfield == (void*)pval->plink) {
                                fldname = rec.ent.pflddes->name;
                                break;
                            }
                        }

                        printf("%*s%s.%s", 30, "", pval->plink ? pval->plink->precord->name : "<NULL>", fldname);

                        switch(pval->pp) {
                        case pvaLinkConfig::NPP: printf(" NPP"); break;
                        case pvaLinkConfig::Default: printf(" Def"); break;
                        case pvaLinkConfig::PP: printf(" PP"); break;
                        case pvaLinkConfig::CP: printf(" CP"); break;
                        case pvaLinkConfig::CPP: printf(" CPP"); break;
                        }
                        switch(pval->ms) {
                        case pvaLinkConfig::NMS: printf(" NMS"); break;
                        case pvaLinkConfig::MS:  printf(" MS"); break;
                        case pvaLinkConfig::MSI: printf(" MSI"); break;
                        }

                        printf(" Q=%u pipe=%c defer=%c time=%c retry=%c morder=%d\n",
                               unsigned(pval->queueSize),
                               pval->pipeline ? 'T' : 'F',
                               pval->defer ? 'T' : 'F',
                               pval->time ? 'T' : 'F',
                               pval->retry ? 'T' : 'F',
                               pval->monorder);
                    }
                    printf("\n");
                }
            }
        }

        printf("  %zu/%zu channels connected used by %zu links\n",
               nconn, nchans, nlinks);

    } catch(std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
    }
}

static
void installPVAAddLinkHook()
{
    initHookRegister(&initPVALink);
    epics::iocshRegister<const char*, int, &dbpvar>("dbpvar", "record name", "level");
    epics::registerRefCounter("pvaLinkChannel", &pvaLinkChannel::num_instances);
    epics::registerRefCounter("pvaLink", &pvaLink::num_instances);
}

extern "C" {
    epicsExportRegistrar(installPVAAddLinkHook);
    epicsExportAddress(jlif, lsetPVA);
    epicsExportAddress(int, pvaLinkDebug);
    epicsExportAddress(int, pvaLinkNWorkers);
}
