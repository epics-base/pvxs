/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <set>
#include <map>

#include <string.h>

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
#include <errlog.h>
#include <link.h>
#include <dbJLink.h>
#include <epicsUnitTest.h>
#include <epicsString.h>

#define PVXS_ENABLE_EXPERT_API

#include <pvxs/server.h>

#include "channel.h"
#include "pvalink.h"
#include "dblocker.h"
#include "dbentry.h"
#include "iocshcommand.h"
#include "utilpvt.h"
#include "qsrvpvt.h"

#include <epicsStdio.h>  /* redirects stdout/stderr; include after util.h from libevent */
#include <epicsExport.h> /* defines epicsExportSharedSymbols */

#if EPICS_VERSION_INT>=VERSION_INT(7,0,6,0)
#  define HAVE_SHUTDOWN_HOOKS
#endif

namespace pvxs {
namespace ioc {

void linkGlobal_t::alloc()
{
    if(linkGlobal) {
        cantProceed("# Missing call to testqsrvShutdownOk() and/or testqsrvCleanup()");
    }
    linkGlobal = new linkGlobal_t;

    // TODO "local" provider
    if (inUnitTest()) {
        linkGlobal->provider_remote = ioc::server().clientConfig().build();
    } else {
        linkGlobal->provider_remote = client::Config().build();
    }
}

void linkGlobal_t::init()
{
    Guard G(linkGlobal->lock);
    linkGlobal->running = true;

    for(linkGlobal_t::channels_t::iterator it(linkGlobal->channels.begin()), end(linkGlobal->channels.end());
        it != end; ++it)
    {
        std::shared_ptr<pvaLinkChannel> chan(it->second.lock());
        if(!chan) continue;

        chan->open();
    }
}

void linkGlobal_t::deinit()
{
    // no locking here as we assume that shutdown doesn't race startup
    if(!linkGlobal) return;

    linkGlobal->close();
}

void linkGlobal_t::dtor()
{
    if(!linkGlobal) return;
    {
        Guard G(linkGlobal->lock);
        assert(pvaLink::cnt_pvaLink<=1u); // dbRemoveLink() already called
        assert(linkGlobal->channels.empty());
    }

    delete linkGlobal;
    linkGlobal = NULL;
}

static
std::shared_ptr<pvaLinkChannel> testGetPVALink(struct link *plink)
{
    DBLocker lock(plink->precord);

    if(plink->type!=JSON_LINK || !plink->value.json.jlink || plink->value.json.jlink->pif!=&lsetPVA) {
        testAbort("Not a PVA link");
    }
    pvaLink *pval = static_cast<pvaLink*>(plink->value.json.jlink);
    if(!pval->lchan)
        testAbort("PVA link w/o channel?");
    return pval->lchan;
}

static
DBLINK* testGetLink(const char *pv)
{
    Channel chan(pv);
    switch(dbChannelFieldType(chan)) {
    case DBF_INLINK:
    case DBF_OUTLINK:
    case DBF_FWDLINK:
        break;
    default:
        testAbort("%s : not a link field", pv);
    }
    return static_cast<struct link*>(dbChannelField(chan));
}

void testqsrvWaitForLinkConnected(struct link *plink, bool conn)
{
    if(conn)
        linkGlobal->provider_remote.hurryUp();
    std::shared_ptr<pvaLinkChannel> lchan(testGetPVALink(plink));
    Guard G(lchan->lock);
    while(lchan->connected!=conn) {
        testDiag("%s(\"%s\", %c) sleep", __func__, plink->precord->name, conn?'C':'D');
        UnGuard U(G);
        if(!lchan->update_evt.wait(10.0))
            testAbort("%s(\"%s\") timeout", __func__, plink->precord->name);
        errlogFlush();
        testDiag("%s(\"%s\") wakeup", __func__, plink->precord->name);
    }
    errlogFlush();
}

void testqsrvWaitForLinkConnected(const char* pv, bool conn)
{
    testqsrvWaitForLinkConnected(testGetLink(pv), conn);
}

QSrvWaitForLinkUpdate::QSrvWaitForLinkUpdate(struct link *plink)
    :plink(plink)
{
    std::shared_ptr<pvaLinkChannel> lchan(testGetPVALink(plink));
    Guard G(lchan->lock);
    seq = lchan->update_seq;
    testDiag("%s(\"%s\") arm at %u", __func__, plink->precord->name, seq);
}

QSrvWaitForLinkUpdate::QSrvWaitForLinkUpdate(const char *pv)
    :QSrvWaitForLinkUpdate(testGetLink(pv))
{}

QSrvWaitForLinkUpdate::~QSrvWaitForLinkUpdate()
{
    std::shared_ptr<pvaLinkChannel> lchan(testGetPVALink(plink));
    Guard G(lchan->lock);
    while(seq == lchan->update_seq) {
        testDiag("%s(\"%s\") wait for end of %u", __func__, plink->precord->name, seq);
        bool ok;
        {
            UnGuard U(G);
            ok = lchan->update_evt.wait(5.0);
        }
        if(!ok)
            testAbort("%s(\"%s\") timeout at %u", __func__, plink->precord->name, seq);
        errlogFlush();
        testDiag("%s(\"%s\") wake at %u", __func__, plink->precord->name, seq);
    }
}

extern "C"
void dbpvar(const char *precordname, int level)
{
    try {
        if(!linkGlobal) {
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

        linkGlobal_t::channels_t channels;
        {
            Guard G(linkGlobal->lock);
            channels = linkGlobal->channels; // copy snapshot
        }

        for(linkGlobal_t::channels_t::const_iterator it(channels.begin()), end(channels.end());
            it != end; ++it)
        {
            std::shared_ptr<pvaLinkChannel> chan(it->second.lock());
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
            if(chan->connected)
                nconn++;

            if(!precordname)
                nlinks += chan->links.size();

            if(level<=0)
                continue;

            if(level>=2 || (!chan->connected && level==1)) {
                if(chan->key.first.size()<=28) {
                    printf("%28s ", chan->key.first.c_str());
                } else {
                    printf("%s\t", chan->key.first.c_str());
                }

                printf("conn=%c %zu disconnects, %zu type changes",
                       chan->connected?'T':'F',
                       chan->num_disconnect,
                       chan->num_type_change);
                if(chan->op_put) {
                    printf(" Put");
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
                        ioc::DBEntry rec(pval->plink->precord);
                        for(bool done = !!dbFirstField(rec, 0); !done; done = !!dbNextField(rec, 0))
                        {
                            if(rec->pfield == (void*)pval->plink) {
                                fldname = rec->pflddes->name;
                                break;
                            }
                        }

                        printf("%*s%s.%s", 30, "", pval->plink ? pval->plink->precord->name : "<NULL>", fldname);

                        switch(pval->proc) {
                        case pvaLinkConfig::NPP: printf(" NPP"); break;
                        case pvaLinkConfig::Default: printf(" Def"); break;
                        case pvaLinkConfig::PP: printf(" PP"); break;
                        case pvaLinkConfig::CP: printf(" CP"); break;
                        case pvaLinkConfig::CPP: printf(" CPP"); break;
                        }
                        switch(pval->sevr) {
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
const iocshVarDef pvaLinkNWorkersDef[] = {
    {
        "pvaLinkNWorkers",
        iocshArgInt,
        &pvaLinkNWorkers
    },
    {0, iocshArgInt, 0}
};

void pvalink_enable()
{
    IOCShCommand<const char*, int>("dbpvar", "dbpvar", "record name", "level")
            .implementation<&dbpvar>();
    iocshRegisterVariable(pvaLinkNWorkersDef);

}

}} // namespace pvxs::ioc
