/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <sstream>

#include "pvalink.h"

#include <epicsStdio.h> // redirects stdout/stderr
#include <epicsExport.h>

namespace pvxs {
namespace ioc {
pvaLinkConfig::~pvaLinkConfig() {}

namespace {

/* link options.
 *
 * "pvname" # short-hand, sets PV name only
 *
 * {
 *  "pv":"name",
 *  "field":"blah.foo",
 *  "Q":5,
 *  "pipeline":false,
 *  "proc":true, // false, true, none, "", "NPP", "PP", "CP", "CPP"
 *  "sevr":true, // false, true, "NMS", "MS", "MSI", "MSS"
 *  "time":true, // false, true
 *  "monorder":#,// order of processing during CP scan
 *  "defer":true,// whether to immediately start Put, or only queue value to be sent
 *  "retry":true,// queue Put while disconnected, and retry on connect
 *  "always":true,// CP/CPP updates always process a like, even if its input field hasn't changed
 *  "local":false,// Require local channel
 * }
 */

jlink* pva_alloc_jlink(short) noexcept
{
    try {
        return new pvaLink;

    }catch(std::exception& e){
        errlogPrintf("Error allocating pva link: %s\n", e.what());
        return NULL;
    }
}

#define TRY  pvaLinkConfig *pvt = static_cast<pvaLinkConfig*>(pjlink); (void)pvt; try
#define CATCH(RET) catch(std::exception& e){ \
    errlogPrintf("Error in %s link: %s\n", __FUNCTION__, e.what()); \
    return RET; }

void pva_free_jlink(jlink *pjlink) noexcept
{
    TRY {
        delete pvt;
    }catch(std::exception& e){
        errlogPrintf("Error freeing pva link: %s\n", e.what());
    }
}

jlif_result pva_parse_null(jlink *pjlink) noexcept
{
    TRY {
        if(pvt->parseDepth!=1) {
            // ignore
        } else if(pvt->jkey == "proc") {
            pvt->proc = pvaLinkConfig::Default;
        } else if(pvt->jkey == "sevr") {
            pvt->sevr = pvaLinkConfig::NMS;
        } else if(pvt->jkey == "local") {
            pvt->local = false; // alias for local:false
        } else if(pvt->debug) {
            printf("pva link parsing unknown none depth=%u key=\"%s\"\n",
                   pvt->parseDepth, pvt->jkey.c_str());
        }

        pvt->jkey.clear();
        return jlif_continue;
    }CATCH(jlif_stop)
}

jlif_result pva_parse_bool(jlink *pjlink, int val) noexcept
{
    TRY {
//        TRACE(<<pvt->jkey<<" "<<(val?"true":"false"));
        if(pvt->parseDepth!=1) {
            // ignore
        } else if(pvt->jkey == "proc") {
            pvt->proc = val ? pvaLinkConfig::PP : pvaLinkConfig::NPP;
        } else if(pvt->jkey == "sevr") {
            pvt->sevr = val ? pvaLinkConfig::MS : pvaLinkConfig::NMS;
        } else if(pvt->jkey == "defer") {
            pvt->defer = !!val;
        } else if(pvt->jkey == "pipeline") {
            pvt->pipeline = !!val;
        } else if(pvt->jkey == "time") {
            pvt->time = !!val;
        } else if(pvt->jkey == "retry") {
            pvt->retry = !!val;
        } else if(pvt->jkey == "local") {
            pvt->local = !!val;
        } else if(pvt->jkey == "always") {
            pvt->always = !!val;
        } else if(pvt->jkey == "atomic") {
            pvt->atomic = !!val;
        } else if(pvt->debug) {
            printf("pva link parsing unknown integer depth=%u key=\"%s\" value=%s\n",
                   pvt->parseDepth, pvt->jkey.c_str(), val ? "true" : "false");
        }

        pvt->jkey.clear();
        return jlif_continue;
    }CATCH(jlif_stop)
}

jlif_result pva_parse_integer(jlink *pjlink, long long val) noexcept
{
    TRY {
        if(pvt->parseDepth!=1) {
            // ignore
        } else if(pvt->jkey == "Q") {
            pvt->queueSize = val < 1 ? 1 : size_t(val);
        } else if(pvt->jkey == "monorder") {
            pvt->monorder = std::max(-1024, std::min(int(val), 1024));
        } else if(pvt->debug) {
            printf("pva link parsing unknown integer depth=%u key=\"%s\" value=%lld\n",
                   pvt->parseDepth, pvt->jkey.c_str(), val);
        }

        pvt->jkey.clear();
        return jlif_continue;
    }CATCH(jlif_stop)
}

jlif_result pva_parse_string(jlink *pjlink, const char *val, size_t len) noexcept
{
    TRY{
        std::string sval(val, len);
        if(pvt->parseDepth==0 || (pvt->parseDepth==1 && pvt->jkey=="pv")) {
            pvt->channelName = sval;

        } else if(pvt->parseDepth > 1) {
            // ignore

        } else if(pvt->jkey=="field") {
            pvt->fieldName = sval;

        } else if(pvt->jkey=="proc") {
            if(sval.empty()) {
                pvt->proc = pvaLinkConfig::Default;
            } else if(sval=="CP") {
                pvt->proc = pvaLinkConfig::CP;
            } else if(sval=="CPP") {
                pvt->proc = pvaLinkConfig::CPP;
            } else if(sval=="PP") {
                pvt->proc = pvaLinkConfig::PP;
            } else if(sval=="NPP") {
                pvt->proc = pvaLinkConfig::NPP;
            } else if(pvt->debug) {
                printf("pva link parsing unknown proc depth=%u key=\"%s\" value=\"%s\"\n",
                       pvt->parseDepth, pvt->jkey.c_str(), sval.c_str());
            }

        } else if(pvt->jkey=="sevr") {
            if(sval=="NMS") {
                pvt->sevr = pvaLinkConfig::NMS;
            } else if(sval=="MS") {
                pvt->sevr = pvaLinkConfig::MS;
            } else if(sval=="MSI") {
                pvt->sevr = pvaLinkConfig::MSI;
            } else if(sval=="MSS") {
                // not sure how to handle mapping severity for MSS.
                // leave room for this to happen compatibly later by
                // handling as alias for MS until then.
                pvt->sevr = pvaLinkConfig::MS;
            } else if(pvt->debug) {
                printf("pva link parsing unknown sevr depth=%u key=\"%s\" value=\"%s\"\n",
                       pvt->parseDepth, pvt->jkey.c_str(), sval.c_str());
            }

        } else if(pvt->debug) {
            printf("pva link parsing unknown string depth=%u key=\"%s\" value=\"%s\"\n",
                   pvt->parseDepth, pvt->jkey.c_str(), sval.c_str());
        }

        pvt->jkey.clear();
        return jlif_continue;
    }CATCH(jlif_stop)
}

jlif_key_result pva_parse_start_map(jlink *pjlink) noexcept
{
    TRY {
        return jlif_key_continue;
    }CATCH(jlif_key_stop)
}

jlif_result pva_parse_key_map(jlink *pjlink, const char *key, size_t len) noexcept
{
    TRY {
        std::string sval(key, len);
        pvt->jkey = sval;

        return jlif_continue;
    }CATCH(jlif_stop)
}

jlif_result pva_parse_end_map(jlink *pjlink) noexcept
{
    TRY {
        return jlif_continue;
    }CATCH(jlif_stop)
}

struct lset* pva_get_lset(const jlink *pjlink) noexcept
{
    return &pva_lset;
}

void pva_report(const jlink *rpjlink, int lvl, int indent) noexcept
{
    const pvaLink *pval = static_cast<const pvaLink*>(rpjlink);
    try {
        (void)pval;
        printf("%*s'pva': %s", indent, "", pval->channelName.c_str());
        if(!pval->fieldName.empty())
            printf("|.%s", pval->fieldName.c_str());

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
        if(lvl>0) {
            printf(" Q=%u pipe=%c defer=%c time=%c retry=%c atomic=%c morder=%d",
                   unsigned(pval->queueSize),
                   pval->pipeline ? 'T' : 'F',
                   pval->defer ? 'T' : 'F',
                   pval->time ? 'T' : 'F',
                   pval->retry ? 'T' : 'F',
                   pval->atomic ? 'T' : 'F',
                   pval->monorder);
        }

        if(pval->lchan) {
            // after open()
            Guard G(pval->lchan->lock);

            printf(" conn=%c", pval->lchan->connected ? 'T' : 'F');
            if(pval->lchan->op_put) {
                printf(" Put");
            }

            if(lvl>0) {
                printf(" #disconn=%zu", pval->lchan->num_disconnect);
            }
//            if(lvl>5) {
//                std::ostringstream strm;
//                pval->lchan->chan.show(strm);
//                printf("\n%*s   CH: %s", indent, "", strm.str().c_str());
//            }
        } else {
            printf(" No Channel");
        }
        printf("\n");
    }CATCH()
}

} //namespace

jlif lsetPVA = {
    "pva",
    &pva_alloc_jlink,
    &pva_free_jlink,
    &pva_parse_null,
    &pva_parse_bool,
    &pva_parse_integer,
    NULL,
    &pva_parse_string,
    &pva_parse_start_map,
    &pva_parse_key_map,
    &pva_parse_end_map,
    NULL,
    NULL,
    NULL,
    &pva_get_lset,
    &pva_report,
    NULL
};

}} //namespace pvxs::ioc

extern "C" {
using pvxs::ioc::lsetPVA;
epicsExportAddress(jlif, lsetPVA);
}
