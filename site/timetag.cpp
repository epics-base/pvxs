/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Implements Q:time:tag: packs low bits of the nanoseconds timestamp into
// timeStamp.userTag and clears those bits from timeStamp.nanoseconds.
//
// info(Q:time:tag, "nsec:lsb:<N>") on a record reserves the lowest N bits of
// the nsec field for a user-defined tag.  After IOCSource::get() writes the
// raw nsec value, this post-processor overwrites both fields:
//   timeStamp.nanoseconds &= ~mask        (clear the tag bits)
//   timeStamp.userTag      = nsec & mask  (expose the tag bits)
//
// Implemented as a site-extension post-processor so it works regardless of
// whether DBR_UTAG is defined in the target EPICS Base.
//
// Behaviour change vs. the original in-tree implementation: on EPICS Base
// versions without DBR_UTAG, the old code still masked timeStamp.nanoseconds
// but had nowhere to put the extracted bits, so they were silently dropped
// and timeStamp.userTag stayed 0. This post-processor runs unconditionally,
// so userTag is now populated even when DBR_UTAG is unavailable.

#include <cstdlib>
#include <cstring>
#include <unordered_map>

#include <dbCommon.h>
#include <dbStaticLib.h>

#include "dbentry.h"
#include "sitehooks.h"

namespace {

std::unordered_map<dbCommon*, uint32_t>& nsecMaskCache() {
    static std::unordered_map<dbCommon*, uint32_t> s;
    return s;
}

void onBeginning() { nsecMaskCache().clear(); }

void onIocBuilt()
{
    auto& cache = nsecMaskCache();
    pvxs::ioc::DBEntry ent;
    for (long s = dbFirstRecordType(ent); !s; s = dbNextRecordType(ent)) {
        for (s = dbFirstRecord(ent); !s; s = dbNextRecord(ent)) {
            auto* prec = static_cast<dbCommon*>(ent->precnode->precord);
            const char* val = ent.info("Q:time:tag");
            if (!val || strncmp(val, "nsec:lsb:", 9) != 0)
                continue;
            char* end = nullptr;
            long dig = strtol(val + 9, &end, 10);
            if (end == val + 9 || *end != '\0' || dig < 1 || dig > 32)
                continue;
            // Shift by (32 - dig), not by dig: dig may be 32, and shifting a
            // 32-bit value by 32 is undefined behaviour in C++.  32 - dig is
            // always in [0, 31], so this form is safe for the full range.
            cache[prec] = ~uint32_t(0u) >> (32 - dig);
        }
    }
}

void applyTimeTag(dbCommon* prec, pvxs::Value& node)
{
    auto& cache = nsecMaskCache();
    auto it = cache.find(prec);
    if (it == cache.end())
        return;
    uint32_t nsecMask = it->second;
    uint32_t nsec = prec->time.nsec;
    node["timeStamp.nanoseconds"] = int32_t(nsec & ~nsecMask);
    node["timeStamp.userTag"]     = int32_t(nsec &  nsecMask);
}

} // namespace

namespace pvxs { namespace ioc { namespace site {
void registerTimetag() {
    addInitHookAtBeginning(onBeginning);
    addInitHookAfterIocBuilt(onIocBuilt);
    addNodePostProcessor(applyTimeTag);
}
}}} // pvxs::ioc::site
