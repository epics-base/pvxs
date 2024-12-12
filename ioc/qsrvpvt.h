/* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef QSRVPVT_H
#define QSRVPVT_H

#include <pvxs/version.h>
#include <pvxs/iochooks.h>

namespace pvxs {
namespace ioc {

#if EPICS_VERSION_INT >= VERSION_INT(3, 15, 0 ,0)
#  define USE_QSRV_SINGLE
void single_enable();
void dbRegisterQSRV2();
void addSingleSrc();
#else
static inline void single_enable() {}
static inline void dbRegisterQSRV2() {}
static inline void addSingleSrc() {}
#endif

#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 0 ,0)
#  define USE_PVA_LINKS
void group_enable();
void pvalink_enable();
void processGroups();
void addGroupSrc();
void resetGroups();
#else
static inline void group_enable() {}
static inline void pvalink_enable() {}
static inline void processGroups() {}
static inline void addGroupSrc() {}
static inline void resetGroups() {}
#endif

#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 4, 0)
#  define USE_DEINIT_HOOKS
#endif
#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 8, 0)
#  define USE_PREPARE_CLEANUP_HOOKS
#endif

#ifdef USE_PVA_LINKS
// test utilities for PVA links

PVXS_IOC_API
void testqsrvWaitForLinkConnected(struct link *plink, bool conn=true);
PVXS_IOC_API
void testqsrvWaitForLinkConnected(const char* pv, bool conn=true);

class PVXS_IOC_API QSrvWaitForLinkUpdate final {
    struct link * const plink;
    unsigned seq;
public:
    QSrvWaitForLinkUpdate(struct link *plink);
    QSrvWaitForLinkUpdate(const char* pv);
    ~QSrvWaitForLinkUpdate();
};
#endif

}} // namespace pvxs::ioc

#endif // QSRVPVT_H
