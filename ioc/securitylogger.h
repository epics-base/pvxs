/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_SECURITYLOGGER_H
#define PVXS_SECURITYLOGGER_H

#include <algorithm>
#include <asLib.h>
#include <dbChannel.h>

#include "credentials.h"
#include "securityclient.h"

namespace pvxs {
namespace ioc {

class SecurityLogger {
    void* pfieldsave = nullptr;
    dbChannel *pchan = nullptr;
    void* pvt;
public:
    ~SecurityLogger() {
        asTrapWriteAfterWrite(pvt);
        // asTrapWrite callbacks may have clobbered pfield
        if(pchan)
            pchan->addr.pfield = pfieldsave;
    }

    void swap(SecurityLogger& o) {
        std::swap(pfieldsave, o.pfieldsave);
        std::swap(pchan, o.pchan);
        std::swap(pvt, o.pvt);
    }

    SecurityLogger()
            :pvt(nullptr) {
    }
    SecurityLogger(dbChannel* pDbChannel,
                   const Credentials& credentials,
                   const SecurityClient& securityClient)
        :pfieldsave(pDbChannel->addr.pfield)
        ,pvt(asTrapWriteWithData((securityClient.cli)[0], // The user is the first element
                         credentials.cred[0].c_str(),     // The user is the first element
                         credentials.host.c_str(),
                         pDbChannel,
                         dbChannelFinalFieldType(pDbChannel),
                         dbChannelFinalElements(pDbChannel),
                         nullptr
                 ))
    {
        /* asTrapWrite callbacks may have called clobbered
         * see
         *   https://github.com/epics-modules/caPutLog/pull/23
         *   https://github.com/epics-base/epics-base/issues/474
         */
        if(pchan)
            pchan->addr.pfield = pfieldsave;
    }

    SecurityLogger(const SecurityLogger&) = delete;
    SecurityLogger& operator=(const SecurityLogger&) = delete;
};

} // pvxs
} // ioc

#endif //PVXS_SECURITYLOGGER_H
