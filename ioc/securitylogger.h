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

namespace pvxs {
namespace ioc {

class SecurityLogger {
    void* pvt;
public:
    ~SecurityLogger() {
        asTrapWriteAfterWrite(pvt);
    }

    void swap(SecurityLogger& o) {
        std::swap(pvt, o.pvt);
    }

    explicit SecurityLogger(void* pvt)
            :pvt(pvt) {
    }

    SecurityLogger()
            :pvt(nullptr) {
    }

    SecurityLogger(const SecurityLogger&) = delete;
    SecurityLogger& operator=(const SecurityLogger&) = delete;
};

} // pvxs
} // ioc

#endif //PVXS_SECURITYLOGGER_H
