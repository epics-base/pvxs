/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <dbCommon.h>
#include <dbBase.h>
#include <asLib.h>

#include "securityclient.h"

namespace pvxs {
namespace ioc {

void SecurityClient::update(dbChannel* ch, Credentials& cred) {
    SecurityClient temp;
    temp.cli.resize(cred.cred.size(), nullptr);

    for (size_t i = 0, N = temp.cli.size(); i < N; i++) {
        /* asAddClient() fails secure to no-permission */
        (void)asAddClient(&temp.cli[i],
                dbChannelRecord(ch)->asp,
                dbChannelFldDes(ch)->as_level,
                cred.cred[i].c_str(),
                // TODO switch to vector of char to accommodate inplace modifications to string
                const_cast<char*>(cred.host.data()));
    }

    cli.swap(temp.cli);
}

SecurityClient::~SecurityClient() {
    for (auto asc: cli) {
        asRemoveClient(&asc);
    }
}

bool SecurityClient::canWrite() const {
    return std::any_of(cli.begin(), cli.end(), [](ASCLIENTPVT asc) {
        return asCheckPut(asc);
    });
}

PutOperationCache::~PutOperationCache() {
    // To avoid bug epics-base: unchecked access to notify.chan
    if (notify.chan) {
        dbNotifyCancel(&notify);
    }
}
} // pvxs
} // ioc
