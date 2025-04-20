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

void SecurityClient::update(ASMEMBERPVT mem, int asl, Credentials& cred) {
    SecurityClient temp;
    temp.cli.resize(cred.cred.size(), nullptr);

    for (size_t i = 0, N = temp.cli.size(); i < N; i++) {
        /* asAddClient() fails secure to no-permission */
        (void)asAddClientIdentity(&temp.cli[i], mem, asl,
                           (ASIDENTITY){
                               .user = cred.cred[i].c_str(),
                               .host = const_cast<char*>(cred.host.data()),
                               .method = cred.method.c_str(),
                               .authority = cred.authority.c_str(),
                               .protocol = AS_PROTOCOL_TLS }
        );
    }

    cli.swap(temp.cli);
}

void SecurityClient::update(dbChannel* ch, Credentials& cred) {
    update(dbChannelRecord(ch)->asp, dbChannelFldDes(ch)->as_level, cred);
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
} // pvxs
} // ioc
