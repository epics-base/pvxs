/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <utilpvt.h>

#include "credentials.h"

namespace pvxs {
namespace ioc {

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 *
 * @param clientCredentials
 */

Credentials::Credentials(const server::ClientCredentials& clientCredentials) {
    // Extract host name part (or whole thing if no colon present)
    auto pos = clientCredentials.peer.find_first_of(':');
    host = clientCredentials.peer.substr(0, pos);
    method = clientCredentials.method;
    authority = clientCredentials.authority;
    issuer_id = clientCredentials.issuer_id;
    serial = clientCredentials.serial;
    cred.emplace_back(clientCredentials.account);

    for (const auto& role: clientCredentials.roles()) {
        cred.emplace_back(SB() << "role/" << role);
    }
}
} // pvxs
} // ioc
