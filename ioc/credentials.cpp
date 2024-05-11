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

    // "ca" style credentials
    if (clientCredentials.method == "ca") {
        pos = clientCredentials.account.find_last_of('/');
        if (pos == std::string::npos) {
            cred.emplace_back(clientCredentials.account);
        } else {
            cred.emplace_back(clientCredentials.account.substr(pos + 1));
        }
    } else {
        cred.emplace_back(SB() << clientCredentials.method << '/' << clientCredentials.account);
    }

    for (const auto& role: clientCredentials.roles()) {
        cred.emplace_back(SB() << "role/" << role);
    }
}
} // pvxs
} // ioc
