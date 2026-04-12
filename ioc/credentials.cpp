/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <pvxs/credentials.h>

#include <utilpvt.h>

namespace pvxs {
namespace ioc {

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 *
 * @param clientCredentials The client credentials to be used for the credentials object
 */

Credentials::Credentials(const server::ClientCredentials& clientCredentials) {
    SockAddr addr(clientCredentials.peer);
    addr.setPort(0);
    host = std::string(SB()<<addr.map6to4());
    method = clientCredentials.method;
    authority = clientCredentials.authority;
    issuer_id = clientCredentials.issuer_id;
    serial = clientCredentials.serial;
    isTLS = clientCredentials.isTLS;
    san = clientCredentials.san;
    cred.emplace_back(clientCredentials.account);

    for (const auto& role: clientCredentials.roles()) {
        cred.emplace_back(SB() << "role/" << role);
    }

    for (const auto& entry: san) {
        if      (entry.type == "ip")  cred.emplace_back(SB() << "san_ip/"  << entry.value);
        else if (entry.type == "dns") cred.emplace_back(SB() << "san_dns/" << entry.value);
    }
}
} // pvxs
} // ioc
