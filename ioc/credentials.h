/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_CREDENTIALS_H
#define PVXS_CREDENTIALS_H

#include <vector>
#include <string>

#include <pvxs/source.h>

namespace pvxs {
namespace ioc {

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 */
class Credentials {
public:
    std::vector<std::string> cred;
    std::string host;
    explicit Credentials(const server::ClientCredentials& clientCredentials);
    Credentials(const Credentials&) = delete;
    Credentials(Credentials&&) = default;
};

} // pvxs
} // ioc

#endif //PVXS_CREDENTIALS_H
