/*
* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CREDENTIALS_H
#define PVXS_CREDENTIALS_H

#include <vector>
#include <string>

#include <pvxs/iochooks.h>
#include <pvxs/source.h>

#include <asLib.h>
#include <dbChannel.h>

namespace pvxs {
namespace ioc {

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 */
class PVXS_IOC_API Credentials {
 public:
  std::vector<std::string> cred;
  std::vector<SanEntry> san;
  std::string method;
  std::string authority;
  std::string host;
  std::string issuer_id;
  std::string serial;
  bool isTLS = false;
  explicit Credentials(const server::ClientCredentials& clientCredentials);
  Credentials(const Credentials&) = delete;
  Credentials(Credentials&&) = default;
};

class PVXS_IOC_API SecurityClient {
 public:
  std::vector<ASCLIENTPVT> cli;
  ~SecurityClient();
  void update(dbChannel* ch, Credentials& cred);
  void update(ASMEMBERPVT mem, int asl, Credentials& cred);
  bool canWrite() const;
};

} // ioc
} // pvxs

#endif //PVXS_CREDENTIALS_H
