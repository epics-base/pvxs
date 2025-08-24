/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_SECURITYCLIENT_H
#define PVXS_SECURITYCLIENT_H

// The version of epics-base that first contains the new Secure PVAccess API
#define EPICS_SPVA_COMPAT_VERSION_INT VERSION_INT(7, 0, 9, 1)

#include <vector>
#include <asLib.h>
#include <dbChannel.h>
#include <dbNotify.h>

#include "credentials.h"
#include "typeutils.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {

class SecurityClient {
public:
	std::vector<ASCLIENTPVT> cli;
	~SecurityClient();
	void update(dbChannel* ch, Credentials& cred);
	void update(ASMEMBERPVT mem, int asl, Credentials& cred);
	bool canWrite() const;
};

/**
 * Security objects that can be controlled
 */
class SecurityControlObject {
public:
	bool done = false;
	TriState forceProcessing{ Unset };
};

/**
 * group security cache - for storing group security credentials and clients
 */
class GroupSecurityCache : public SecurityControlObject {
public:
	std::vector<SecurityClient> securityClients;
	std::unique_ptr<Credentials> credentials;
    INST_COUNTER(GroupSecurityCache);
};

/**
 * sing security cache - for storing single a source security credential and client
 */
class SingleSecurityCache : public SecurityControlObject {
public:
	SecurityClient securityClient;
	std::unique_ptr<Credentials> credentials;
};

/**
 * The put operation cache for caching information about the current client put connection
 * Includes a single security cache as well as information pertaining to asynchronous put operations
 */
struct PutOperationCache : public SingleSecurityCache {
	bool doWait{ false };
	processNotify notify{};
	Value valueToSet;
	std::unique_ptr<server::ExecOp> putOperation;
    INST_COUNTER(PutOperationCache);
    ~PutOperationCache() {
        // To avoid bug epics-base: unchecked access to notify.chan
        if (notify.chan) {
            dbNotifyCancel(&notify);
        }
    }
};

} // pvxs
} // ioc

#endif //PVXS_SECURITYCLIENT_H
