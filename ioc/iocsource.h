/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_IOCSOURCE_H
#define PVXS_IOCSOURCE_H

#include <pvxs/data.h>

#include <dbAccess.h>

#include "dbeventcontextdeleter.h"
#include "fieldconfig.h"
#include "singlesrcsubscriptionctx.h"
#include "credentials.h"
#include "securitylogger.h"
#include "securityclient.h"

// added in Base 7.0.6
#ifndef DBRamsg
#  define DBRamsg
#  define DBRutag
#  define DBR_AMSG 0
#  define DBR_UTAG 0
#endif

namespace pvxs {
namespace ioc {

namespace UpdateType {
enum type {
    Value = DBE_VALUE,
    Alarm = DBE_ALARM,
    Property   = DBE_PROPERTY,
    Everything = DBE_VALUE | DBE_ALARM | DBE_PROPERTY, // GET
};
}

class IOCSource {
public:
    static void initialize(Value& value, const MappingInfo &info, const Channel &chan);

    static void get(Value& valuePrototype,
                    const MappingInfo& info, const Value &anyType,
                    UpdateType::type change,
                    dbChannel *pChannel,
                    db_field_log* pDbFieldLog);
    static void put(dbChannel* pDbChannel, const Value& value, const MappingInfo& info);
    static void doPostProcessing(dbChannel* pDbChannel, TriState forceProcessing);
    static void doPreProcessing(dbChannel* pDbChannel, SecurityLogger& securityLogger, const Credentials& credentials,
            const SecurityClient& securityClient);
    static void doFieldPreProcessing(const SecurityClient& securityClient);

    //////////////////////////////
    // Common Utils
    //////////////////////////////
    // Utility function to get the TypeCode that the given database channel is configured for
    static TypeCode getChannelValueType(const Channel &pDbChannel, bool errOnLinks = false);
    static void
    setForceProcessingFlag(server::RemoteLogger *op,
                           const Value& pvRequest,
                           const std::shared_ptr<SecurityControlObject>& securityControlObject);
};

struct CurrentOp {
    explicit CurrentOp(server::ExecOp *op);
    ~CurrentOp();
    static
    server::ExecOp *current();
private:
    server::ExecOp *prev;
};

} // pvxs
} // ioc

#endif //PVXS_IOCSOURCE_H
