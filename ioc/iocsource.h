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

#include "dbeventcontextdeleter.h"
#include "field.h"
#include "metadata.h"
#include "singlesrcsubscriptionctx.h"
#include "credentials.h"
#include "securitylogger.h"
#include "securityclient.h"

struct AllMetadataSize {
    DBRstatus
    DBRamsg
    DBRunits
    DBRprecision
    DBRtime
    DBRutag
    DBRenumStrs
    DBRgrDouble
    DBRctrlDouble
    DBRalDouble
};

// Maximum amount of space that metadata can use in the buffer returned by dbGetField()
#define MAX_METADATA_SIZE sizeof(AllMetadataSize)

namespace pvxs {
namespace ioc {

// To specify the get desired operation
typedef enum {
    FOR_VALUE_AND_PROPERTIES,
    FOR_VALUE,
    FOR_METADATA,
    FOR_PROPERTIES,
} GetOperationType;

// For alignment, we need this kind of union as the basis for our buffer
typedef union {
    double _scalar;
    char _string[MAX_STRING_SIZE];
} ScalarValueBuffer;

// For this is a structure that is the maximum length for a scalar value with metadata
// DON'T use _max_scalar to reference the value
typedef struct {
    double _max_meta[MAX_METADATA_SIZE];
    ScalarValueBuffer _max_scalar;
} ValueBuffer;

class IOCSource {
public:
    static void get(dbChannel* pDbValueChannel, dbChannel* pDbPropertiesChannel, Value& valuePrototype,
            GetOperationType getOperationType,
            db_field_log* pDbFieldLog);
    static void put(dbChannel* pDbChannel, const Value& value);
    static void putScalar(dbChannel* pDbChannel, const Value& value);
    static void putArray(dbChannel* pDbChannel, const Value& value);
    static void doPostProcessing(dbChannel* pDbChannel, TriState forceProcessing);
    static void doPreProcessing(dbChannel* pDbChannel, SecurityLogger& securityLogger, const Credentials& credentials,
            const SecurityClient& securityClient);
    static void doFieldPreProcessing(const SecurityClient& securityClient);

    //////////////////////////////
    // Get & Subscription
    //////////////////////////////
    // Get a return value from the given database value buffer
    static void getValueFromBuffer(Value& valueTarget, const void* pValueBuffer);
    // Get a return value from the given database value buffer
    static void getValueFromBuffer(Value& valueTarget, const void* pValueBuffer, const long& nElements);
/**
 * Set the value field of the given return value to a scalar pointed to by pValueBuffer
 * Supported types are:
 *   TypeCode::Int8 	TypeCode::UInt8
 *   TypeCode::Int16 	TypeCode::UInt16
 *   TypeCode::Int32 	TypeCode::UInt32
 *   TypeCode::Int64 	TypeCode::UInt64
 *   TypeCode::Float32 	TypeCode::Float64
 *
 * @tparam valueType the type of the scalar stored in the buffer.  One of the supported types
 * @param valueTarget the return value
 * @param pValueBuffer the pointer to the data containing the database data to store in the return value
 */
    template<typename valueType> static void getValueFromBuffer(Value& valueTarget, const void* pValueBuffer) {
        valueTarget = ((valueType*)pValueBuffer)[0];
    }

    // Get a return value from the given database value buffer (templated)
    template<typename valueType>
    static void getValueFromBuffer(Value& valueTarget, const void* pValueBuffer, const long& nElements);

    //////////////////////////////
    // Set
    //////////////////////////////
    // Set the value into the given database value buffer
    static void setValueInBuffer(const Value& valueSource, char* pValueBuffer, dbChannel* pDbChannel);
    // Set the value into the given database value buffer
    static void setValueInBuffer(const Value& valueSource, char* pValueBuffer, long nElements);
    // Set string value in the given buffer
    static void setStringValueInBuffer(const Value& valueSource, char* pValueBuffer);
// Set the value into the given database value buffer (templated)
    template<typename valueType> static void setValueInBuffer(const Value& valueSource, void* pValueBuffer) {
        ((valueType*)pValueBuffer)[0] = valueSource.as<valueType>();
    }
    // Set the value into the given database value buffer (templated)
    template<typename valueType>
    static void setValueInBuffer(const Value& valueSource, void* pValueBuffer, long nElements);

    //////////////////////////////
    // Common Utils
    //////////////////////////////
    // Utility function to get the TypeCode that the given database channel is configured for
    static TypeCode getChannelValueType(const dbChannel* pDbChannel, bool errOnLinks = false);
    static void getScalar(dbChannel* pDbValueChannel, dbChannel* pDbPropertiesChannel, Value& value, Value& valueTarget,
            uint32_t& requestedOptions, GetOperationType getOperationType, db_field_log* pDbFieldLog);
    static void getArray(dbChannel* pDbValueChannel, dbChannel* pDbPropertiesChannel, Value& value, Value& valueTarget,
            uint32_t& requestedOptions, GetOperationType getOperationType, db_field_log* pDbFieldLog);
    static void getMetadata(Value& valuePrototype, void*& pValueBuffer, const uint32_t& requestedOptions,
            const uint32_t& actualOptions);
    static void
    setForceProcessingFlag(const Value& pvRequest, const std::shared_ptr<SecurityControlObject>& securityControlObject);
};

} // pvxs
} // ioc

#endif //PVXS_IOCSOURCE_H
