/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>
#include <algorithm>

#include <special.h>
#include <epicsTime.h>

#include "iocsource.h"
#include "dbentry.h"
#include "dberrormessage.h"
#include "typeutils.h"
#include "credentials.h"
#include "securityclient.h"
#include "securitylogger.h"

namespace pvxs {
namespace ioc {

/**
 * IOC function that will get data from the database.  This will use the provided value prototype to determine the shape
 * of the data to be returned (if it has a `value` subfield, it is a structure).  The provided channel
 * is used to retrieve the data and the flags forValues and forProperties are used to determine whether to fetch
 * values, properties or both from the database.
 *
 * When the data has been retrieved the provided returnFn is called with the value, otherwise the an
 * exception is thrown
 *
 * @param pDbValueChannel the channel to get the value from
 * @param pDbPropertiesChannel the channel to get the properties from
 * @param valuePrototype the value prototype to use to determine the shape of the data
 * @param getOperationType for values, for properties or for metadata
 * @param pDbFieldLog the field log of changes if this comes from a subscription
 */
void IOCSource::get(dbChannel* pDbValueChannel, dbChannel* pDbPropertiesChannel, Value& valuePrototype,
        const GetOperationType getOperationType,
        db_field_log* pDbFieldLog) {
    // Assumes this is the leaf node in a group, or is a simple db record.field reference
    Value value = valuePrototype; // The value that will be returned, if compound then metadata is set here
    Value valueTarget = valuePrototype; // The part of value that will be retrieved from the database value field
    bool isCompound = false;
    if (getOperationType <= FOR_VALUE && value.type() == TypeCode::Any) {
        auto type = fromDbrType(dbChannelFinalFieldType(pDbValueChannel));
        if (dbChannelFinalElements(pDbValueChannel) != 1) {
            type = type.arrayOf();
        }
        value = valueTarget = TypeDef(type).create();
        valuePrototype.from(value);
    } else if (auto targetCandidate = value["value"]) {
        isCompound = true;
        valueTarget = targetCandidate;
    }

    // options bit mask LSB to MSB
    uint32_t options = 0;
    if (isCompound && getOperationType <= FOR_METADATA) {
        options = IOC_VALUE_OPTIONS;
    }
    if (isCompound && (getOperationType == FOR_VALUE_AND_PROPERTIES ||
            getOperationType == FOR_PROPERTIES)) {
        options |= IOC_PROPERTIES_OPTIONS;
    }

    if (dbChannelFinalElements(pDbValueChannel) == 1) {
        getScalar(pDbValueChannel, pDbPropertiesChannel, value, valueTarget, options, getOperationType, pDbFieldLog);
    } else {
        getArray(pDbValueChannel, pDbPropertiesChannel, value, valueTarget, options, getOperationType, pDbFieldLog);
    }
}

/**
 * Get a scalar value from the database
 * @param pDbValueChannel the database channel to get the value from
 * @param pDbPropertiesChannel the database channel to get the properties from
 * @param value the value to set including metadata if this is a compound value
 * @param valueTarget where to store the "value" part of the scalar within value
 * @param requestedOptions the options defining what metadata to get
 * @param getOperationType for values, for properties or for metadata
 * @param pDbFieldLog the field log of changes if this comes from a subscription
 */
void IOCSource::getScalar(dbChannel* pDbValueChannel, dbChannel* pDbPropertiesChannel, Value& value, Value& valueTarget,
        uint32_t& requestedOptions, const GetOperationType getOperationType, db_field_log* pDbFieldLog) {
    ValueBuffer valueBuffer{}; // Enough for metadata and 1 scalar
    void* pValueBuffer = &valueBuffer;
    long nElements = (getOperationType <= FOR_VALUE) ? 1 : 0;
    long actualOptions = requestedOptions;

    // Get metadata/properties and field value
    // Note that metadata will precede the value in the buffer and will be laid out in the options order
    DBErrorMessage dbErrorMessage;
    if (getOperationType <= FOR_METADATA) {
        dbErrorMessage =
                dbChannelGet(pDbValueChannel, dbChannelFinalFieldType(pDbValueChannel), pValueBuffer, &actualOptions,
                        &nElements,
                        pDbFieldLog);
    } else {
        dbErrorMessage =
                dbChannelGet(pDbPropertiesChannel, dbChannelFinalFieldType(pDbPropertiesChannel), pValueBuffer,
                        &actualOptions,
                        &nElements,
                        pDbFieldLog);
    }

    if (dbErrorMessage) {
        throw std::runtime_error(dbErrorMessage.c_str());
    }

    // Get metadata/properties from buffer if any have been requested
    getMetadata(value, pValueBuffer, requestedOptions, actualOptions);

    // Get the value if it has been requested
    if (getOperationType <= FOR_VALUE) {
        if (dbChannelFinalFieldType(pDbValueChannel) == DBR_ENUM && valueTarget.type() == TypeCode::Struct) {
            valueTarget["index"] = *(uint16_t*)(pValueBuffer);
        } else {
            getValueFromBuffer(valueTarget, pValueBuffer);
        }
    }
}

/**
 * Get an array value from the database
 *
 * @param pDbValueChannel the database channel to get the value from
 * @param pDbPropertiesChannel the database channel to get the properties from
 * @param value the value to set including metadata if this is a compound value
 * @param valueTarget where to store the "value" part of the array within value
 * @param requestedOptions the options defining what metadata to get
 * @param getOperationType for values, for properties or for metadata
 * @param pDbFieldLog the field log of changes if this comes from a subscription
 */
void IOCSource::getArray(dbChannel* pDbValueChannel, dbChannel* pDbPropertiesChannel, Value& value, Value& valueTarget,
        uint32_t& requestedOptions, const GetOperationType getOperationType, db_field_log* pDbFieldLog) {
    // value buffer to store the field we will get from the database including metadata.
    std::vector<char> valueBuffer;
    auto nElements = (getOperationType <= FOR_VALUE) ? (long)dbChannelFinalElements(pDbValueChannel)
                                                     : 0; // maximal number of elements
    // Initialize the buffer to the maximal size including metadata and zero it out
    valueBuffer.resize(nElements * pDbValueChannel->addr.field_size + MAX_METADATA_SIZE, '\0');
    void* pValueBuffer = &valueBuffer[0];
    long actualOptions = requestedOptions;

    // Get the metadata/properties and value into this buffer
    // Note that metadata will precede the array value in the buffer and will be laid out in the options order
    DBErrorMessage dbErrorMessage;
    if (getOperationType <= FOR_METADATA) {
        dbErrorMessage =
                dbChannelGet(pDbValueChannel, dbChannelFinalFieldType(pDbValueChannel), pValueBuffer, &actualOptions,
                        &nElements,
                        pDbFieldLog);
    } else {
        dbErrorMessage =
                dbChannelGet(pDbPropertiesChannel, pDbPropertiesChannel->final_type, pValueBuffer, &actualOptions,
                        &nElements,
                        pDbFieldLog);
    }

    if (dbErrorMessage) {
        throw std::runtime_error(dbErrorMessage.c_str());
    }

    // Get metadata/properties from buffer if any have been requested
    getMetadata(value, pValueBuffer, requestedOptions, actualOptions);

    // Get the value array if it has been requested
    if (getOperationType <= FOR_VALUE) {
        // Get the array value from the updated buffer pointer
        // Note: nElements will have been updated with the number of actual elements in the array
        if (dbChannelFinalFieldType(pDbValueChannel) == DBR_ENUM && valueTarget.type() == TypeCode::Struct) {
            shared_array<uint16_t> values(nElements);
            for (auto i = 0; i < nElements; i++) {
                values[i] = ((uint16_t*)pValueBuffer)[i];
            }
            valueTarget["index"] = values.freeze();
        } else {
            getValueFromBuffer(valueTarget, pValueBuffer, nElements);
        }
    }
}

/**
 * Put a given value to the specified channel.  Throw an exception if there are any errors.
 *
 * @param pDbChannel the channel to put the value into
 * @param value the value to put
 */
void IOCSource::put(dbChannel* pDbChannel, const Value& value) {
    Value valueSource = value;
    // TODO may need to handle Array of and Union as special cases as well
    if (value.type() == TypeCode::Any) {
        valueSource = valueSource["->"];
    } else if (auto sourceCandidate = value["value"]) {
        valueSource = sourceCandidate;
    }

    if (dbChannelFinalElements(pDbChannel) == 1) {
        putScalar(pDbChannel, valueSource);
    } else {
        putArray(pDbChannel, valueSource);
    }
}

/**
 * Put a given scalar value to the specified channel.  Throw an exception if there are any errors.
 *
 * @param pDbChannel the channel to put the value into
 * @param value the scalar value to put
 */
void IOCSource::putScalar(dbChannel* pDbChannel, const Value& value) {
    ScalarValueBuffer valueBuffer{};
    auto pValueBuffer = (char*)&valueBuffer;

    if (dbChannelFinalFieldType(pDbChannel) == DBR_ENUM) {
        *(uint16_t*)(pValueBuffer) = (value)["index"].as<uint16_t>();
    } else {
        setValueInBuffer(value, pValueBuffer, pDbChannel);
    }

    long status;
    if (dbChannelFieldType(pDbChannel) >= DBF_INLINK && dbChannelFieldType(pDbChannel) <= DBF_FWDLINK) {
        status = dbChannelPutField(pDbChannel, dbChannelFinalFieldType(pDbChannel), pValueBuffer, 1);
    } else {
        status = dbChannelPut(pDbChannel, dbChannelFinalFieldType(pDbChannel), pValueBuffer, 1);
    }
    DBErrorMessage dbErrorMessage(status);
    if (dbErrorMessage) {
        throw std::runtime_error(dbErrorMessage.c_str());
    }
}

/**
 * Put a given array value to the specified channel.  Throw an exception if there are any errors.
 *
 * @param pDbChannel the channel to put the value into
 * @param value the array value to put
 */
void IOCSource::putArray(dbChannel* pDbChannel, const Value& value) {
    auto valueArray = value.as<shared_array<const void>>();

    void* pValueBuffer;
    long nElements = (long)valueArray.size();
    std::vector<char> stringValueBuffer;

    if (dbChannelFinalFieldType(pDbChannel) == DBR_STRING) {
        stringValueBuffer.resize(MAX_STRING_SIZE * valueArray.size(), '\0');
        char* pCurrent = stringValueBuffer.data();
        auto stringArray = valueArray.castTo<const std::string>();
        for (auto& element: stringArray) {
            element.copy(pCurrent, MAX_STRING_SIZE - 1);
            pCurrent += MAX_STRING_SIZE;
        }
        pValueBuffer = stringValueBuffer.data();
    } else {
        // Set the buffer to the internal value buffer as it's the same for the db records for non-string fields
        pValueBuffer = (void*)valueArray.data();
        setValueInBuffer(value, (char*)pValueBuffer, nElements);
    }

    long status;
    if (dbChannelFieldType(pDbChannel) >= DBF_INLINK && dbChannelFieldType(pDbChannel) <= DBF_FWDLINK) {
        status = dbChannelPutField(pDbChannel, dbChannelFinalFieldType(pDbChannel), pValueBuffer, nElements);
    } else {
        status = dbChannelPut(pDbChannel, dbChannelFinalFieldType(pDbChannel), pValueBuffer, nElements);
    }
    DBErrorMessage dbErrorMessage(status);
    if (dbErrorMessage) {
        throw std::runtime_error(dbErrorMessage.c_str());
    }
}

/**
 * Do necessary preprocessing before put operations.  Check if put is allowed.
 *
 * @param pDbChannel channel to do preprocessing for
 * @param securityLogger the logger that will audit security events
 * @param credentials client credentials that are applied to this execution context
 * @param securityClient the security client.  Keep in scope around the put operation
 */
void
IOCSource::doPreProcessing(dbChannel* pDbChannel, SecurityLogger& securityLogger, const Credentials& credentials,
        const SecurityClient& securityClient) {
    if (pDbChannel->addr.special == SPC_ATTRIBUTE) {
        throw std::runtime_error("Unable to put value: Modifications not allowed: S_db_noMod");
    } else if (pDbChannel->addr.precord->disp && pDbChannel->addr.pfield != &pDbChannel->addr.precord->disp) {
        throw std::runtime_error("Unable to put value: Field Disabled: S_db_putDisabled");
    }

    SecurityLogger asWritePvt(
            asTrapWriteWithData((securityClient.cli)[0], // The user is the first element
                    credentials.cred[0].c_str(),         // The user is the first element
                    credentials.host.c_str(),
                    pDbChannel,
                    dbChannelFinalFieldType(pDbChannel),
                    dbChannelFinalElements(pDbChannel),
                    nullptr
            )
    );

    securityLogger.swap(asWritePvt);

}

/**
 * Do necessary preprocessing before put operations.  Check if put is allowed.
 *
 * @param securityClient security client applied to this execution context
 */
void IOCSource::doFieldPreProcessing(const SecurityClient& securityClient) {
    if (!securityClient.canWrite()) {
        // TODO this will abort the whole group put operation, so may be a behavior change, need to check
        throw std::runtime_error("Put not permitted");
    }
}

/**
 * Do necessary post processing after put operations.  If this field is a processing record then do processing
 * and set status
 * Note: Only called when dbPutField() is not called.
 *
 * @param pDbChannel channel to do post processing for
 * @param forceProcessing whether to force processing, True, False
 */
void IOCSource::doPostProcessing(dbChannel* pDbChannel, TriState forceProcessing) {
    if (pDbChannel->addr.pfield == &pDbChannel->addr.precord->proc ||
            (forceProcessing == True) ||
            (pDbChannel->addr.pfldDes->process_passive &&
                    pDbChannel->addr.precord->scan == 0 &&
                    dbChannelFinalFieldSize(pDbChannel) < DBR_PUT_ACKT &&
                    forceProcessing == Unset)) {
        if (pDbChannel->addr.precord->pact) {
            if (dbAccessDebugPUTF && pDbChannel->addr.precord->tpro) {
                printf("%s: single source onPut to Active '%s', setting RPRO=1\n",
                        epicsThreadGetNameSelf(), pDbChannel->addr.precord->name);
            }
            pDbChannel->addr.precord->rpro = TRUE;
        } else {
            pDbChannel->addr.precord->putf = TRUE;
            DBErrorMessage dbErrorMessage(dbProcess(pDbChannel->addr.precord));
            if (dbErrorMessage) {
                throw std::runtime_error(dbErrorMessage.c_str());
            }
        }
    }
}

/**
 * Set a flag that will force processing of record in the specified security control object
 *
 * @param pvRequest the request
 * @param securityControlObject the security control object to update
 */
void IOCSource::setForceProcessingFlag(const Value& pvRequest,
        const std::shared_ptr<SecurityControlObject>& securityControlObject) {
    pvRequest["record._options.process"]
            .as<std::string>([&securityControlObject](const std::string& forceProcessingOption) {
                if (forceProcessingOption == "true") {
                    securityControlObject->forceProcessing = True;
                } else if (forceProcessingOption == "false") {
                    securityControlObject->forceProcessing = False;
                }
            });
}

/**
 * Set a return value from the given database value buffer
 *
 * @param valueTarget the value to set
 * @param pValueBuffer pointer to the database value buffer
 */
void IOCSource::getValueFromBuffer(Value& valueTarget, const void* pValueBuffer) {
    auto valueType(valueTarget.type());

    if (valueType == TypeCode::String) {
        valueTarget = ((const char*)pValueBuffer);
    } else {
        SwitchTypeCodeForTemplatedCall(valueType, getValueFromBuffer, (valueTarget, pValueBuffer));
    }
}

/**
 * Set a return value from the given database value buffer.  This is the array version of the function
 *
 * @param valueTarget the value to set
 * @param pValueBuffer the database value buffer
 * @param nElements the number of elements in the buffer
 */
void IOCSource::getValueFromBuffer(Value& valueTarget, const void* pValueBuffer, const long& nElements) {
    auto valueType(valueTarget.type());
    if (valueType == TypeCode::StringA) {
        shared_array<std::string> values(nElements);
        char stringBuffer[MAX_STRING_SIZE + 1]{ 0 }; // Need to do this because some strings may not be null terminated
        for (auto i = 0; i < nElements; i++) {
            auto pStringValue = (char*)&((const char*)pValueBuffer)[i * MAX_STRING_SIZE];
            strncpy(stringBuffer, pStringValue, MAX_STRING_SIZE);
            values[i] = (char*)&stringBuffer[0];
        }
        valueTarget = values.freeze().template castTo<const void>();
    } else {
        SwitchTypeCodeForTemplatedCall(valueType, getValueFromBuffer, (valueTarget, pValueBuffer, nElements));
    }
}

/**
 * Set scalar value into given database buffer
 *
 * @param valueSource the value to put into the buffer
 * @param pValueBuffer the database buffer to put it in
 * @param pDbChannel the db channel
 */
void IOCSource::setValueInBuffer(const Value& valueSource, char* pValueBuffer, dbChannel* pDbChannel) {
    auto valueType(valueSource.type());
    if (valueType == TypeCode::String) {
        setStringValueInBuffer(valueSource, pValueBuffer);
    } else if (valueType == TypeCode::Any || valueType == TypeCode::Union) {
        SwitchTypeCodeForTemplatedCall(fromDbrType(dbChannelFinalFieldType(pDbChannel)), setValueInBuffer,
                (valueSource, pValueBuffer));
    } else {
        SwitchTypeCodeForTemplatedCall(valueType, setValueInBuffer, (valueSource, pValueBuffer));
    }
}

/**
 * Set an array value in the given buffer
 *
 * @param valueSource the value to put into the buffer
 * @param pValueBuffer the database buffer to put it in
 * @param nElements the number of elements to put into the buffer
 */
void IOCSource::setValueInBuffer(const Value& valueSource, char* pValueBuffer, long nElements) {
    auto valueType(valueSource.type());
    if (valueType == TypeCode::StringA) {
        auto sharedValueArray = valueSource.as<shared_array<const Value>>();
        for (auto i = 0u; i < sharedValueArray.size(); i++, pValueBuffer += MAX_STRING_SIZE) {
            setStringValueInBuffer(sharedValueArray[i], pValueBuffer);
        }
    } else {
        SwitchTypeCodeForTemplatedCall(valueType, setValueInBuffer, (valueSource, pValueBuffer, nElements));
    }
}

/**
 * Given a string value source, and a buffer, copy the string contents into the buffer up to the MAX_STRING_SIZE.
 * Null terminate the string before exiting.
 *
 * @param valueSource  the string value source
 * @param pValueBuffer  the buffer to copy the string contents to
 */
void IOCSource::setStringValueInBuffer(const Value& valueSource, char* pValueBuffer) {
    auto stringValue = valueSource.as<std::string>();
    auto len = std::min(stringValue.length(), (size_t)MAX_STRING_SIZE - 1);
    stringValue.copy(pValueBuffer, len);
    pValueBuffer[len] = '\0';
}

/**
 * Set the value field of the given return value to an array of scalars pointed to by pValueBuffer
 * Supported types are:
 *   TypeCode::Int8 	TypeCode::UInt8
 *   TypeCode::Int16 	TypeCode::UInt16
 *   TypeCode::Int32 	TypeCode::UInt32
 *   TypeCode::Int64 	TypeCode::UInt64
 *   TypeCode::Float32 	TypeCode::Float64
 *
 * @tparam valueType the type of the scalars stored in this array.  One of the supported types
 * @param valueTarget the return value
 * @param pValueBuffer the pointer to the data containing the database data to store in the return value
 * @param nElements the number of elements in the array
 */
template<typename valueType>
void IOCSource::getValueFromBuffer(Value& valueTarget, const void* pValueBuffer, const long& nElements) {
    shared_array<valueType> values(nElements);
    for (auto i = 0; i < nElements; i++) {
        values[i] = ((valueType*)pValueBuffer)[i];
    }
    valueTarget = values.freeze().template castTo<const void>();
}

/**
 * Get the value into the given database value buffer (templated)
 *
 * @tparam valueType the type of the scalars stored in this array.  One of the supported types
 * @param valueSource the value to put into the buffer
 * @param pValueBuffer the database buffer to put it in
 * @param nElements the number of elements to put into the buffer
 */
template<typename valueType>
void IOCSource::setValueInBuffer(const Value& valueSource, void* pValueBuffer, long nElements) {
    auto valueArray = valueSource.as<shared_array<const valueType>>();
    for (auto i = 0; i < nElements; i++) {
        ((valueType*)pValueBuffer)[i] = valueArray[i];
    }
}

/**
 * Utility function to get the TypeCode that the given database channel is configured for
 *
 * @param pDbChannel the pointer to the database channel to get the TypeCode for
 * @param errOnLinks determines whether to throw an error on finding links, default no
 * @return the TypeCode that the channel is configured for
 */
TypeCode IOCSource::getChannelValueType(const dbChannel* pDbChannel, const bool errOnLinks) {
    auto dbChannel(pDbChannel);
    short dbrType(dbChannelFinalFieldType(dbChannel));
    auto nFinalElements(dbChannelFinalElements(dbChannel));
    auto nElements(dbChannelElements(dbChannel));

    TypeCode valueType;

    if (dbChannelFieldType(dbChannel) == DBF_STRING && nElements == 1 && dbrType && nFinalElements > 1) {
        // single character long DBF_STRING being cast to DBF_CHAR array.
        valueType = TypeCode::String;

    } else {
        if (dbrType == DBF_INLINK || dbrType == DBF_OUTLINK || dbrType == DBF_FWDLINK) {
            if (errOnLinks) {
                throw std::runtime_error("Link fields not allowed in this context");
            } else {
                // Handle as chars and fail later
                dbrType = DBF_CHAR;
            }
        }

        valueType = fromDbfType(dbfType(dbrType));
        if (valueType != TypeCode::Null && nFinalElements != 1) {
            valueType = valueType.arrayOf();
        }
    }
    return valueType;
}

/**
 * Get Metadata from the given buffer into the provided value object.  The options parameter is used
 * to select the metadata to retrieve.  It must always be retrieved in the specified order
 * as it is laid out that way by the db subsystems on retrieval.
 *
 * @param value the value object to retrieve the metadata into
 * @param pValueBuffer the db value buffer retrieved from the db subsystem
 * @param options the options parameter used to select the metadata.
 */
void IOCSource::getMetadata(Value& value, void*& pValueBuffer, const uint32_t& requestedOptions,
        const uint32_t& actualOptions) {
    if (requestedOptions) {
        // Temporary variable to store metadata while retrieving it
        Metadata metadata;

        // Alarm
        if (requestedOptions & DBR_STATUS) {
            get4MetadataFields(pValueBuffer, uint16_t,
                    metadata.metadata.status, metadata.metadata.severity,
                    metadata.metadata.acks, metadata.metadata.ackt);
            if (actualOptions & DBR_STATUS) {
                checkedSetField(metadata.metadata.status, alarm.status);
                checkedSetField(metadata.metadata.severity, alarm.severity);
                checkedSetField(metadata.metadata.acks, alarm.acks);
                checkedSetField(metadata.metadata.ackt, alarm.ackt);
            }
        }

        // Alarm message
        if (requestedOptions & DBR_AMSG) {
            getMetadataString(pValueBuffer, metadata.metadata.amsg);
            if (actualOptions & DBR_AMSG) {
                checkedSetStringField(metadata.metadata.amsg, alarm.message);
            }
        }

        // Units
        if (requestedOptions & DBR_UNITS) {
            getMetadataBuffer(pValueBuffer, const char, metadata.pUnits, DB_UNITS_SIZE);
            if (actualOptions & DBR_UNITS && value["display"]) {
                checkedSetStringField(metadata.pUnits, display.units);
            }
        }

        // Precision
        if (requestedOptions & DBR_PRECISION) {
            getMetadataBuffer(pValueBuffer, const dbr_precision, metadata.pPrecision, dbr_precision_size);
            if (actualOptions & DBR_PRECISION && value["display"]) {
                checkedSetField(metadata.pPrecision->precision.dp, display.precision);
            }
        }

        // Time
        if (requestedOptions & DBR_TIME) {
            get2MetadataFields(pValueBuffer, uint32_t, metadata.metadata.time.secPastEpoch,
                    metadata.metadata.time.nsec);
            if (actualOptions & DBR_TIME) {
                checkedSetField(metadata.metadata.time.secPastEpoch + POSIX_TIME_AT_EPICS_EPOCH,
                        timeStamp.secondsPastEpoch);
                checkedSetField(metadata.metadata.time.nsec, timeStamp.nanoseconds);
            }
        }

        // User tag
        if (requestedOptions & DBR_UTAG) {
            getMetadataField(pValueBuffer, uint64_t, metadata.metadata.utag);
            if (actualOptions & DBR_UTAG) {
                checkedSetField(metadata.metadata.utag, timeStamp.userTag);
            }
        }

        // Enum strings
        if (requestedOptions & DBR_ENUM_STRS) {
            getMetadataBuffer(pValueBuffer, const dbr_enumStrs, metadata.enumStrings, dbr_enumStrs_size);
            if (actualOptions & DBR_ENUM_STRS && value["value.choices"] && metadata.enumStrings) {
                shared_array<std::string> choices(metadata.enumStrings->no_str);
                for (epicsUInt32 i = 0; i < metadata.enumStrings->no_str; i++) {
                    choices[i] = metadata.enumStrings->strs[i];
                }
                value["value.choices"] = choices.freeze().castTo<const void>();
            }
        }

        // Display long
        if (requestedOptions & DBR_GR_LONG) {
            getMetadataBuffer(pValueBuffer, const struct dbr_grLong, metadata.graphicsLong, dbr_grLong_size);
            if (actualOptions & DBR_GR_LONG && value["display"]) {
                checkedSetLongField(metadata.graphicsLong->lower_disp_limit, display.limitLow);
                checkedSetLongField(metadata.graphicsLong->upper_disp_limit, display.limitHigh);
            }
        }

        // Display double
        if (requestedOptions & DBR_GR_DOUBLE) {
            getMetadataBuffer(pValueBuffer, const struct dbr_grDouble, metadata.graphicsDouble, dbr_grDouble_size);
            if (actualOptions & DBR_GR_DOUBLE && value["display"]) {
                checkedSetDoubleField(metadata.graphicsDouble->lower_disp_limit, display.limitLow);
                checkedSetDoubleField(metadata.graphicsDouble->upper_disp_limit, display.limitHigh);
            }
        }

        // Control long
        if (requestedOptions & DBR_CTRL_LONG) {
            getMetadataBuffer(pValueBuffer, const struct dbr_ctrlLong, metadata.controlLong, dbr_ctrlLong_size);
            if (actualOptions & DBR_CTRL_LONG && value["control"]) {
                checkedSetLongField(metadata.controlLong->lower_ctrl_limit, control.limitLow);
                checkedSetLongField(metadata.controlLong->upper_ctrl_limit, control.limitHigh);
            }
        }

        // Control double
        if (requestedOptions & DBR_CTRL_DOUBLE) {
            getMetadataBuffer(pValueBuffer, const struct dbr_ctrlDouble, metadata.controlDouble, dbr_ctrlDouble_size);
            if (actualOptions & DBR_CTRL_DOUBLE && value["control"]) {
                checkedSetDoubleField(metadata.controlDouble->lower_ctrl_limit, control.limitLow);
                checkedSetDoubleField(metadata.controlDouble->upper_ctrl_limit, control.limitHigh);
            }
        }

        // Alarm long
        if (requestedOptions & DBR_AL_LONG) {
            getMetadataBuffer(pValueBuffer, const struct dbr_alLong, metadata.alarmLong, dbr_alLong_size);
            if (actualOptions & DBR_AL_LONG && value["valueAlarm"]) {
                checkedSetLongField(metadata.alarmLong->lower_alarm_limit, valueAlarm.lowAlarmLimit);
                checkedSetLongField(metadata.alarmLong->lower_warning_limit, valueAlarm.lowWarningLimit);
                checkedSetLongField(metadata.alarmLong->upper_warning_limit, valueAlarm.highWarningLimit);
                checkedSetLongField(metadata.alarmLong->upper_alarm_limit, valueAlarm.highAlarmLimit);
            }
        }

        // Alarm double
        if (requestedOptions & DBR_AL_DOUBLE) {
            getMetadataBuffer(pValueBuffer, const struct dbr_alDouble, metadata.alarmDouble, dbr_alDouble_size);
            if (actualOptions & DBR_AL_DOUBLE && value["valueAlarm"]) {
                checkedSetDoubleField(metadata.alarmDouble->lower_alarm_limit, valueAlarm.lowAlarmLimit);
                checkedSetDoubleField(metadata.alarmDouble->lower_warning_limit, valueAlarm.lowWarningLimit);
                checkedSetDoubleField(metadata.alarmDouble->upper_warning_limit, valueAlarm.highWarningLimit);
                checkedSetDoubleField(metadata.alarmDouble->upper_alarm_limit, valueAlarm.highAlarmLimit);
            }
        }
    }
}

} // pvxs
} // ioc
