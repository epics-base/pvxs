/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_METADATA_H
#define PVXS_METADATA_H

#include <string.h>
#include <cmath>

#include <dbCommon.h>
#include <dbAccess.h>

// Options when retrieving values: value, time and alarm only
#define IOC_VALUE_OPTIONS ( \
    DBR_TIME | \
    DBR_STATUS | \
    DBR_AMSG | \
    DBR_UTAG )

// Options when retrieving properties:
#define IOC_PROPERTIES_OPTIONS ( \
    DBR_UNITS | \
    DBR_PRECISION | \
    DBR_TIME | \
    DBR_UTAG | \
    DBR_ENUM_STRS| \
    DBR_GR_DOUBLE | \
    DBR_CTRL_DOUBLE | \
    DBR_AL_DOUBLE)

#define getMetadataField(_buffer, _type, _field1) getMetadataFieldsEnclosure(_buffer, _type, metadataFieldGetter(_field1) )
#define get2MetadataFields(_buffer, _type, _field1, _field2) getMetadataFieldsEnclosure(_buffer, _type, metadataFieldGetter(_field1) metadataFieldGetter(_field2) )
#define get4MetadataFields(_buffer, _type, _field1, _field2, _field3, _field4) getMetadataFieldsEnclosure(_buffer, _type, metadataFieldGetter(_field1) metadataFieldGetter(_field2) metadataFieldGetter(_field3) metadataFieldGetter(_field4))
#define getMetadataFieldsEnclosure(_buffer, _type, _getters) { \
    auto* __pBuffer = (_type*)pValueBuffer;                     \
    _getters                                                   \
    (_buffer) = (void*)__pBuffer;                               \
}

#define metadataFieldGetter(_field) (_field) = *__pBuffer++;

#define getMetadataBuffer(_buffer, _type, _field, _size) { \
    (_field) = (_type*)(_buffer); \
    (_buffer) = ((void*)&((const char*)(_buffer))[_size]); \
}

#define getMetadataString(_buffer, _field) { \
    strcpy(_field, (const char*)(_buffer)); \
    (_buffer) = (void*)((const char*)(_buffer) + sizeof(_field)); \
}

#define checkedSetField(_lvalue, _rvalue) \
if (auto&& __field = value[#_rvalue] ) { \
    __field = _lvalue; \
}

#define checkedSetDoubleField(_lvalue, _rvalue) \
if (auto&& __field = value[#_rvalue] ) { \
    if ( !std::isnan(_lvalue)) { \
        __field = _lvalue; \
    } \
}

#define checkedSetLongField(_lvalue, _rvalue) \
if (auto&& __field = value[#_rvalue] ) { \
    __field = _lvalue; \
}

#define checkedSetStringField(_lvalue, _rvalue) \
if (auto&& __field = value[#_rvalue] ) { \
    if ( strlen(_lvalue)) { \
        __field = _lvalue; \
    } \
}

namespace pvxs {
namespace ioc {

struct CommonMetadata {
    DBRstatus
    DBRamsg
    DBRtime
    DBRutag

    enum {
        mask = DBR_STATUS | DBR_AMSG | DBR_TIME | DBR_UTAG
    };
};

/**
 * structure to store metadata
 */
struct Metadata {
    CommonMetadata metadata{};
    const char* pUnits{};
    const dbr_precision* pPrecision{};
    const dbr_enumStrs* enumStrings{};
    const struct dbr_grDouble* graphicsDouble{};
    const struct dbr_grLong* graphicsLong{};
    const struct dbr_ctrlDouble* controlDouble{};
    const struct dbr_ctrlLong* controlLong{};
    const struct dbr_alDouble* alarmDouble{};
    const struct dbr_alLong* alarmLong{};
};

} // ioc
} // pvxs

#endif //PVXS_METADATA_H
