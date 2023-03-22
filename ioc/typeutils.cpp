/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <pvxs/source.h>

#include <dbStaticLib.h>

#include "typeutils.h"

namespace pvxs {

/**
 * Convert the given database field type code into a pvxs type code
 *
 * @param dbfType the database field type code
 * @return a pvxs type code
 *
 */
TypeCode fromDbfType(dbfType dbfType) {
    switch (dbfType) {
    case DBF_CHAR:
        return TypeCode::Int8;
    case DBF_UCHAR:
        return TypeCode::UInt8;
    case DBF_SHORT:
        return TypeCode::Int16;
    case DBF_USHORT:
        return TypeCode::UInt16;
    case DBF_LONG:
        return TypeCode::Int32;
    case DBF_ULONG:
        return TypeCode::UInt32;
    case DBF_INT64:
        return TypeCode::Int64;
    case DBF_UINT64:
        return TypeCode::UInt64;
    case DBF_FLOAT:
        return TypeCode::Float32;
    case DBF_DOUBLE:
        return TypeCode::Float64;
    case DBF_ENUM:
    case DBF_MENU:
        return TypeCode::Struct;
    case DBF_STRING:
    case DBF_INLINK:
    case DBF_OUTLINK:
    case DBF_FWDLINK:
        return TypeCode::String;
    case DBF_DEVICE:
    case DBF_NOACCESS:
    default:
        return TypeCode::Null;
    }
}

/**
 * Convert the given database record type code into a pvxs type code
 *
 * @param dbrType the database record type code
 * @return a pvxs type code
 *
 */
TypeCode fromDbrType(short dbrType) {
    switch (dbrType) {
    case DBR_CHAR:
        return TypeCode::Int8;
    case DBR_UCHAR:
        return TypeCode::UInt8;
    case DBR_SHORT:
        return TypeCode::Int16;
    case DBR_USHORT:
    case DBR_ENUM:
        return TypeCode::UInt16;
    case DBR_LONG:
        return TypeCode::Int32;
    case DBR_ULONG:
        return TypeCode::UInt32;
    case DBR_INT64:
        return TypeCode::Int64;
    case DBR_UINT64:
        return TypeCode::UInt64;
    case DBR_FLOAT:
        return TypeCode::Float32;
    case DBR_DOUBLE:
        return TypeCode::Float64;
    case DBR_STRING:
        return TypeCode::String;
    case DBR_NOACCESS:
    default:
        return TypeCode::Null;
    }
}

}
