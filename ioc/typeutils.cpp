/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string.h>

#include <pvxs/source.h>

#include <dbStaticLib.h>
#include <epicsStdlib.h>

#include "dbentry.h"
#include "fielddefinition.h"
#include "typeutils.h"

namespace pvxs {

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
#ifdef DBR_INT64
    case DBR_INT64:
        return TypeCode::Int64;
    case DBR_UINT64:
        return TypeCode::UInt64;
#endif
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


namespace ioc {
const char *MappingInfo::name(type_t t)
{
    switch(t) {
    case Scalar: return "scalar";
    case Plain: return "plain";
    case Any: return "any";
    case Meta: return "meta";
    case Proc: return "proc";
    case Structure: return "structure";
    case Const: return "const";
    }
    return "<invalid>";
}

void MappingInfo::updateNsecMask(dbCommon *prec)
{
    assert(prec);
    DBEntry ent(prec);
    if(auto val = ent.info("Q:time:tag")) {
        epicsInt32 dig = 0;
        if(strncmp(val, "nsec:lsb:", 9)==0 && !epicsParseInt32(&val[9], &dig, 10, nullptr)) {
            nsecMask = (uint64_t(1u)<<dig)-1u;
        }
    }
}
} // namespace ioc

} // namespace pvxs
