/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <pvxs/nt.h>

namespace pvxs {
namespace nt {

TypeDef NTScalar::build() const
{
    return TypeDef(TypeCode::Struct,
                   value.isarray() ? "epics:nt/NTScalarArray:1.0" : "epics:nt/NTScalar:1.0", {
                       Member(value, "value"),
                       Member(TypeCode::Struct, "alarm", "alarm_t", {
                           Member(TypeCode::Int32, "severity"),
                           Member(TypeCode::Int32, "status"),
                           Member(TypeCode::String, "message"),
                       }),
                       Member(TypeCode::Struct, "timeStamp", "time_t", {
                           Member(TypeCode::Int64, "secondsPastEpoch"),
                           Member(TypeCode::Int32, "nanoseconds"),
                           Member(TypeCode::Int32, "userTag"),
                       }),
                   });

//    const bool isnumeric = value.kind()==Kind::Integer || value.kind()==Kind::Real;
//    const auto scalar = value.scalarOf();

//    if(display && isnumeric) {
//        def.begin()
//                .insert("display", TypeCode::Struct).seek("display")
//                    .insert("limitLow", scalar)
//                    .insert("limitHigh", scalar)
//                    .insert("description", TypeCode::String)
//                    //.insert("format", TypeCode::String)
//                    .insert("units", TypeCode::String)
//                .up()
//                ;
//    }

//    if(control && isnumeric) {
//        def.begin()
//                .insert("control", TypeCode::Struct).seek("control")
//                    .insert("limitLow", scalar)
//                    .insert("limitHigh", scalar)
//                    .insert("minStep", scalar)
//                .up()
//                ;
//    }

//    if(valueAlarm && isnumeric) {
//        def.begin()
//                .insert("valueAlarm", TypeCode::Struct).seek("valueAlarm")
//                    .insert("active", TypeCode::Bool) // useless?
//                    .insert("lowAlarmLimit", scalar)
//                    .insert("lowWarningLimit", scalar)
//                    .insert("highWarningLimit", scalar)
//                    .insert("highAlarmLimit", scalar)
//                    .insert("lowAlarmSeverity", TypeCode::Int32)
//                    .insert("lowWarningSeverity", TypeCode::Int32)
//                    .insert("highWarningSeverity", TypeCode::Int32)
//                    .insert("highAlarmSeverity", TypeCode::Int32)
//                    .insert("hysteresis", TypeCode::Float64)
//                .up()
//                ;
//    }

//    return def;
}

TypeDef NTNDArray::build() const
{
    TypeDef def(TypeCode::Struct, "epics:nt/NTNDArray:1.0");


    return def;
}

}} // namespace pvxs::nt
