/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <pvxs/nt.h>

namespace pvxs {
namespace nt {


TypeDef NTScalar::build()
{
    TypeDef def(TypeCode::Struct,
                value.isarray() ? "epics:nt/NTScalarArray:1.0" : "epics:nt/NTScalar:1.0");

    const bool isnumeric = value.kind()==Kind::Integer || value.kind()==Kind::Real;
    const auto scalar = value.scalarOf();

    def.begin()
            .insert("value", value)
            .insert("alarm", "alarm_t", TypeCode::Struct).seek("alarm")
                .insert("severity", TypeCode::Int32)
                .insert("status", TypeCode::Int32)
                .insert("message", TypeCode::String)
            .up()
            .insert("timeStamp", "time_t", TypeCode::Struct).seek("timeStamp")
                .insert("secondsPastEpoch", TypeCode::Int64)
                .insert("nanoseconds", TypeCode::Int32)
                .insert("userTag", TypeCode::Int32)
            .up()
            ;

    if(display && isnumeric) {
        def.begin()
                .insert("display", TypeCode::Struct).seek("display")
                    .insert("limitLow", scalar)
                    .insert("limitHigh", scalar)
                    .insert("description", TypeCode::String)
                    //.insert("format", TypeCode::String)
                    .insert("units", TypeCode::String)
                .up()
                ;
    }

    if(control && isnumeric) {
        def.begin()
                .insert("control", TypeCode::Struct).seek("control")
                    .insert("limitLow", scalar)
                    .insert("limitHigh", scalar)
                    .insert("minStep", scalar)
                .up()
                ;
    }

    if(valueAlarm && isnumeric) {
        def.begin()
                .insert("valueAlarm", TypeCode::Struct).seek("valueAlarm")
                    .insert("active", TypeCode::Bool) // useless?
                    .insert("lowAlarmLimit", scalar)
                    .insert("lowWarningLimit", scalar)
                    .insert("highWarningLimit", scalar)
                    .insert("highAlarmLimit", scalar)
                    .insert("lowAlarmSeverity", TypeCode::Int32)
                    .insert("lowWarningSeverity", TypeCode::Int32)
                    .insert("highWarningSeverity", TypeCode::Int32)
                    .insert("highAlarmSeverity", TypeCode::Int32)
                    .insert("hysteresis", TypeCode::Float64)
                .up()
                ;
    }

    return def;
}

}} // namespace pvxs::nt
