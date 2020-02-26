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
    using namespace pvxs::members;

    if(!value.valid() || value.kind()==Kind::Compound)
        throw std::logic_error("NTScalar only permits (array of) primative");

    TypeDef def(TypeCode::Struct,
                   value.isarray() ? "epics:nt/NTScalarArray:1.0" : "epics:nt/NTScalar:1.0", {
                       Member(value, "value"),
                       Struct("alarm", "alarm_t", {
                           Int32("severity"),
                           Int32("status"),
                           String("message"),
                       }),
                       Struct("timeStamp", "time_t", {
                           Int64("secondsPastEpoch"),
                           Int32("nanoseconds"),
                           Int32("userTag"),
                       }),
                   });

    const bool isnumeric = value.kind()==Kind::Integer || value.kind()==Kind::Real;
    const auto scalar = value.scalarOf();

    if(display && isnumeric) {
        def += {
                Struct("display", {
                           Member(scalar, "limitLow"),
                           Member(scalar, "limitHigh"),
                           String("description"),
                           //String("format"),
                           String("units"),
                       }),
        };
    } else if(display && !isnumeric) {
            def += {
                    Struct("display", {
                               String("description"),
                               //String("format"),
                               String("units"),
                           }),
            };
    }

    if(control && isnumeric) {
        def += {
                Struct("control", {
                           Member(scalar, "limitLow"),
                           Member(scalar, "limitHigh"),
                           Member(scalar, "minStep"),
                       }),
        };
    }

    if(valueAlarm && isnumeric) {
        def += {
                Struct("valueAlarm", {
                           Bool("active"),
                           Member(scalar, "lowAlarmLimit"),
                           Member(scalar, "lowWarningLimit"),
                           Member(scalar, "highWarningLimit"),
                           Member(scalar, "highAlarmLimit"),
                           Int32("lowAlarmSeverity"),
                           Int32("lowWarningSeverity"),
                           Int32("highWarningSeverity"),
                           Int32("highAlarmSeverity"),
                           Float64("hysteresis"),
                       }),
        };
    }

    return def;
}

TypeDef NTNDArray::build() const
{
    using namespace pvxs::members;

    auto time_t = {
        Int64("secondsPastEpoch"),
        Int32("nanoseconds"),
        Int32("userTag"),
    };
    auto alarm_t = {
        Int32("severity"),
        Int32("status"),
        String("message"),
    };

    TypeDef def(TypeCode::Struct, "epics:nt/NTNDArray:1.0", {
                    Union("value", {
                        BoolA("booleanValue"),
                        Int8A("byteValue"),
                        Int16A("shortValue"),
                        Int32A("intValue"),
                        Int64A("longValue"),
                        UInt8A("ubyteValue"),
                        UInt16A("ushortValue"),
                        UInt32A("uintValue"),
                        UInt64A("ulongValue"),
                        Float32("floatValue"),
                        Float64("doubleValue"),
                    }),
                    Struct("codec", "codec_t", {
                        String("name"),
                        Any("parameters"),
                    }),
                    Int64("compressedSize"),
                    Int64("uncompressedSize"),
                    Int32("uniqueId"),
                    Struct("dataTimeStamp", "time_t", time_t),
                    Struct("alarm", "alarm_t", alarm_t),
                    Struct("timeStamp", "time_t", time_t),
                    StructA("dimension", "dimension_t", {
                        Int32("size"),
                        Int32("offset"),
                        Int32("fullSize"),
                        Int32("binning"),
                        Bool("reverse"),
                    }),
                    StructA("attribute", "epics:nt/NTAttribute:1.0", {
                        String("name"),
                        Any("value"),
                        StringA("tags"),
                        String("descriptor"),
                        Struct("alarm", "alarm_t", alarm_t),
                        Struct("timeStamp", "time_t", time_t),
                        Int32("sourceType"),
                        String("source"),
                    }),
                });

    return def;
}

NTURI::NTURI(std::initializer_list<Member> args)
{
    using namespace pvxs::members;

    _def = TypeDef(TypeCode::Struct, "epics:nt/NTURI:1.0", {
                       String("scheme"),
                       String("authority"),
                       String("path"),
                       Struct("query", args),
    });
}

}} // namespace pvxs::nt
