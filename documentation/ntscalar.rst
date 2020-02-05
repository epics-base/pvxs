NTScalar and NTScalarArray
==========================

The "epics:nt/NTScalar:1.0" and related "epics:nt/NTScalarArray:1.0"
definitions describe a primary 'value' and supporting meta-data.
In the case of NTScalarArray the value is a 1-d array of primative type.
In the case of NTScalar the value is a single primative value.

Both variants include time and alarm meta-data fields,
and optionally display and control meta-data fields.

.. code-block:: c++

    using namespace pvxs;

    // integer scalar
    auto iscalar = nt::NTScalar{TypeCode::Int64}.create();

    // real array
    auto farray = nt::NTScalar{TypeCode::Float64A}.create();

    // eg. access "value" field
    iscalar["value"] = 42;

Fields
------

**"value"**
    The primary field.  May be any pvxs::TypeCode other than Struct, Union, StructA, UnionA, or Null.

**"timeStamp.secondsPastEpoch"**

**"timeStamp.nanoseconds"**
    Time associated with the value.  Typically time of measurement.  See `time_t`

**"alarm.severity"**

**"alarm.status"**

**"alarm.message"**
    Alarm state associated with value.  See `alarm_t`

**"display.description"**
    Text providing some context about what this value/PV represents.

**"display.units"**
    Text identifying units of value.  eg. "V" or "Hz"

Meta-data for numeric types.

**"display.limitLow"**

**"display.limitHigh"**
    Hints for clients which can indicate inclusive range of possible values.  eg. a UI gauge widget.
    Ignore unless limitLow < limitHigh

**"control.limitLow"**

**"control.limitHigh"**
    Hints for clients on the inclusive range of values which may reasonably be written to this PV.
    Ignore unless limitLow < limitHigh
    Not authoritative.

**"control.minStep"**
    Hint for client of a useful minimum increment for setting.

**"valueAlarm.lowAlarmLimit"**

**"valueAlarm.highAlarmLimit"**

**"valueAlarm.lowAlarmSeverity"**

**"valueAlarm.highAlarmSeverity"**

**"valueAlarm.lowWarningLimit"**

**"valueAlarm.highWarningLimit"**

**"valueAlarm.lowWarningSeverity"**

**"valueAlarm.highWarningSeverity"**
    Hints for clients on the ranges of values which will result in a alarms of the given severities.
    Could be used by eg. a UI gauge widget to place markers colored by alarm severity.
    Actual alarms are signals with **"alarm.severity"**.

    Two value ranges are defined.  The names Alarm vs. Warning do not have a special significance.

    Ignore \*Alarm\* range unless lowAlarmLimit < highAlarmLimit

    Ignore \*Warning\* range unless lowWarningLimit < highWarningLimit

    If a value is within a range [low\*Limit, high\*Limit] inclusive then no alarm is expected.
    If a value is < low\*Limit then the alarm severity low\*Severity is expected.
    If a value is > high\*Limit then the alarm severity high\*Severity is expected.


Builder API
-----------

.. doxygenstruct:: pvxs::nt::NTScalar
    :members:
