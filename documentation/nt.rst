.. _ntapi:

Common Type Definitions
=======================

Library of common type definitions. ::

    #include <pvxs/nt.h>
    namespace pvxs { namespace nt { ... } }

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   ntscalar

.. _time_t:

time_t
------

Commonly used sub-structure to represent a time

**"secondsPastEpoch"**
    Seconds since POSIX epoch of 1 Jan 1970 UTC.
    Note that the EPICS epoch is 631152000 seconds after the POSIX epoch.
    (cf. POSIX_TIME_AT_EPICS_EPOCH in epicsTime.h from EPICS Base)

**"nanoseconds"**
    Number of nanoseconds since the start of the second.

.. _alarm_t:

alarm_t
-------

**"severity"**
    Enumeration of 0 - No Alarm, 1 - Minor, 2 - Major, 3 - Invalid.

    The meaning of Minor and Major are contextual and may be different for each PV.
    An Invalid alarm severity means that the value field should not be taken as
    a meaningful represention of eg. the quantity being measured.  Typically,
    it reflects the most recent valid value.

    A UI client may change the state of a widget displaying a value which is alarming
    by eg. changing border color.

**"status"**
    Enumeration providing context to **"severity"** 0 - No Alarm, 1 - Device, 2 - Driver,
    3 - Record, 4 - Database, 5 - Configuration, 6 - Undefined, 7 - Client

**"message"**
    Arbitrary string describing the condition being alarmed.

NTNDArray
---------

Container for image data used by areaDetector.

.. doxygenstruct:: pvxs::nt::NTNDArray
    :members:

NTURI
-----

.. doxygenclass:: pvxs::nt::NTURI
    :members:
