.. _releasenotes:

Release Notes
=============

0.1.4 (APR 2021)
----------------

* Bug Fixes

 * Fix potential locking issue monitor queue
 * Fix potential locking issue in Shared PV with concurrent open()/close() vs. post()

* Additions

 * Add `pvxs::nt::TimeStamp` and `pvxs::nt::Alarm`.

0.1.3 (FEB 2021)
----------------

* Bug Fixes

 * Fix regression from 0.1.2 causing possible crash on targets defining SO_RXQ_OVFL (eg. Linux).

0.1.2 (FEB 2021)
----------------

* Bug Fixes

 * Fix TCP connection "stall" (incorrect deferred read).

* Changes

 * Raise UDP search reply processing limit.
 * Try not to fragment UDP search packets.
 * mailbox example can serve more than one PV.
 * Indent printed field=value in delta output mode.

0.1.1 (Jan 2021)
----------------

* Bug Fixes

 * Fix decoding of "null" string.  Addresses interoperability with pvAccessJava.
 * Increase inactivity timeout for TCP connections from 30 to 40 seconds.  Also for interoperability with pvAccessJava.
 * Client search requests incorrectly set Server direction bit.  (existing servers don't enforce this)
 * Improved handling of errors resulting from pvRequest processing.  eg. field selection which doesn't select any fields.

* Added Features

 * Added `PVXS_ABI_VERSION` et al. to *pvxs/version.h*
 * Add `testThrowsMatch` and `testStrMatch` to *pvxs/unitttest.h*

* Changes

 * Changed name of automatic Sources `builtin` and `server` to `__builtin` and `__server`.
   Document that Source names beginning with `__` are reserved.

0.1.0 (Dec 2020)
----------------

 * Initial Release
