.. _releasenotes:

Release Notes
=============

0.1.2 (UNRELEASED)
------------------

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
