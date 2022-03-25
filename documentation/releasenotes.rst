.. _releasenotes:

Release Notes
=============

0.2.3 (UNRELEASED)
------------------

0.2.2 (Jan 2022)
----------------

* No functional change to libraries.
* Updates to python packaging.

0.2.1 (Oct 2021)
----------------

* Bug fixes

 * Fix `pvxsmonitor` hang when interrupted (Ctrl+c).
 * Fix `pvxs::client::Subscription::shared_from_this()` leaking internal reference.
 * Fix SharedPV potential race conditions involving "current" Value.

* Changes

 * Ignore beacons with protocol field other than "tcp".  Forward compatibility.
 * Limit packet hex dumps to 64 bytes.
 * `testStrMatch()` now specified POSIX regular expression syntax.
 * Client operations builders `rawRequest(Value())` is now a no-op.
   Previously produced a non-nonsensical empty request.

* Additions

 * Add `pvxs::client::Context::fromEnv()`.

0.2.0 (July 2021)
-----------------

* Bug fixes

 * Resolve ambiguity between Value::as(T&) and Value::as(FN&&) causing issue with GCC 4.8.
 * Fix encoding of (Sub)Struct w/ valid set.
 * Fix locking issue with client tracking of server beacons.
 * Fix binding to specific interface addresses.

* Changes

 * To simplify usage in situations with complex threading, many client methods avoid unnecessary
   synchronization with the client worker thread.
   Cancellation still synchronizes by default, but this may now be controlled with
   the new syncCancel() Builder methods.  cf. `pvxs::client::detail::CommonBuilder::syncCancel()`.
 * Client Op Builder server() method now implemented.
 * Client channel cache now periodically prunes unused Channels automatically.

* Additions

 * Add server ignore address list.  cf. `pvxs::server::Config::ignoreAddrs`.  Configured from $EPICS_PVAS_IGNORE_ADDR_LIST.
 * Allow TCP timeout to be configured.
 * Add `pvxs::client::Context::connect()` to force Channel creation and retention.
 * Add `pvxs::client::Subscription::shared_from_this()` which can be used with eg. the new `pvxs::MPMCFIFO` to create a work queue.
 * Add `pvxs::server::ExecOp::pvRequest()`
 * Semi-public :ref:`expertapi`.
 * Update bundled libevent
 * Preliminary support for RTEMS 5.1 with libbsd

0.1.5 (May 2021)
----------------

* Bug Fixes

 * Fix several previously unusable template methods of `pvxs::shared_array`
 * Fix `pvxs::logger_level_set`

* Changes

 * Default logger level changed from Err to Warn.
 * Server warns when falling back from requested TCP port.
 * Public headers include <iosfwd> instead of <ostream>.

* Additions

 * Add `pvxs::nt::NTEnum`

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
