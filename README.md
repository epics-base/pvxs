PVXS - PVAccess protocol library
================================

VXS client/server for PVA Protocol
===================================

This module provides a library (libpvxs.so or pvxs.dll) and a set of
CLI utilities acting as PVAccess protocol client and/or server.

PVXS is functionally equivalent to the
`pvDataCPP <https://github.com/epics-base/pvDataCPP>`_ and
`pvAccessCPP <https://github.com/epics-base/pvAccessCPP>`_ modules,
which it hopes to eventually supplant (Ok, the author hopes).

- VCS: https://github.com/epics-base/pvxs/
- Docs: https://epics-base.github.io/pvxs/
- Issues: https://github.com/epics-base/pvxs/issues

Dependencies

* A C++11 compliant compiler

* GCC >= 4.8
* Visual Studio >= 2015 / 12.0'
* clang

* EPICS Base https://epics-controls.org/resources-and-support/base/ >=3.15.1
* libevent http://libevent.org/ >=2.0.1  (Optionally bundled)
* CLI11 https://github.com/CLIUtils/CLI11 >=2.4.2 (optionally bundled)

**Optional**
* CMake <https://cmake.org/ >=3.1, only needed when building bundled libevent

**Optional, only when building Secure PV Access**
* openssl http://www.openssl.org/ >=3.2.1
* sqlite https://www.sqlite.org/ >=3.48.0
