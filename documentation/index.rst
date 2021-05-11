PVXS client/server for PVA Protocol
===================================

This module provides a library (libpvxs.so or pvxs.dll) and a set of
CLI utilities acting as PVAccess protocol client and/or server.

PVXS is functionally equivilant to the
`pvDataCPP <https://github.com/epics-base/pvDataCPP>`_ and
`pvAccessCPP <https://github.com/epics-base/pvAccessCPP>`_ modules,
which it hopes to eventually surplant (Ok, the author hopes).

The canonical version of this page is https://mdavidsaver.github.io/pvxs

Versioned source can be found at https://github.com/mdavidsaver/pvxs ,
which is also where `issues <https://github.com/mdavidsaver/pvxs/issues>`_ should be reported.
See :ref:`reportbug`.
Also :ref:`contrib` if you are so inclined.

Dependencies

* A C++11 compliant compiler

 * GCC >= 4.8
 * Visual Studio >= 2015 (>= 12.0)

* `EPICS Base <https://epics-controls.org/resources-and-support/base/>`_ >=3.15.1
* `libevent <http://libevent.org/>`_ >=2.0.1
* (optional) `CMake <https://cmake.org/>`_ >=3.1, only needed when building bundled libevent

See :ref:`building` for details.

Download
--------

Releases are published to https://github.com/mdavidsaver/pvxs/releases.
See :ref:`relpolicy` for details.

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   overview
   example
   building
   cli
   value
   client
   server
   util
   details
   releasenotes


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
