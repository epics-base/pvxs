PVXS client/server for PVA Protocol
===================================

This module provides a low-level PVAccess protocol :ref:`clientapi`, :ref:`serverapi`,
a set of CLI utilities,
as well as high-level integration with the EPICS IOC Process Database (aka. :ref:`qsrv2`)

- VCS: https://github.com/epics-base/pvxs
- Docs: https://epics-base.github.io/pvxs
- `Issues <https://github.com/epics-base/pvxs/issues>`_ (see :ref:`reportbug`)
- :ref:`contrib`

Dependencies
------------

* A C++11 compliant compiler

 * GCC >= 4.8
 * Visual Studio >= 2015 / 12.0
 * clang

* `EPICS Base <https://epics-controls.org/resources-and-support/base/>`_ >=3.15.1
* `libevent <http://libevent.org/>`_ >=2.0.1  (Optionally bundled)
* (optional) `CMake <https://cmake.org/>`_ >=3.10, only needed when building bundled libevent

Download
--------

Releases are published to https://github.com/epics-base/pvxs/releases.
See :ref:`relpolicy` for details.

Getting Started
---------------

See :ref:`building`, and :ref:`includepvxs`.

With QSRV2 included, all local database records will be served via PVA.
For most user IOCs, no further action is necessary.

Contents
--------

.. toctree::
   :maxdepth: 1

   overview
   example
   building

.. toctree::
   :maxdepth: 2

   netconfig
   ioc
   cli

.. toctree::
   :caption: API References
   :maxdepth: 2

   value
   client
   server
   util
   details

.. toctree::
   :maxdepth: 1

   releasenotes

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

This document describes version |release| and earlier.
