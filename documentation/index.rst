PVXS client/server for PVA Protocol
===================================

The canonical version of this page is https://mdavidsaver.github.io/pvxs

Versioned source can be found at https://github.com/mdavidsaver/pvxs
where `issues <https://github.com/mdavidsaver/pvxs/issues>`_ should be reported.

This module provides a library (libpvxs.so or pvxs.dll) and a set of
CLI utilities acting as PVAccess protocol client and/or server.

Dependencies

* A C++11 compliant compiler like GCC >= 4.8 or Visual Studio 2015 (12.0)
* `EPICS Base <https://epics-controls.org/resources-and-support/base/>`_ >=3.15.1
* `libevent <http://libevent.org/>`_ >=2.0.1
* (optional) `CMake <https://cmake.org/>`_ >=3.1, only needed when building bundled libevent

Status

This module is considered feature complete, but is not yet making releases.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   building
   value
   client
   server
   util
   example
   details


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
