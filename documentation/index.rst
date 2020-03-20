PVXS client/server for PVA Protocol
===================================

This module is under active development and is only suitable for experimental usage.

The canonical version of this page is https://mdavidsaver.github.io/pvxs

Versioned source can be found at https://github.com/mdavidsaver/pvxs

This module provides a library (libpvxs.so or pvxs.dll) and a set of
CLI utilities acting as PVAccess protocol client and/or server.

Dependencies

* A C++11 compliant compiler (eg. GCC >= 4.8)
* `EPICS Base <https://epics-controls.org/resources-and-support/base/>`_ >=3.15.1
* `libevent <http://libevent.org/>`_ >=2.0.1
* (optional) `CMake <https://cmake.org/>`_ >=3.1, only when building bundled libevent

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
