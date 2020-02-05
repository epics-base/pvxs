Value Container
===============

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   nt
   typedef

The `pvxs::Value` container class provides the means to interact with PVA data values.

.. code-block:: c++

    #include <pvxs/data.h>
    namespace pvxs { ... }

A `pvxs::Value` may be obtained via the remote peer (client or server),
or created locally.  See `ntapi` or `typedefapi`.

.. doxygenclass:: pvxs::Value
    :members:

.. doxygenstruct:: pvxs::NoField

.. doxygenstruct:: pvxs::NoConvert
